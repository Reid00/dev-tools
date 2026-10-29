use regex::Regex;
use serde_json::{Value, json};
use std::collections::HashSet;

use super::{gen_singbox, types::ProxyNode};

pub fn apply_proxy_dns(
    config: &mut Value,
    proxy_dns: super::parse_clash::ProxyDns,
) -> Result<(), String> {
    let bootstrap = config["route"]["default_domain_resolver"].clone();
    if bootstrap.is_null() {
        return Err("模板缺少节点 DNS 所需的引导解析器".to_string());
    }
    let servers = config["dns"]["servers"]
        .as_array_mut()
        .ok_or("模板 dns.servers 必须为数组")?;
    let mut tag = "proxy-dns".to_string();
    let mut suffix = 2;
    while servers.iter().any(|server| server["tag"] == tag) {
        tag = format!("proxy-dns-{suffix}");
        suffix += 1;
    }
    let mut server = proxy_dns.server;
    server["tag"] = json!(tag);
    if server["server"]
        .as_str()
        .is_some_and(|host| host.parse::<std::net::IpAddr>().is_err())
    {
        server["domain_resolver"] = bootstrap.clone();
    }
    servers.push(server);
    for outbound in config["outbounds"]
        .as_array_mut()
        .ok_or("模板 outbounds 必须为数组")?
    {
        if outbound["type"] == "direct" && outbound.get("domain_resolver").is_none() {
            outbound["domain_resolver"] = bootstrap.clone();
        }
    }
    for client in config["http_clients"].as_array_mut().into_iter().flatten() {
        if client.get("domain_resolver").is_none() {
            client["domain_resolver"] = bootstrap.clone();
        }
    }
    config["route"]["default_domain_resolver"] = if proxy_dns.ipv4_only {
        json!({"server":tag,"strategy":"ipv4_only"})
    } else {
        json!(tag)
    };
    Ok(())
}

pub fn render_template(template_text: &str, nodes: &[ProxyNode]) -> Result<Value, String> {
    let mut template: Value = serde_json::from_str(template_text)
        .map_err(|error| format!("Failed to parse template JSON: {error}"))?;

    let outbounds = template["outbounds"]
        .as_array_mut()
        .ok_or_else(|| "Template outbounds must be an array".to_string())?;

    let mut reserved_tags = outbounds
        .iter()
        .filter_map(|outbound| outbound.get("tag").and_then(Value::as_str))
        .map(ToString::to_string)
        .collect::<HashSet<_>>();
    let mut generated_outbounds = nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            gen_singbox::node_to_singbox_outbound(node).map_err(|error| {
                format!(
                    "第 {} 个节点「{}」（{}）无法转换：{error}",
                    index + 1,
                    node.name,
                    node.protocol.protocol_str()
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let proxy_tags =
        normalize_generated_outbound_tags(&mut generated_outbounds, nodes, &mut reserved_tags);

    for outbound in outbounds.iter_mut() {
        if has_selector_outbounds(outbound) {
            let filtered_tags = apply_template_filter(&proxy_tags, outbound.get("filter"))?;
            let selector_outbounds = outbound["outbounds"]
                .as_array_mut()
                .expect("selector outbounds was checked as array");
            let mut expanded = Vec::new();

            for item in selector_outbounds.iter() {
                let member = item
                    .as_str()
                    .ok_or_else(|| "Selector outbound entries must be strings".to_string())?;
                if member == "{all}" {
                    expanded.extend(filtered_tags.iter().cloned());
                } else {
                    expanded.push(member.to_string());
                }
            }

            let mut deduped = Vec::new();
            for member in expanded {
                if !deduped.contains(&member) {
                    deduped.push(member);
                }
            }

            outbound["outbounds"] = json!(deduped);
        }

        if let Some(object) = outbound.as_object_mut() {
            object.remove("filter");
        }
    }

    outbounds.extend(generated_outbounds);
    Ok(template)
}

fn has_selector_outbounds(outbound: &Value) -> bool {
    outbound.get("outbounds").is_some_and(Value::is_array)
}

fn normalize_generated_outbound_tags(
    generated_outbounds: &mut [Value],
    nodes: &[ProxyNode],
    reserved_tags: &mut HashSet<String>,
) -> Vec<String> {
    let mut tags = Vec::with_capacity(generated_outbounds.len());

    for (index, (outbound, node)) in generated_outbounds.iter_mut().zip(nodes.iter()).enumerate() {
        let base = normalized_proxy_tag(node, index);
        let mut candidate = base.clone();
        let mut suffix = 2usize;
        while reserved_tags.contains(&candidate) {
            candidate = format!("{base}-{suffix}");
            suffix += 1;
        }
        outbound["tag"] = json!(candidate.clone());
        reserved_tags.insert(candidate.clone());
        tags.push(candidate);
    }

    tags
}

fn normalized_proxy_tag(node: &ProxyNode, index: usize) -> String {
    let trimmed = node.name.trim();
    if !trimmed.is_empty() {
        return trimmed.to_string();
    }

    let server = if node.server.trim().is_empty() {
        format!("node-{}", index + 1)
    } else {
        node.server.trim().to_string()
    };

    format!("{}-{}-{}", node.protocol.protocol_str(), server, node.port)
}

fn apply_template_filter(
    proxy_tags: &[String],
    filter: Option<&Value>,
) -> Result<Vec<String>, String> {
    let Some(filter) = filter else {
        return Ok(proxy_tags.to_vec());
    };

    let Some(rules) = filter.as_array() else {
        return Ok(proxy_tags.to_vec());
    };

    let mut filtered = proxy_tags.to_vec();

    for rule in rules {
        let action = rule
            .get("action")
            .and_then(Value::as_str)
            .ok_or_else(|| "Template filter action is required".to_string())?;
        let keywords = rule
            .get("keywords")
            .and_then(Value::as_array)
            .ok_or_else(|| "Template filter keywords are required".to_string())?;
        let pattern = keywords
            .iter()
            .map(|keyword| {
                keyword
                    .as_str()
                    .ok_or_else(|| "Template filter keywords are required".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?
            .join("|");
        let regex = Regex::new(&pattern)
            .map_err(|error| format!("Invalid template filter regex: {error}"))?;

        match action {
            "include" => filtered.retain(|tag| regex.is_match(tag)),
            "exclude" => filtered.retain(|tag| !regex.is_match(tag)),
            _ => return Err(format!("未知模板过滤动作：{action}")),
        }
    }

    if filtered.is_empty() {
        Ok(proxy_tags.to_vec())
    } else {
        Ok(filtered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::sub_convert::types::{ProxyNode, ProxyProtocol};

    fn node(name: &str) -> ProxyNode {
        let mut node = ProxyNode::default_with(ProxyProtocol::Trojan, name, "example.com", 443);
        node.password = "secret".to_string();
        node.tls_enabled = true;
        node.tls_sni = "example.com".to_string();
        node
    }

    #[test]
    fn dedicated_dns_keeps_template_routes_and_direct_bootstrap_unchanged() {
        for descriptor in super::super::template::builtin_templates() {
            let text = super::super::template::builtin_template_content(descriptor.id).unwrap();
            let mut config: Value = serde_json::from_str(text).unwrap();
            let original = config.clone();
            apply_proxy_dns(&mut config, super::super::parse_clash::ProxyDns {
                server: json!({"type":"https","server":"resolver.example.com","path":"/private/dns"}),
                ipv4_only: true,
                alternative_count: 0,
            }).unwrap();
            let dns = config["dns"]["servers"].as_array().unwrap().last().unwrap();
            assert_eq!(dns["tag"], "proxy-dns");
            assert_eq!(dns["domain_resolver"], "local");
            assert!(dns.get("detour").is_none());
            assert!(dns.get("tls").is_none());
            assert_eq!(
                config["route"]["default_domain_resolver"],
                json!({"server":"proxy-dns","strategy":"ipv4_only"})
            );
            for outbound in config["outbounds"].as_array().unwrap() {
                if outbound["type"] == "direct" {
                    assert_eq!(outbound["domain_resolver"], "local");
                }
            }
            for section in ["rules", "final", "strategy", "reverse_mapping"] {
                assert_eq!(config["dns"][section], original["dns"][section]);
            }
            for section in ["rules", "rule_set", "final", "auto_detect_interface"] {
                assert_eq!(config["route"][section], original["route"][section]);
            }
            assert_eq!(config["inbounds"], original["inbounds"]);
            let rendered = render_template(&config.to_string(), &[node("test")]).unwrap();
            super::super::validate::validate_references(&rendered).unwrap();
        }
    }

    #[test]
    fn proxy_dns_tag_collisions_and_ip_resolvers_are_handled() {
        let mut config = json!({
            "dns":{"servers":[{"type":"udp","tag":"proxy-dns","server":"223.5.5.5"}]},
            "outbounds":[{"type":"direct","tag":"direct","domain_resolver":"proxy-dns"}],
            "route":{"default_domain_resolver":"proxy-dns"}
        });
        apply_proxy_dns(
            &mut config,
            super::super::parse_clash::ProxyDns {
                server: json!({"type":"udp","server":"1.1.1.1"}),
                ipv4_only: false,
                alternative_count: 0,
            },
        )
        .unwrap();
        assert_eq!(config["route"]["default_domain_resolver"], "proxy-dns-2");
        assert!(config["dns"]["servers"][1].get("domain_resolver").is_none());
        assert_eq!(config["outbounds"][0]["domain_resolver"], "proxy-dns");
    }

    #[test]
    fn render_template_injects_all_proxy_tags_into_proxy_selector() {
        let template = r#"{
          "outbounds": [
            {"tag": "Proxy", "type": "selector", "outbounds": ["auto", "direct", "{all}"]},
            {"tag": "auto", "type": "urltest", "outbounds": ["{all}"]},
            {"tag": "direct", "type": "direct"}
          ]
        }"#;
        let rendered = render_template(template, &[node("🇭🇰 HK 01"), node("🇸🇬 SG 01")]).unwrap();
        let proxy = rendered["outbounds"].as_array().unwrap()[0]["outbounds"]
            .as_array()
            .unwrap();

        assert_eq!(proxy[0], "auto");
        assert_eq!(proxy[1], "direct");
        assert!(proxy.iter().any(|item| item == "🇭🇰 HK 01"));
        assert!(proxy.iter().any(|item| item == "🇸🇬 SG 01"));
    }

    #[test]
    fn render_template_applies_include_filter_groups() {
        let template = r#"{
          "outbounds": [
            {"tag": "HongKong", "type": "selector", "outbounds": ["{all}"], "filter": [{"action": "include", "keywords": ["🇭🇰|HK|HongKong"]}]},
            {"tag": "Others", "type": "selector", "outbounds": ["{all}"], "filter": [{"action": "exclude", "keywords": ["🇭🇰|HK|HongKong"]}]}
          ]
        }"#;
        let rendered = render_template(template, &[node("🇭🇰 HK 01"), node("🇸🇬 SG 01")]).unwrap();
        let outbounds = rendered["outbounds"].as_array().unwrap();

        assert_eq!(
            outbounds[0]["outbounds"].as_array().unwrap(),
            &vec![serde_json::json!("🇭🇰 HK 01")]
        );
        assert_eq!(
            outbounds[1]["outbounds"].as_array().unwrap(),
            &vec![serde_json::json!("🇸🇬 SG 01")]
        );
    }

    #[test]
    fn render_template_applies_filter_rules_sequentially_and_removes_filters() {
        let template = r#"{
          "outbounds": [
            {"tag": "Region", "type": "selector", "outbounds": ["{all}"], "filter": [
              {"action": "include", "keywords": ["HK|SG"]},
              {"action": "include", "keywords": ["VIP"]},
              {"action": "exclude", "keywords": ["SG"]}
            ]},
            {"tag": "direct", "type": "direct", "filter": [{"action": "include", "keywords": ["HK"]}]}
          ]
        }"#;
        let rendered = render_template(
            template,
            &[
                node("🇭🇰 HK VIP 01"),
                node("🇭🇰 HK 02"),
                node("🇸🇬 SG VIP 01"),
                node("🇯🇵 JP VIP 01"),
            ],
        )
        .unwrap();
        let outbounds = rendered["outbounds"].as_array().unwrap();

        assert_eq!(
            outbounds[0]["outbounds"].as_array().unwrap(),
            &vec![serde_json::json!("🇭🇰 HK VIP 01")]
        );
        assert!(
            outbounds
                .iter()
                .all(|outbound| outbound.get("filter").is_none())
        );
    }

    #[test]
    fn render_template_does_not_validate_non_selector_entries() {
        let template = r#"{
          "outbounds": [
            {"tag": "Proxy", "type": "selector", "outbounds": ["{all}"]},
            {"tag": "direct", "type": "direct", "detour": 42, "filter": [{"keywords": ["["]}]},
            {"tag": "block", "type": "block", "filter": [{"keywords": ["HK"]}]}
          ]
        }"#;
        let rendered = render_template(template, &[node("HK 01")]).unwrap();
        let outbounds = rendered["outbounds"].as_array().unwrap();

        assert_eq!(outbounds[1]["detour"], 42);
        assert!(outbounds[1].get("filter").is_none());
        assert!(outbounds[2].get("filter").is_none());
    }

    #[test]
    fn render_template_expands_all_with_normalized_unique_generated_tags() {
        let template = r#"{
          "outbounds": [
            {"tag": "Proxy", "type": "selector", "outbounds": ["{all}"]},
            {"tag": "auto", "type": "urltest", "outbounds": ["{all}"]},
            {"tag": "direct", "type": "direct"}
          ]
        }"#;
        let rendered =
            render_template(template, &[node("auto"), node("auto"), node("   ")]).unwrap();
        let outbounds = rendered["outbounds"].as_array().unwrap();
        let generated_tags = outbounds[3..]
            .iter()
            .map(|outbound| outbound["tag"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();

        assert_eq!(generated_tags.len(), 3);
        assert!(generated_tags.iter().all(|tag| !tag.trim().is_empty()));
        assert!(
            generated_tags
                .iter()
                .all(|tag| tag != "Proxy" && tag != "auto")
        );
        assert_eq!(
            generated_tags
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            generated_tags.len()
        );
        assert_eq!(outbounds[0]["outbounds"], serde_json::json!(generated_tags));
        assert_eq!(outbounds[1]["outbounds"], outbounds[0]["outbounds"]);
    }

    #[test]
    fn render_template_uses_all_proxies_for_empty_filter_fallback() {
        let template = r#"{
          "outbounds": [
            {"tag": "EmptyRegion", "type": "selector", "outbounds": ["{all}"], "filter": [{"action": "include", "keywords": ["Missing"]}]},
            {"tag": "DIRECT-OUT", "type": "direct"}
          ]
        }"#;
        let rendered = render_template(template, &[node("HK 01")]).unwrap();
        let outbounds = rendered["outbounds"].as_array().unwrap();

        assert_eq!(
            outbounds[0]["outbounds"].as_array().unwrap(),
            &vec![serde_json::json!("HK 01")]
        );
    }

    #[test]
    fn render_template_keeps_empty_region_usable_without_direct_outbound() {
        let template = r#"{
          "outbounds": [
            {"tag": "EmptyRegion", "type": "selector", "outbounds": ["{all}"], "filter": [{"action": "include", "keywords": ["Missing"]}]}
          ]
        }"#;
        let config = render_template(template, &[node("HK 01")]).unwrap();
        assert_eq!(
            config["outbounds"][0]["outbounds"],
            serde_json::json!(["HK 01"])
        );
    }
}

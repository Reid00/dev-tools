use regex::Regex;
use serde_json::{Value, json};
use std::collections::HashSet;

use super::{gen_singbox, types::ProxyNode};

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
    let direct_tag = outbounds
        .iter()
        .find(|outbound| outbound.get("type").and_then(Value::as_str) == Some("direct"))
        .and_then(|outbound| outbound.get("tag").and_then(Value::as_str))
        .map(ToString::to_string);
    let mut generated_outbounds = nodes
        .iter()
        .map(gen_singbox::node_to_singbox_outbound)
        .collect::<Result<Vec<_>, _>>()?;
    let proxy_tags =
        normalize_generated_outbound_tags(&mut generated_outbounds, nodes, &mut reserved_tags);

    for outbound in outbounds.iter_mut() {
        if has_selector_outbounds(outbound) {
            let filtered_tags =
                apply_template_filter(&proxy_tags, outbound.get("filter"), direct_tag.as_deref())?;
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
    direct_tag: Option<&str>,
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
            _ => {}
        }
    }

    if filtered.is_empty() {
        Ok(vec![
            direct_tag
                .ok_or_else(|| {
                    "Template direct outbound is required for empty filter fallback".to_string()
                })?
                .to_string(),
        ])
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
    fn render_template_uses_custom_direct_tag_for_empty_filter_fallback() {
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
            &vec![serde_json::json!("DIRECT-OUT")]
        );
    }

    #[test]
    fn render_template_rejects_empty_filter_without_direct_outbound() {
        let template = r#"{
          "outbounds": [
            {"tag": "EmptyRegion", "type": "selector", "outbounds": ["{all}"], "filter": [{"action": "include", "keywords": ["Missing"]}]}
          ]
        }"#;
        let err = render_template(template, &[node("HK 01")]).unwrap_err();

        assert_eq!(
            err,
            "Template direct outbound is required for empty filter fallback"
        );
    }
}

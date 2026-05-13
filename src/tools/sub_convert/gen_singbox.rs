use super::types::{ProxyNode, ProxyProtocol, TransportType};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::net::IpAddr;

const ANYTLS_WS_UNSUPPORTED: &str =
    "AnyTLS websocket transport is not supported for sing-box output";
const SSR_UNSUPPORTED: &str = "ShadowsocksR is not supported for sing-box output";

pub fn node_to_singbox_outbound(node: &ProxyNode) -> Result<Value, String> {
    if matches!(node.protocol, ProxyProtocol::Anytls) && matches!(node.transport, TransportType::Ws)
    {
        return Err(ANYTLS_WS_UNSUPPORTED.to_string());
    }

    if matches!(node.protocol, ProxyProtocol::ShadowsocksR) {
        return Err(SSR_UNSUPPORTED.to_string());
    }

    let outbound = match node.protocol {
        ProxyProtocol::Vmess => vmess_outbound(node),
        ProxyProtocol::Vless => vless_outbound(node),
        ProxyProtocol::Trojan => trojan_outbound(node),
        ProxyProtocol::Shadowsocks => ss_outbound(node),
        ProxyProtocol::ShadowsocksR => unreachable!("SSR is rejected above"),
        ProxyProtocol::Hysteria2 => hysteria2_outbound(node),
        ProxyProtocol::Anytls => anytls_outbound(node),
    };

    Ok(outbound)
}

pub fn generate_singbox_config(
    nodes: &[ProxyNode],
    include_direct: bool,
    include_dns: bool,
    hiddify_safe: bool,
) -> Result<Value, String> {
    let mut proxy_outbounds = nodes
        .iter()
        .map(node_to_singbox_outbound)
        .collect::<Result<Vec<_>, _>>()?;

    if hiddify_safe {
        apply_hiddify_safe_domain_resolver(&mut proxy_outbounds);
    }

    let proxy_tags = assign_proxy_tags(&mut proxy_outbounds, nodes);

    let default_proxy = proxy_tags
        .first()
        .cloned()
        .ok_or_else(|| "No valid proxy nodes found".to_string())?;

    let mut selector_outbounds = proxy_tags.clone();
    if include_direct {
        selector_outbounds.push("direct".to_string());
    }

    let mut all_outbounds = vec![json!({
        "type": "selector",
        "tag": "proxy",
        "outbounds": selector_outbounds,
        "default": default_proxy,
    })];
    all_outbounds.extend(proxy_outbounds);

    if include_direct {
        all_outbounds.push(json!({
            "type": "direct",
            "tag": "direct",
        }));
    }

    let mut config = json!({
        "log": {
            "level": "info",
            "timestamp": true,
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 10808,
                "sniff": true,
                "sniff_override_destination": true,
            }
        ],
        "outbounds": all_outbounds,
    });

    if include_dns {
        config["dns"] = json!({
            "servers": [
                {"tag": "google", "type": "tls", "server": "8.8.8.8"},
                {"tag": "local", "type": "udp", "server": "223.5.5.5"}
            ],
            "rules": [
                {"query_type": ["A", "AAAA"], "server": "google"}
            ],
            "strategy": "ipv4_only",
        });
    }

    let mut route_rules = vec![];
    if include_dns {
        route_rules.push(json!({
            "protocol": "dns",
            "action": "hijack-dns",
        }));
    }
    if include_direct {
        route_rules.push(json!({
            "ip_is_private": true,
            "action": "route",
            "outbound": "direct",
        }));
    }

    let mut route = json!({
        "rules": route_rules,
        "auto_detect_interface": true,
        "final": "proxy",
    });

    if include_dns {
        route["default_domain_resolver"] = json!("local");
    }

    config["route"] = route;

    Ok(config)
}

fn apply_hiddify_safe_domain_resolver(proxy_outbounds: &mut [Value]) {
    for outbound in proxy_outbounds.iter_mut() {
        if let Some(server) = outbound["server"].as_str() {
            if server.parse::<IpAddr>().is_err() {
                outbound["domain_resolver"] = json!("dns-local");
            }
        }
    }
}

fn assign_proxy_tags(proxy_outbounds: &mut [Value], nodes: &[ProxyNode]) -> Vec<String> {
    let mut used = HashSet::from([
        "auto".to_string(),
        "proxy".to_string(),
        "direct".to_string(),
    ]);
    let mut tags = Vec::with_capacity(proxy_outbounds.len());

    for (index, (outbound, node)) in proxy_outbounds.iter_mut().zip(nodes.iter()).enumerate() {
        let base = normalized_proxy_tag(node, index);
        let mut candidate = base.clone();
        let mut suffix = 2usize;
        while used.contains(&candidate) {
            candidate = format!("{base}-{suffix}");
            suffix += 1;
        }
        outbound["tag"] = json!(candidate.clone());
        used.insert(candidate.clone());
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

fn vmess_security(node: &ProxyNode) -> String {
    let method = node.method.trim();
    if method.is_empty() {
        "auto".to_string()
    } else {
        method.to_string()
    }
}

fn vmess_outbound(node: &ProxyNode) -> Value {
    let mut outbound = json!({
        "type": "vmess",
        "tag": node.name,
        "server": node.server,
        "server_port": node.port,
        "uuid": node.uuid,
        "alter_id": node.alter_id,
        "security": vmess_security(node),
    });

    if let Some(transport) = transport_json(node) {
        outbound["transport"] = transport;
    }

    if let Some(tls) = tls_json(node, false) {
        outbound["tls"] = tls;
    }

    outbound
}

fn vless_outbound(node: &ProxyNode) -> Value {
    let mut outbound = json!({
        "type": "vless",
        "tag": node.name,
        "server": node.server,
        "server_port": node.port,
        "uuid": node.uuid,
    });

    if !node.flow.is_empty() {
        outbound["flow"] = json!(node.flow);
    }

    if let Some(transport) = transport_json(node) {
        outbound["transport"] = transport;
    }

    if let Some(tls) = tls_json(node, false) {
        outbound["tls"] = tls;
    }

    outbound
}

fn trojan_outbound(node: &ProxyNode) -> Value {
    let mut outbound = json!({
        "type": "trojan",
        "tag": node.name,
        "server": node.server,
        "server_port": node.port,
        "password": node.password,
    });

    if let Some(transport) = transport_json(node) {
        outbound["transport"] = transport;
    }

    if let Some(tls) = tls_json(node, true) {
        outbound["tls"] = tls;
    }

    outbound
}

fn ss_outbound(node: &ProxyNode) -> Value {
    let mut outbound = json!({
        "type": "shadowsocks",
        "tag": node.name,
        "server": node.server,
        "server_port": node.port,
        "method": node.method,
        "password": node.password,
    });

    if !node.ss_plugin.is_empty() {
        outbound["plugin"] = json!(node.ss_plugin);
    }
    if !node.ss_plugin_opts.is_empty() {
        outbound["plugin_opts"] = json!(node.ss_plugin_opts);
    }

    outbound
}

fn hysteria2_outbound(node: &ProxyNode) -> Value {
    let mut outbound = json!({
        "type": "hysteria2",
        "tag": node.name,
        "server": node.server,
        "server_port": node.port,
        "password": node.password,
        "tls": tls_json(node, true).unwrap_or_else(|| json!({"enabled": true})),
    });

    if !node.hy2_obfs_type.is_empty() || !node.hy2_obfs_password.is_empty() {
        let mut obfs = json!({});
        if !node.hy2_obfs_type.is_empty() {
            obfs["type"] = json!(node.hy2_obfs_type);
        }
        if !node.hy2_obfs_password.is_empty() {
            obfs["password"] = json!(node.hy2_obfs_password);
        }
        outbound["obfs"] = obfs;
    }

    if let Some(up_mbps) = node.hy2_up_mbps {
        outbound["up_mbps"] = json!(up_mbps);
    }
    if let Some(down_mbps) = node.hy2_down_mbps {
        outbound["down_mbps"] = json!(down_mbps);
    }

    outbound
}

fn anytls_outbound(node: &ProxyNode) -> Value {
    let mut outbound = json!({
        "type": "anytls",
        "tag": node.name,
        "server": node.server,
        "server_port": node.port,
        "password": node.password,
        "tls": tls_json(node, true).unwrap_or_else(|| json!({"enabled": true})),
    });

    if let Some(transport) = transport_json(node) {
        outbound["transport"] = transport;
    }

    outbound
}

fn transport_json(node: &ProxyNode) -> Option<Value> {
    match node.transport {
        TransportType::Tcp => None,
        TransportType::Ws => Some(json!({
            "type": "ws",
            "path": default_path(&node.transport_path),
            "headers": if node.transport_host.is_empty() {
                json!({})
            } else {
                json!({"Host": node.transport_host})
            },
        })),
        TransportType::Grpc => Some(json!({
            "type": "grpc",
            "service_name": node.transport_service,
        })),
        TransportType::Http => Some(json!({
            "type": "http",
            "path": default_path(&node.transport_path),
            "host": if node.transport_host.is_empty() {
                json!([])
            } else {
                json!([node.transport_host.clone()])
            },
        })),
    }
}

fn tls_json(node: &ProxyNode, force_enabled: bool) -> Option<Value> {
    if !force_enabled && !node.tls_enabled {
        return None;
    }

    let mut tls = json!({
        "enabled": true,
        "server_name": node.tls_sni,
        "insecure": node.tls_insecure,
    });

    if !node.tls_fingerprint.is_empty() {
        tls["utls"] = json!({
            "enabled": true,
            "fingerprint": node.tls_fingerprint,
        });
    }

    if !node.tls_alpn.is_empty() {
        tls["alpn"] = json!(node.tls_alpn);
    }

    if node.reality_enabled {
        let mut reality = json!({
            "enabled": true,
        });
        if !node.reality_public_key.is_empty() {
            reality["public_key"] = json!(node.reality_public_key);
        }
        if !node.reality_short_id.is_empty() {
            reality["short_id"] = json!(node.reality_short_id);
        }
        tls["reality"] = reality;
    }

    Some(tls)
}

fn default_path(path: &str) -> &str {
    if path.is_empty() { "/" } else { path }
}

#[cfg(test)]
mod tests {
    use super::{generate_singbox_config, node_to_singbox_outbound};
    use crate::tools::sub_convert::types::{ProxyNode, ProxyProtocol, TransportType};

    fn node(protocol: ProxyProtocol, name: &str, server: &str, port: u16) -> ProxyNode {
        ProxyNode::default_with(protocol, name, server, port)
    }

    #[test]
    fn test_vmess_outbound_uses_alter_id_and_method_or_default_security() {
        let mut tls_node = node(ProxyProtocol::Vmess, "vmess-tls", "vmess.example.com", 8443);
        tls_node.uuid = "11111111-1111-1111-1111-111111111111".to_string();
        tls_node.alter_id = 7;
        tls_node.transport = TransportType::Ws;
        tls_node.transport_path = "/ws".to_string();
        tls_node.transport_host = "cdn.example.com".to_string();
        tls_node.tls_enabled = true;
        tls_node.tls_sni = "tls.example.com".to_string();

        let tls_outbound = node_to_singbox_outbound(&tls_node).unwrap();
        assert_eq!(tls_outbound["type"], "vmess");
        assert_eq!(tls_outbound["alter_id"], 7);
        assert_eq!(tls_outbound["security"], "auto");
        assert_eq!(tls_outbound["transport"]["type"], "ws");
        assert_eq!(tls_outbound["transport"]["path"], "/ws");
        assert_eq!(
            tls_outbound["transport"]["headers"]["Host"],
            "cdn.example.com"
        );
        assert_eq!(tls_outbound["tls"]["server_name"], "tls.example.com");
        assert!(tls_outbound.get("network").is_none());

        let mut plain_node = node(ProxyProtocol::Vmess, "vmess-plain", "plain.example.com", 80);
        plain_node.uuid = "22222222-2222-2222-2222-222222222222".to_string();

        let plain_outbound = node_to_singbox_outbound(&plain_node).unwrap();
        assert_eq!(plain_outbound["security"], "auto");
        assert_eq!(plain_outbound["alter_id"], 0);
        assert!(plain_outbound.get("tls").is_none());
    }

    #[test]
    fn test_vmess_outbound_prefers_explicit_method_for_security() {
        let mut node = node(
            ProxyProtocol::Vmess,
            "vmess-method",
            "vmess.example.com",
            443,
        );
        node.uuid = "99999999-9999-9999-9999-999999999999".to_string();
        node.method = "aes-128-gcm".to_string();

        let outbound = node_to_singbox_outbound(&node).unwrap();

        assert_eq!(outbound["type"], "vmess");
        assert_eq!(outbound["security"], "aes-128-gcm");
        assert!(outbound.get("tls").is_none());
    }

    #[test]
    fn test_vless_outbound_preserves_reality_ws_fields_without_network() {
        let mut node = node(ProxyProtocol::Vless, "vless-node", "vless.example.com", 443);
        node.uuid = "33333333-3333-3333-3333-333333333333".to_string();
        node.flow = "xtls-rprx-vision".to_string();
        node.transport = TransportType::Ws;
        node.transport_path = "/vless".to_string();
        node.transport_host = "cdn.vless.example.com".to_string();
        node.tls_enabled = true;
        node.tls_sni = "tls.vless.example.com".to_string();
        node.tls_fingerprint = "chrome".to_string();
        node.tls_alpn = vec!["h2".to_string(), "http/1.1".to_string()];
        node.reality_enabled = true;
        node.reality_public_key = "pubkey".to_string();
        node.reality_short_id = "shortid".to_string();

        let outbound = node_to_singbox_outbound(&node).unwrap();
        assert_eq!(outbound["type"], "vless");
        assert_eq!(outbound["flow"], "xtls-rprx-vision");
        assert_eq!(outbound["transport"]["type"], "ws");
        assert_eq!(outbound["transport"]["path"], "/vless");
        assert_eq!(
            outbound["transport"]["headers"]["Host"],
            "cdn.vless.example.com"
        );
        assert_eq!(outbound["tls"]["server_name"], "tls.vless.example.com");
        assert_eq!(outbound["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(outbound["tls"]["alpn"][0], "h2");
        assert_eq!(outbound["tls"]["reality"]["enabled"], true);
        assert_eq!(outbound["tls"]["reality"]["public_key"], "pubkey");
        assert_eq!(outbound["tls"]["reality"]["short_id"], "shortid");
        assert!(outbound.get("network").is_none());
    }

    #[test]
    fn test_trojan_outbound_preserves_grpc_tls_fields_without_network() {
        let mut node = node(
            ProxyProtocol::Trojan,
            "trojan-node",
            "trojan.example.com",
            443,
        );
        node.password = "secret".to_string();
        node.transport = TransportType::Grpc;
        node.transport_service = "grpc-service".to_string();
        node.tls_enabled = true;
        node.tls_sni = "tls.trojan.example.com".to_string();
        node.tls_fingerprint = "firefox".to_string();
        node.tls_alpn = vec!["h2".to_string()];

        let outbound = node_to_singbox_outbound(&node).unwrap();
        assert_eq!(outbound["type"], "trojan");
        assert_eq!(outbound["password"], "secret");
        assert_eq!(outbound["transport"]["type"], "grpc");
        assert_eq!(outbound["transport"]["service_name"], "grpc-service");
        assert_eq!(outbound["tls"]["server_name"], "tls.trojan.example.com");
        assert_eq!(outbound["tls"]["utls"]["fingerprint"], "firefox");
        assert_eq!(outbound["tls"]["alpn"][0], "h2");
        assert!(outbound.get("network").is_none());
    }

    #[test]
    fn test_ss_and_ssr_outbounds_preserve_protocol_specific_fields() {
        let mut ss = node(
            ProxyProtocol::Shadowsocks,
            "ss-node",
            "ss.example.com",
            8388,
        );
        ss.method = "aes-256-gcm".to_string();
        ss.password = "ss-pass".to_string();
        ss.ss_plugin = "v2ray-plugin".to_string();
        ss.ss_plugin_opts = "mode=websocket;host=cdn.example.com".to_string();

        let ss_outbound = node_to_singbox_outbound(&ss).unwrap();
        assert_eq!(ss_outbound["type"], "shadowsocks");
        assert_eq!(ss_outbound["plugin"], "v2ray-plugin");
        assert_eq!(
            ss_outbound["plugin_opts"],
            "mode=websocket;host=cdn.example.com"
        );

        let mut ssr = node(
            ProxyProtocol::ShadowsocksR,
            "ssr-node",
            "ssr.example.com",
            9443,
        );
        ssr.method = "aes-256-cfb".to_string();
        ssr.password = "ssr-pass".to_string();
        ssr.ssr_protocol = "auth_sha1_v4".to_string();
        ssr.ssr_protocol_param = "proto-param".to_string();
        ssr.ssr_obfs = "tls1.2_ticket_auth".to_string();
        ssr.ssr_obfs_param = "obfs.example.com".to_string();

        let err = node_to_singbox_outbound(&ssr).unwrap_err();
        assert_eq!(err, "ShadowsocksR is not supported for sing-box output");
    }

    #[test]
    fn test_hysteria2_outbound_preserves_obfs_and_bandwidth_fields() {
        let mut node = node(
            ProxyProtocol::Hysteria2,
            "hy2-node",
            "hy2.example.com",
            8443,
        );
        node.password = "hy2-pass".to_string();
        node.tls_enabled = true;
        node.tls_sni = "peer.example.com".to_string();
        node.tls_insecure = true;
        node.tls_alpn = vec!["h3".to_string(), "h2".to_string()];
        node.hy2_obfs_type = "salamander".to_string();
        node.hy2_obfs_password = "obfs-pass".to_string();
        node.hy2_up_mbps = Some(120);
        node.hy2_down_mbps = Some(240);

        let outbound = node_to_singbox_outbound(&node).unwrap();
        assert_eq!(outbound["type"], "hysteria2");
        assert_eq!(outbound["password"], "hy2-pass");
        assert_eq!(outbound["tls"]["server_name"], "peer.example.com");
        assert_eq!(outbound["tls"]["insecure"], true);
        assert_eq!(outbound["tls"]["alpn"][0], "h3");
        assert_eq!(outbound["obfs"]["type"], "salamander");
        assert_eq!(outbound["obfs"]["password"], "obfs-pass");
        assert_eq!(outbound["up_mbps"], 120);
        assert_eq!(outbound["down_mbps"], 240);
    }

    #[test]
    fn test_generate_singbox_config_wraps_nodes_with_direct_dns_and_final_proxy() {
        let mut node = node(ProxyProtocol::Vmess, "wrap-node", "wrap.example.com", 443);
        node.uuid = "44444444-4444-4444-4444-444444444444".to_string();
        node.tls_enabled = true;
        node.tls_sni = "wrap.example.com".to_string();

        let config = generate_singbox_config(&[node], true, true, false).unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();
        let selector = outbounds
            .iter()
            .find(|item| item["tag"] == "proxy")
            .unwrap();
        let direct = outbounds
            .iter()
            .find(|item| item["tag"] == "direct")
            .unwrap();

        assert_eq!(config["inbounds"][0]["type"], "mixed");
        assert_eq!(selector["type"], "selector");
        assert_eq!(selector["outbounds"][0], "wrap-node");
        assert_eq!(selector["outbounds"][1], "direct");
        assert_eq!(selector["default"], "wrap-node");
        assert_eq!(direct["type"], "direct");
        assert_eq!(config["dns"]["strategy"], "ipv4_only");
        assert_eq!(config["route"]["rules"][0]["protocol"], "dns");
        assert_eq!(config["route"]["rules"][1]["outbound"], "direct");
        assert_eq!(config["route"]["final"], "proxy");
        assert_eq!(config["route"]["default_domain_resolver"], "local");
        assert!(outbounds.iter().all(|item| item["type"] != "urltest"));
    }

    #[test]
    fn test_generate_singbox_config_assigns_non_empty_unique_proxy_tags() {
        let mut first = node(ProxyProtocol::Vmess, "   ", "dup.example.com", 443);
        first.uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_string();

        let mut second = node(ProxyProtocol::Vless, "auto", "dup.example.com", 8443);
        second.uuid = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".to_string();

        let mut third = node(ProxyProtocol::Trojan, "auto", "dup.example.com", 9443);
        third.password = "secret".to_string();

        let config = generate_singbox_config(&[first, second, third], false, false, false).unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();
        let selector = outbounds
            .iter()
            .find(|item| item["tag"] == "proxy")
            .unwrap();

        let proxy_tags = outbounds
            .iter()
            .filter_map(|outbound| outbound["tag"].as_str())
            .filter(|tag| *tag != "proxy" && *tag != "direct")
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        assert_eq!(proxy_tags.len(), 3);
        assert!(proxy_tags.iter().all(|tag| !tag.trim().is_empty()));
        assert!(
            proxy_tags
                .iter()
                .all(|tag| tag != "proxy" && tag != "direct")
        );

        let unique = proxy_tags.iter().collect::<std::collections::HashSet<_>>();
        assert_eq!(unique.len(), proxy_tags.len());
        assert_eq!(selector["outbounds"], serde_json::json!(proxy_tags));
        assert_eq!(selector["default"], selector["outbounds"][0]);
    }

    #[test]
    fn test_generate_singbox_config_rejects_anytls_websocket_transport() {
        let mut node = node(
            ProxyProtocol::Anytls,
            "anytls-ws",
            "anytls.example.com",
            443,
        );
        node.password = "secret".to_string();
        node.transport = TransportType::Ws;
        node.transport_path = "/ws".to_string();
        node.transport_host = "cdn.anytls.example.com".to_string();
        node.tls_enabled = true;
        node.tls_sni = "tls.anytls.example.com".to_string();

        let err = generate_singbox_config(&[node], false, false, false).unwrap_err();
        assert_eq!(
            err,
            "AnyTLS websocket transport is not supported for sing-box output"
        );
    }
}

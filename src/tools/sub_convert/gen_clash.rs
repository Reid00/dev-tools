use super::types::{ProxyNode, ProxyProtocol, TransportType};
use serde_yaml::{Mapping, Number, Value};

pub fn node_to_clash_entry(node: &ProxyNode) -> Value {
    let mut node_map = Mapping::new();
    node_map.insert(sy("name"), sy(&node.name));

    let clash_type = match node.protocol {
        ProxyProtocol::Shadowsocks => "ss",
        ProxyProtocol::ShadowsocksR => "ssr",
        protocol => protocol.protocol_str(),
    };
    node_map.insert(sy("type"), sy(clash_type));
    node_map.insert(sy("server"), sy(&node.server));
    node_map.insert(sy("port"), Value::Number(Number::from(node.port)));

    match node.protocol {
        ProxyProtocol::Vmess => {
            node_map.insert(sy("uuid"), sy(&node.uuid));
            node_map.insert(sy("alterId"), Value::Number(Number::from(node.alter_id)));
            let cipher = if node.method.is_empty() {
                "auto"
            } else {
                node.method.as_str()
            };
            node_map.insert(sy("cipher"), sy(cipher));
        }
        ProxyProtocol::Vless => {
            node_map.insert(sy("uuid"), sy(&node.uuid));
            node_map.insert(sy("cipher"), sy("none"));
            if !node.flow.is_empty() {
                node_map.insert(sy("flow"), sy(&node.flow));
            }
        }
        ProxyProtocol::Trojan => {
            node_map.insert(sy("password"), sy(&node.password));
        }
        ProxyProtocol::Shadowsocks => {
            node_map.insert(sy("cipher"), sy(&node.method));
            node_map.insert(sy("password"), sy(&node.password));
            if !node.ss_plugin.is_empty() {
                node_map.insert(sy("plugin"), sy(&node.ss_plugin));
            }
            if !node.ss_plugin_opts.is_empty() {
                node_map.insert(sy("plugin-opts"), sy(&node.ss_plugin_opts));
            }
        }
        ProxyProtocol::ShadowsocksR => {
            node_map.insert(sy("cipher"), sy(&node.method));
            node_map.insert(sy("password"), sy(&node.password));
            if !node.ssr_protocol.is_empty() {
                node_map.insert(sy("protocol"), sy(&node.ssr_protocol));
            }
            if !node.ssr_protocol_param.is_empty() {
                node_map.insert(sy("protocol-param"), sy(&node.ssr_protocol_param));
            }
            if !node.ssr_obfs.is_empty() {
                node_map.insert(sy("obfs"), sy(&node.ssr_obfs));
            }
            if !node.ssr_obfs_param.is_empty() {
                node_map.insert(sy("obfs-param"), sy(&node.ssr_obfs_param));
            }
        }
        ProxyProtocol::Hysteria2 => {
            node_map.insert(sy("password"), sy(&node.password));
            if let Some(up) = node.hy2_up_mbps {
                node_map.insert(sy("up"), Value::Number(Number::from(up)));
            }
            if let Some(down) = node.hy2_down_mbps {
                node_map.insert(sy("down"), Value::Number(Number::from(down)));
            }
            if !node.hy2_obfs_type.is_empty() {
                node_map.insert(sy("obfs"), sy(&node.hy2_obfs_type));
            }
            if !node.hy2_obfs_password.is_empty() {
                node_map.insert(sy("obfs-password"), sy(&node.hy2_obfs_password));
            }
        }
        ProxyProtocol::Anytls => {
            node_map.insert(sy("password"), sy(&node.password));
        }
    }

    if node.transport != TransportType::Tcp {
        node_map.insert(sy("network"), sy(transport_type_str(&node.transport)));
    }

    if node.tls_enabled {
        node_map.insert(sy("tls"), Value::Bool(true));
        if !node.tls_sni.is_empty() {
            node_map.insert(sy("servername"), sy(&node.tls_sni));
        }
        if node.tls_insecure {
            node_map.insert(sy("skip-cert-verify"), Value::Bool(true));
        }
        if !node.tls_fingerprint.is_empty() {
            node_map.insert(sy("client-fingerprint"), sy(&node.tls_fingerprint));
        }
        if !node.tls_alpn.is_empty() {
            node_map.insert(
                sy("alpn"),
                Value::Sequence(node.tls_alpn.iter().map(|value| sy(value)).collect()),
            );
        }

        if node.reality_enabled && !node.reality_public_key.is_empty() {
            let mut reality_opts = Mapping::new();
            reality_opts.insert(sy("public-key"), sy(&node.reality_public_key));
            if !node.reality_short_id.is_empty() {
                reality_opts.insert(sy("short-id"), sy(&node.reality_short_id));
            }
            node_map.insert(sy("reality-opts"), Value::Mapping(reality_opts));
        }
    }

    match node.transport {
        TransportType::Ws => {
            let mut ws_opts = Mapping::new();
            ws_opts.insert(sy("path"), sy(default_path(&node.transport_path)));
            if !node.transport_host.is_empty() {
                let mut headers = Mapping::new();
                headers.insert(sy("Host"), sy(&node.transport_host));
                ws_opts.insert(sy("headers"), Value::Mapping(headers));
            }
            node_map.insert(sy("ws-opts"), Value::Mapping(ws_opts));
        }
        TransportType::Grpc => {
            if !node.transport_service.is_empty() {
                let mut grpc_opts = Mapping::new();
                grpc_opts.insert(sy("grpc-service-name"), sy(&node.transport_service));
                node_map.insert(sy("grpc-opts"), Value::Mapping(grpc_opts));
            }
        }
        TransportType::Http | TransportType::Tcp => {}
    }

    Value::Mapping(node_map)
}

pub fn generate_clash_yaml(
    nodes: &[ProxyNode],
    include_direct: bool,
    include_dns: bool,
) -> Result<String, String> {
    let clash_proxies = nodes.iter().map(node_to_clash_entry).collect::<Vec<_>>();
    let proxy_names = nodes.iter().map(|node| node.name.clone()).collect::<Vec<_>>();

    let mut proxy_group_outbounds = vec![Value::String("auto".to_string())];
    if include_direct {
        proxy_group_outbounds.push(Value::String("DIRECT".to_string()));
    }
    proxy_group_outbounds.extend(proxy_names.iter().cloned().map(Value::String));

    let mut groups = vec![];

    let mut select_group = Mapping::new();
    select_group.insert(sy("name"), sy("Proxy"));
    select_group.insert(sy("type"), sy("select"));
    select_group.insert(sy("proxies"), Value::Sequence(proxy_group_outbounds));
    groups.push(Value::Mapping(select_group));

    let mut auto_group = Mapping::new();
    auto_group.insert(sy("name"), sy("auto"));
    auto_group.insert(sy("type"), sy("url-test"));
    auto_group.insert(sy("url"), sy("https://www.gstatic.com/generate_204"));
    auto_group.insert(sy("interval"), Value::Number(Number::from(180)));
    auto_group.insert(sy("tolerance"), Value::Number(Number::from(50)));
    auto_group.insert(
        sy("proxies"),
        Value::Sequence(proxy_names.iter().cloned().map(Value::String).collect()),
    );
    groups.push(Value::Mapping(auto_group));

    let mut rules = vec![];
    if include_dns {
        rules.push(Value::String(
            "PROCESS-NAME,systemd-resolved,DIRECT".to_string(),
        ));
    }
    if include_direct {
        rules.push(Value::String("GEOIP,LAN,DIRECT,no-resolve".to_string()));
    }
    rules.push(Value::String("MATCH,Proxy".to_string()));

    let mut root = Mapping::new();
    root.insert(sy("mixed-port"), Value::Number(Number::from(7890)));
    root.insert(sy("allow-lan"), Value::Bool(true));
    root.insert(sy("mode"), sy("rule"));
    root.insert(sy("log-level"), sy("info"));
    root.insert(sy("proxies"), Value::Sequence(clash_proxies));
    root.insert(sy("proxy-groups"), Value::Sequence(groups));
    root.insert(sy("rules"), Value::Sequence(rules));

    if include_dns {
        let mut dns = Mapping::new();
        dns.insert(sy("enable"), Value::Bool(true));
        dns.insert(sy("ipv6"), Value::Bool(false));
        dns.insert(sy("enhanced-mode"), sy("fake-ip"));
        dns.insert(
            sy("nameserver"),
            Value::Sequence(vec![
                sy("https://8.8.8.8/dns-query"),
                sy("https://223.5.5.5/dns-query"),
            ]),
        );
        root.insert(sy("dns"), Value::Mapping(dns));
    }

    serde_yaml::to_string(&root).map_err(|e| format!("Failed to serialize clash yaml: {e}"))
}

fn sy(s: &str) -> Value {
    Value::String(s.to_string())
}

fn transport_type_str(transport: &TransportType) -> &'static str {
    match transport {
        TransportType::Tcp => "tcp",
        TransportType::Ws => "ws",
        TransportType::Grpc => "grpc",
        TransportType::Http => "http",
    }
}

fn default_path(path: &str) -> &str {
    if path.is_empty() {
        "/"
    } else {
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmess_clash_entry_cipher_uses_method_or_defaults_to_auto() {
        let empty_method_node = ProxyNode {
            uuid: "uuid".to_string(),
            alter_id: 0,
            method: String::new(),
            tls_enabled: true,
            tls_sni: "sni.com".to_string(),
            transport: TransportType::Ws,
            transport_path: "/ws".to_string(),
            transport_host: "ws-host.com".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Vmess, "VMess", "server.com", 443)
        };
        let empty_method_entry = node_to_clash_entry(&empty_method_node);
        let empty_method_map = empty_method_entry.as_mapping().unwrap();
        assert_eq!(empty_method_map.get(sy("cipher")), Some(&sy("auto")));
        assert_eq!(empty_method_map.get(sy("tls")), Some(&Value::Bool(true)));
        assert_eq!(empty_method_map.get(sy("network")), Some(&sy("ws")));
        assert!(empty_method_map.get(sy("ws-opts")).is_some());

        let custom_method_node = ProxyNode {
            method: "aes-128-gcm".to_string(),
            ..empty_method_node.clone()
        };
        let custom_method_entry = node_to_clash_entry(&custom_method_node);
        let custom_method_map = custom_method_entry.as_mapping().unwrap();
        assert_eq!(custom_method_map.get(sy("cipher")), Some(&sy("aes-128-gcm")));
    }

    #[test]
    fn test_vless_clash_reality() {
        let node = ProxyNode {
            uuid: "uuid".to_string(),
            tls_enabled: true,
            tls_sni: "sni.com".to_string(),
            reality_enabled: true,
            reality_public_key: "pubkey".to_string(),
            reality_short_id: "shortid".to_string(),
            tls_fingerprint: "chrome".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Vless, "VLESS-Reality", "server.com", 443)
        };
        let entry = node_to_clash_entry(&node);
        let map = entry.as_mapping().unwrap();
        assert!(map.get(sy("reality-opts")).is_some());
        let reality = map.get(sy("reality-opts")).unwrap().as_mapping().unwrap();
        assert_eq!(reality.get(sy("public-key")), Some(&sy("pubkey")));
        assert_eq!(reality.get(sy("short-id")), Some(&sy("shortid")));
        assert_eq!(map.get(sy("client-fingerprint")), Some(&sy("chrome")));
    }

    #[test]
    fn test_generate_clash_yaml_output() {
        let node = ProxyNode {
            password: "pass".to_string(),
            tls_sni: "sni.com".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Trojan, "Trojan", "server.com", 443)
        };
        let yaml = generate_clash_yaml(&[node], false, false).unwrap();
        assert!(yaml.contains("proxies:"));
        assert!(yaml.contains("proxy-groups:"));
        assert!(yaml.contains("type: trojan"));
        assert!(yaml.contains("password: pass"));
    }

    #[test]
    fn test_generate_clash_yaml_wrapper_matches_flags() {
        let node = ProxyNode {
            password: "pass".to_string(),
            tls_enabled: true,
            tls_sni: "sni.com".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Trojan, "Trojan", "server.com", 443)
        };

        let yaml = generate_clash_yaml(&[node], true, true).unwrap();
        let doc: Value = serde_yaml::from_str(&yaml).unwrap();

        let groups = doc["proxy-groups"].as_sequence().unwrap();
        let proxy_group = groups
            .iter()
            .find(|group| group["name"].as_str() == Some("Proxy"))
            .unwrap();
        let selectors = proxy_group["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        assert_eq!(selectors, vec!["auto", "DIRECT", "Trojan"]);

        let rules = doc["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        assert_eq!(
            rules,
            vec![
                "PROCESS-NAME,systemd-resolved,DIRECT",
                "GEOIP,LAN,DIRECT,no-resolve",
                "MATCH,Proxy"
            ]
        );
        assert_eq!(doc["dns"]["enable"].as_bool(), Some(true));
    }

    #[test]
    fn test_http_transport_sets_network_without_extra_opts() {
        let node = ProxyNode {
            password: "secret".to_string(),
            transport: TransportType::Http,
            transport_path: "/http".to_string(),
            transport_host: "cdn.example.com".to_string(),
            tls_enabled: true,
            tls_sni: "tls.example.com".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Trojan, "HTTP", "http.example.com", 443)
        };

        let entry = node_to_clash_entry(&node);
        let map = entry.as_mapping().unwrap();

        assert_eq!(map.get(sy("network")), Some(&sy("http")));
        assert!(map.get(sy("ws-opts")).is_none());
        assert!(map.get(sy("grpc-opts")).is_none());
    }

    #[test]
    fn test_shadowsocks_entry_preserves_plugin_fields() {
        let node = ProxyNode {
            method: "aes-128-gcm".to_string(),
            password: "secret".to_string(),
            ss_plugin: "v2ray-plugin".to_string(),
            ss_plugin_opts: "mode=websocket;host=cdn.example.com".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Shadowsocks, "SS", "ss.example.com", 8388)
        };

        let entry = node_to_clash_entry(&node);
        let map = entry.as_mapping().unwrap();

        assert_eq!(map.get(sy("type")), Some(&sy("ss")));
        assert_eq!(map.get(sy("plugin")), Some(&sy("v2ray-plugin")));
        assert_eq!(
            map.get(sy("plugin-opts")),
            Some(&sy("mode=websocket;host=cdn.example.com"))
        );
    }

    #[test]
    fn test_anytls_and_hysteria2_type_names_are_preserved() {
        let anytls = ProxyNode {
            password: "secret".to_string(),
            tls_enabled: true,
            ..ProxyNode::default_with(ProxyProtocol::Anytls, "AnyTLS", "any.example.com", 443)
        };
        let hysteria2 = ProxyNode {
            password: "secret".to_string(),
            tls_enabled: true,
            ..ProxyNode::default_with(ProxyProtocol::Hysteria2, "HY2", "hy.example.com", 443)
        };

        let anytls_entry = node_to_clash_entry(&anytls);
        let hysteria2_entry = node_to_clash_entry(&hysteria2);
        let anytls_map = anytls_entry.as_mapping().unwrap();
        let hysteria2_map = hysteria2_entry.as_mapping().unwrap();

        assert_eq!(anytls_map.get(sy("type")), Some(&sy("anytls")));
        assert_eq!(hysteria2_map.get(sy("type")), Some(&sy("hysteria2")));
    }
}

use super::types::{ProxyNode, ProxyProtocol, TransportType};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::json;

pub fn node_to_uri(node: &ProxyNode) -> String {
    match node.protocol {
        ProxyProtocol::Vmess => vmess_node_to_uri(node),
        ProxyProtocol::Vless => vless_node_to_uri(node),
        ProxyProtocol::Trojan => trojan_node_to_uri(node),
        ProxyProtocol::Shadowsocks => ss_node_to_uri(node),
        ProxyProtocol::ShadowsocksR => ssr_node_to_uri(node),
        ProxyProtocol::Hysteria2 => hysteria2_node_to_uri(node),
        ProxyProtocol::Anytls => anytls_node_to_uri(node),
    }
}

pub fn generate_subscription_content(nodes: &[ProxyNode]) -> String {
    let uris: Vec<String> = nodes.iter().map(node_to_uri).collect();
    STANDARD.encode(uris.join("\n"))
}

pub fn generate_v2ray_content(nodes: &[ProxyNode]) -> String {
    nodes.iter().map(node_to_uri).collect::<Vec<_>>().join("\n")
}

fn vmess_node_to_uri(node: &ProxyNode) -> String {
    let mut vmess_obj = json!({
        "v": "2",
        "ps": node.name,
        "add": node.server,
        "port": node.port.to_string(),
        "id": node.uuid,
        "aid": node.alter_id.to_string(),
        "net": transport_type_str(node.transport),
        "type": "none",
        "host": "",
        "path": "",
        "tls": "",
        "sni": ""
    });

    if !node.method.is_empty() {
        vmess_obj["scy"] = json!(node.method);
    }

    match node.transport {
        TransportType::Ws | TransportType::Http => {
            vmess_obj["path"] = json!(node.transport_path);
            if !node.transport_host.is_empty() {
                vmess_obj["host"] = json!(node.transport_host);
            }
        }
        TransportType::Grpc => {
            vmess_obj["path"] = json!(node.transport_service);
            if !node.transport_host.is_empty() {
                vmess_obj["host"] = json!(node.transport_host);
            }
        }
        TransportType::Tcp => {}
    }

    if node.tls_enabled {
        vmess_obj["tls"] = json!("tls");
        if !node.tls_sni.is_empty() {
            vmess_obj["sni"] = json!(node.tls_sni);
        }
    }

    format!(
        "vmess://{}",
        STANDARD.encode(serde_json::to_string(&vmess_obj).unwrap_or_default())
    )
}

fn vless_node_to_uri(node: &ProxyNode) -> String {
    let mut url = format!(
        "vless://{}@{}:{}?type={}",
        node.uuid,
        node.server,
        node.port,
        transport_type_str(node.transport)
    );

    if !node.flow.is_empty() {
        url.push_str(&format!("&flow={}", urlencoding::encode(&node.flow)));
    }

    if node.tls_enabled {
        if node.reality_enabled {
            url.push_str("&security=reality");
        } else {
            url.push_str("&security=tls");
        }
        if !node.tls_sni.is_empty() {
            url.push_str(&format!("&sni={}", urlencoding::encode(&node.tls_sni)));
        }
    }

    if !node.tls_fingerprint.is_empty() {
        url.push_str(&format!(
            "&fp={}",
            urlencoding::encode(&node.tls_fingerprint)
        ));
    }

    if !node.tls_alpn.is_empty() {
        url.push_str(&format!(
            "&alpn={}",
            urlencoding::encode(&node.tls_alpn.join(","))
        ));
    }

    if node.reality_enabled {
        if !node.reality_public_key.is_empty() {
            url.push_str(&format!(
                "&pbk={}",
                urlencoding::encode(&node.reality_public_key)
            ));
        }
        if !node.reality_short_id.is_empty() {
            url.push_str(&format!(
                "&sid={}",
                urlencoding::encode(&node.reality_short_id)
            ));
        }
    }

    match node.transport {
        TransportType::Ws | TransportType::Http => {
            if !node.transport_path.is_empty() {
                url.push_str(&format!(
                    "&path={}",
                    urlencoding::encode(&node.transport_path)
                ));
            }
            if !node.transport_host.is_empty() {
                url.push_str(&format!(
                    "&host={}",
                    urlencoding::encode(&node.transport_host)
                ));
            }
        }
        TransportType::Grpc => {
            if !node.transport_service.is_empty() {
                url.push_str(&format!(
                    "&serviceName={}",
                    urlencoding::encode(&node.transport_service)
                ));
            }
            if !node.transport_host.is_empty() {
                url.push_str(&format!(
                    "&host={}",
                    urlencoding::encode(&node.transport_host)
                ));
            }
        }
        TransportType::Tcp => {}
    }

    url.push_str(&format!("#{}", urlencoding::encode(&node.name)));
    url
}

fn trojan_node_to_uri(node: &ProxyNode) -> String {
    let mut url = format!(
        "trojan://{}@{}:{}?",
        urlencoding::encode(&node.password),
        node.server,
        node.port
    );

    if node.reality_enabled {
        url.push_str("security=reality");
    } else {
        url.push_str("security=tls");
    }

    if !node.tls_sni.is_empty() {
        url.push_str(&format!("&sni={}", urlencoding::encode(&node.tls_sni)));
    }
    if !node.tls_fingerprint.is_empty() {
        url.push_str(&format!(
            "&fp={}",
            urlencoding::encode(&node.tls_fingerprint)
        ));
    }
    if !node.tls_alpn.is_empty() {
        url.push_str(&format!(
            "&alpn={}",
            urlencoding::encode(&node.tls_alpn.join(","))
        ));
    }

    if node.transport != TransportType::Tcp {
        url.push_str(&format!("&type={}", transport_type_str(node.transport)));
        match node.transport {
            TransportType::Ws | TransportType::Http => {
                if !node.transport_path.is_empty() {
                    url.push_str(&format!(
                        "&path={}",
                        urlencoding::encode(&node.transport_path)
                    ));
                }
                if !node.transport_host.is_empty() {
                    url.push_str(&format!(
                        "&host={}",
                        urlencoding::encode(&node.transport_host)
                    ));
                }
            }
            TransportType::Grpc => {
                if !node.transport_service.is_empty() {
                    url.push_str(&format!(
                        "&serviceName={}",
                        urlencoding::encode(&node.transport_service)
                    ));
                }
                if !node.transport_host.is_empty() {
                    url.push_str(&format!(
                        "&host={}",
                        urlencoding::encode(&node.transport_host)
                    ));
                }
            }
            TransportType::Tcp => {}
        }
    }

    if node.reality_enabled {
        if !node.reality_public_key.is_empty() {
            url.push_str(&format!(
                "&pbk={}",
                urlencoding::encode(&node.reality_public_key)
            ));
        }
        if !node.reality_short_id.is_empty() {
            url.push_str(&format!(
                "&sid={}",
                urlencoding::encode(&node.reality_short_id)
            ));
        }
    }

    url.push_str(&format!("#{}", urlencoding::encode(&node.name)));
    url
}

fn ss_node_to_uri(node: &ProxyNode) -> String {
    let userinfo = format!("{}:{}", node.method, node.password);
    let encoded = STANDARD.encode(userinfo);
    let mut url = format!(
        "ss://{}@{}:{}#{}",
        encoded,
        node.server,
        node.port,
        urlencoding::encode(&node.name)
    );

    if !node.ss_plugin.is_empty() {
        let plugin_value = if node.ss_plugin_opts.is_empty() {
            node.ss_plugin.clone()
        } else {
            format!("{};{}", node.ss_plugin, node.ss_plugin_opts)
        };
        url = format!(
            "ss://{}@{}:{}?plugin={}#{}",
            encoded,
            node.server,
            node.port,
            urlencoding::encode(&plugin_value),
            urlencoding::encode(&node.name)
        );
    }

    url
}

fn ssr_node_to_uri(node: &ProxyNode) -> String {
    let password_encoded = STANDARD.encode(&node.password);
    let main = format!(
        "{}:{}:{}:{}:{}:{}",
        node.server, node.port, node.ssr_protocol, node.method, node.ssr_obfs, password_encoded
    );
    let params = format!(
        "/?obfsparam={}&protoparam={}&remarks={}",
        STANDARD.encode(&node.ssr_obfs_param),
        STANDARD.encode(&node.ssr_protocol_param),
        STANDARD.encode(&node.name)
    );
    format!("ssr://{}", STANDARD.encode(main + &params))
}

fn hysteria2_node_to_uri(node: &ProxyNode) -> String {
    let mut url = format!(
        "hysteria2://{}@{}:{}?",
        urlencoding::encode(&node.password),
        node.server,
        node.port
    );

    if !node.tls_sni.is_empty() {
        url.push_str(&format!("sni={}&", urlencoding::encode(&node.tls_sni)));
    }
    if node.tls_insecure {
        url.push_str("insecure=1&");
    }
    if !node.tls_alpn.is_empty() {
        url.push_str(&format!(
            "alpn={}&",
            urlencoding::encode(&node.tls_alpn.join(","))
        ));
    }
    if !node.hy2_obfs_type.is_empty() {
        url.push_str(&format!(
            "obfs={}&",
            urlencoding::encode(&node.hy2_obfs_type)
        ));
    }
    if !node.hy2_obfs_password.is_empty() {
        url.push_str(&format!(
            "obfs-password={}&",
            urlencoding::encode(&node.hy2_obfs_password)
        ));
    }
    if let Some(up) = node.hy2_up_mbps {
        url.push_str(&format!("up={up}&"));
    }
    if let Some(down) = node.hy2_down_mbps {
        url.push_str(&format!("down={down}&"));
    }

    while url.ends_with('&') || url.ends_with('?') {
        url.pop();
    }

    url.push_str(&format!("#{}", urlencoding::encode(&node.name)));
    url
}

fn anytls_node_to_uri(node: &ProxyNode) -> String {
    let mut url = format!(
        "anytls://{}@{}:{}?",
        urlencoding::encode(&node.password),
        node.server,
        node.port
    );

    if !node.tls_sni.is_empty() {
        url.push_str(&format!("sni={}&", urlencoding::encode(&node.tls_sni)));
    }
    if !node.tls_fingerprint.is_empty() {
        url.push_str(&format!(
            "fp={}&",
            urlencoding::encode(&node.tls_fingerprint)
        ));
    }
    if !node.tls_alpn.is_empty() {
        url.push_str(&format!(
            "alpn={}&",
            urlencoding::encode(&node.tls_alpn.join(","))
        ));
    }
    if node.tls_insecure {
        url.push_str("insecure=1&");
    }

    match node.transport {
        TransportType::Ws => {
            url.push_str("type=ws&");
            if !node.transport_path.is_empty() {
                url.push_str(&format!(
                    "path={}&",
                    urlencoding::encode(&node.transport_path)
                ));
            }
            if !node.transport_host.is_empty() {
                url.push_str(&format!(
                    "host={}&",
                    urlencoding::encode(&node.transport_host)
                ));
            }
        }
        TransportType::Tcp | TransportType::Grpc | TransportType::Http => {}
    }

    while url.ends_with('&') || url.ends_with('?') {
        url.pop();
    }

    url.push_str(&format!("#{}", urlencoding::encode(&node.name)));
    url
}

fn transport_type_str(transport: TransportType) -> &'static str {
    match transport {
        TransportType::Tcp => "tcp",
        TransportType::Ws => "ws",
        TransportType::Grpc => "grpc",
        TransportType::Http => "http",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use serde_json::Value;

    fn base64_decode(input: &str) -> Result<String, String> {
        let input: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        let input = input.replace('-', "+").replace('_', "/");
        let padding = (4 - input.len() % 4) % 4;
        let input = input + &"=".repeat(padding);

        STANDARD
            .decode(input)
            .map_err(|e| format!("Base64 decode error: {e}"))
            .and_then(|bytes| String::from_utf8(bytes).map_err(|e| format!("Invalid UTF-8: {e}")))
    }

    #[test]
    fn test_vmess_node_to_uri_ws_tls() {
        let mut node = ProxyNode::default_with(ProxyProtocol::Vmess, "TestNode", "server.com", 443);
        node.uuid = "test-uuid".to_string();
        node.transport = TransportType::Ws;
        node.transport_path = "/ws-path".to_string();
        node.transport_host = "ws-host.com".to_string();
        node.tls_enabled = true;
        node.tls_sni = "ws-host.com".to_string();

        let uri = node_to_uri(&node);
        assert!(uri.starts_with("vmess://"));

        let decoded = base64_decode(uri.strip_prefix("vmess://").unwrap()).unwrap();
        let vmess: Value = serde_json::from_str(&decoded).unwrap();
        assert_eq!(vmess["ps"], "TestNode");
        assert_eq!(vmess["add"], "server.com");
        assert_eq!(vmess["net"], "ws");
        assert_eq!(vmess["host"], "ws-host.com");
        assert_eq!(vmess["path"], "/ws-path");
        assert_eq!(vmess["tls"], "tls");
    }

    #[test]
    fn test_vmess_node_to_uri_preserves_scy_method() {
        let mut node =
            ProxyNode::default_with(ProxyProtocol::Vmess, "VMess Cipher", "server.com", 443);
        node.uuid = "vmess-cipher-uuid".to_string();
        node.method = "chacha20-poly1305".to_string();

        let uri = node_to_uri(&node);
        let decoded = base64_decode(uri.strip_prefix("vmess://").unwrap()).unwrap();
        let vmess: Value = serde_json::from_str(&decoded).unwrap();

        assert_eq!(vmess["scy"], "chacha20-poly1305");
    }

    #[test]
    fn test_vmess_node_to_uri_preserves_explicit_sni_when_different_from_host() {
        let mut node =
            ProxyNode::default_with(ProxyProtocol::Vmess, "VMess SNI", "server.com", 443);
        node.uuid = "vmess-sni-uuid".to_string();
        node.transport = TransportType::Ws;
        node.transport_path = "/ws".to_string();
        node.transport_host = "cdn.example.com".to_string();
        node.tls_enabled = true;
        node.tls_sni = "tls.example.com".to_string();

        let uri = node_to_uri(&node);
        let decoded = base64_decode(uri.strip_prefix("vmess://").unwrap()).unwrap();
        let vmess: Value = serde_json::from_str(&decoded).unwrap();

        assert_eq!(vmess["host"], "cdn.example.com");
        assert_eq!(vmess["sni"], "tls.example.com");
        assert_eq!(vmess["tls"], "tls");
    }

    #[test]
    fn test_vless_node_to_uri_reality() {
        let mut node =
            ProxyNode::default_with(ProxyProtocol::Vless, "RealityNode", "server.com", 443);
        node.uuid = "vless-uuid".to_string();
        node.transport = TransportType::Ws;
        node.transport_path = "/ws".to_string();
        node.transport_host = "ws-host.com".to_string();
        node.tls_enabled = true;
        node.tls_sni = "sni.com".to_string();
        node.reality_enabled = true;
        node.reality_public_key = "pubkey".to_string();
        node.reality_short_id = "shortid".to_string();
        node.tls_fingerprint = "chrome".to_string();

        let uri = node_to_uri(&node);
        assert!(uri.starts_with("vless://"));
        assert!(uri.contains("security=reality"));
        assert!(uri.contains("pbk=pubkey"));
        assert!(uri.contains("sid=shortid"));
        assert!(uri.contains("sni=sni.com"));
        assert!(uri.contains("fp=chrome"));
        assert!(uri.contains("type=ws"));
    }

    #[test]
    fn test_trojan_node_to_uri_encodes_password_and_transport_fields() {
        let mut node =
            ProxyNode::default_with(ProxyProtocol::Trojan, "Trojan Node", "server.com", 443);
        node.password = "pa@ss:#?".to_string();
        node.transport = TransportType::Ws;
        node.transport_path = "/ws".to_string();
        node.transport_host = "cdn.example.com".to_string();
        node.tls_sni = "tls.example.com".to_string();
        node.tls_fingerprint = "chrome".to_string();
        node.tls_alpn = vec!["h2".to_string()];

        let uri = node_to_uri(&node);
        assert!(uri.starts_with("trojan://pa%40ss%3A%23%3F@server.com:443?"));
        assert!(uri.contains("security=tls"));
        assert!(uri.contains("sni=tls.example.com"));
        assert!(uri.contains("fp=chrome"));
        assert!(uri.contains("alpn=h2"));
        assert!(uri.contains("type=ws"));
        assert!(uri.contains("path=%2Fws"));
        assert!(uri.contains("host=cdn.example.com"));
    }

    #[test]
    fn test_ss_node_to_uri_preserves_plugin_fields() {
        let mut node =
            ProxyNode::default_with(ProxyProtocol::Shadowsocks, "SS Node", "1.2.3.4", 8388);
        node.method = "aes-128-gcm".to_string();
        node.password = "mypass".to_string();
        node.ss_plugin = "v2ray-plugin".to_string();
        node.ss_plugin_opts = "mode=websocket;host=cdn.example.com".to_string();

        let uri = node_to_uri(&node);
        assert!(uri.starts_with("ss://"));
        assert!(uri.contains("plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dcdn.example.com"));

        let parts: Vec<&str> = uri.strip_prefix("ss://").unwrap().split('@').collect();
        let userinfo = base64_decode(parts[0]).unwrap();
        assert_eq!(userinfo, "aes-128-gcm:mypass");
    }

    #[test]
    fn test_ssr_node_to_uri_preserves_params() {
        let mut node = ProxyNode::default_with(
            ProxyProtocol::ShadowsocksR,
            "SSR Node",
            "ssr.example.com",
            9443,
        );
        node.method = "aes-256-cfb".to_string();
        node.password = "secret-pass".to_string();
        node.ssr_protocol = "auth_sha1_v4".to_string();
        node.ssr_protocol_param = "proto-param".to_string();
        node.ssr_obfs = "tls1.2_ticket_auth".to_string();
        node.ssr_obfs_param = "obfs-host.example.com".to_string();

        let uri = node_to_uri(&node);
        assert!(uri.starts_with("ssr://"));

        let decoded = base64_decode(uri.strip_prefix("ssr://").unwrap()).unwrap();
        assert!(
            decoded.contains("ssr.example.com:9443:auth_sha1_v4:aes-256-cfb:tls1.2_ticket_auth")
        );
        assert!(decoded.contains("obfsparam=b2Jmcy1ob3N0LmV4YW1wbGUuY29t"));
        assert!(decoded.contains("protoparam=cHJvdG8tcGFyYW0="));
        assert!(decoded.contains("remarks=U1NSIE5vZGU="));
    }

    #[test]
    fn test_hysteria2_node_to_uri_preserves_tls_obfs_bandwidth() {
        let mut node =
            ProxyNode::default_with(ProxyProtocol::Hysteria2, "Hy2 Node", "hy.example.com", 443);
        node.password = "pass".to_string();
        node.tls_enabled = true;
        node.tls_sni = "www.google.com".to_string();
        node.tls_insecure = true;
        node.tls_alpn = vec!["h3".to_string()];
        node.hy2_obfs_type = "salamander".to_string();
        node.hy2_obfs_password = "obfspass".to_string();
        node.hy2_up_mbps = Some(50);
        node.hy2_down_mbps = Some(120);

        let uri = node_to_uri(&node);
        assert!(uri.starts_with("hysteria2://pass@hy.example.com:443?"));
        assert!(uri.contains("sni=www.google.com"));
        assert!(uri.contains("insecure=1"));
        assert!(uri.contains("alpn=h3"));
        assert!(uri.contains("obfs=salamander"));
        assert!(uri.contains("obfs-password=obfspass"));
        assert!(uri.contains("up=50"));
        assert!(uri.contains("down=120"));
    }

    #[test]
    fn test_hysteria2_node_to_uri_percent_encodes_password() {
        let mut node = ProxyNode::default_with(
            ProxyProtocol::Hysteria2,
            "Hy2 Encoded",
            "hy.example.com",
            443,
        );
        node.password = "pa@ss:#?".to_string();

        let uri = node_to_uri(&node);

        assert!(uri.starts_with("hysteria2://pa%40ss%3A%23%3F@hy.example.com:443"));
    }

    #[test]
    fn test_anytls_node_to_uri_encodes_password_and_ws_fields() {
        let mut node =
            ProxyNode::default_with(ProxyProtocol::Anytls, "AnyTLS Node", "any.example.com", 443);
        node.password = "pa@ss:#?".to_string();
        node.transport = TransportType::Ws;
        node.transport_path = "/ws".to_string();
        node.transport_host = "cdn.example.com".to_string();
        node.tls_sni = "www.google.com".to_string();
        node.tls_fingerprint = "chrome".to_string();
        node.tls_alpn = vec!["h2".to_string(), "http/1.1".to_string()];
        node.tls_insecure = true;

        let uri = node_to_uri(&node);
        assert!(uri.starts_with("anytls://pa%40ss%3A%23%3F@any.example.com:443?"));
        assert!(uri.contains("sni=www.google.com"));
        assert!(uri.contains("fp=chrome"));
        assert!(uri.contains("alpn=h2%2Chttp%2F1.1"));
        assert!(uri.contains("insecure=1"));
        assert!(uri.contains("type=ws"));
        assert!(uri.contains("path=%2Fws"));
        assert!(uri.contains("host=cdn.example.com"));
    }

    #[test]
    fn test_generate_subscription_content_base64_wraps_uri_lines() {
        let mut node = ProxyNode::default_with(ProxyProtocol::Shadowsocks, "Test", "1.2.3.4", 443);
        node.method = "aes-128-gcm".to_string();
        node.password = "pass".to_string();

        let content = generate_subscription_content(&[node]);
        let decoded = base64_decode(&content).unwrap();
        assert!(decoded.starts_with("ss://"));
    }

    #[test]
    fn test_generate_v2ray_content_keeps_plain_uri_lines() {
        let mut node = ProxyNode::default_with(ProxyProtocol::Shadowsocks, "Test", "1.2.3.4", 443);
        node.method = "aes-128-gcm".to_string();
        node.password = "pass".to_string();

        let content = generate_v2ray_content(&[node]);
        assert!(content.starts_with("ss://"));
        assert!(!content.contains("\n\n"));
        assert!(STANDARD.decode(&content).is_err());
    }
}

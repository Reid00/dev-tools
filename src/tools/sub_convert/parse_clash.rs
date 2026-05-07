use super::types::{ProxyNode, ProxyProtocol, TransportType};
use serde_yaml::Mapping;

pub fn parse_clash_yaml(content: &str) -> Result<Vec<ProxyNode>, String> {
    let yaml: serde_yaml::Value = serde_yaml::from_str(content)
        .map_err(|error| format!("Failed to parse Clash YAML: {error}"))?;

    let proxies = yaml
        .get("proxies")
        .and_then(|value| value.as_sequence())
        .ok_or_else(|| "No proxies found in Clash YAML".to_string())?;

    let mut nodes = Vec::new();
    for value in proxies {
        if let Some(proxy) = value.as_mapping() {
            if let Some(node) = clash_proxy_to_node(proxy)? {
                nodes.push(node);
            }
        }
    }

    Ok(nodes)
}

fn clash_proxy_to_node(proxy: &Mapping) -> Result<Option<ProxyNode>, String> {
    let Some(proxy_type) = get_str(proxy, "type") else {
        return Ok(None);
    };
    let name = get_str(proxy, "name").unwrap_or("proxy");

    match proxy_type {
        "vmess" => {
            let Some(server) = get_str(proxy, "server") else {
                return Ok(None);
            };
            let Some(port) = get_u16(proxy, "port") else {
                return Ok(None);
            };
            Ok(parse_clash_vmess(proxy, name, server, port))
        }
        "vless" => {
            let Some(server) = get_str(proxy, "server") else {
                return Ok(None);
            };
            let Some(port) = get_u16(proxy, "port") else {
                return Ok(None);
            };
            Ok(parse_clash_vless(proxy, name, server, port))
        }
        "trojan" => {
            let Some(server) = get_str(proxy, "server") else {
                return Ok(None);
            };
            let Some(port) = get_u16(proxy, "port") else {
                return Ok(None);
            };
            Ok(parse_clash_trojan(proxy, name, server, port))
        }
        "ss" => parse_clash_ss(proxy, name).map(Some),
        "ssr" => parse_clash_ssr(proxy, name).map(Some),
        "hysteria2" => {
            let Some(server) = get_str(proxy, "server") else {
                return Ok(None);
            };
            let Some(port) = get_u16(proxy, "port") else {
                return Ok(None);
            };
            Ok(parse_clash_hysteria2(proxy, name, server, port))
        }
        "anytls" => {
            let Some(server) = get_str(proxy, "server") else {
                return Ok(None);
            };
            let Some(port) = get_u16(proxy, "port") else {
                return Ok(None);
            };
            Ok(parse_clash_anytls(proxy, name, server, port))
        }
        _ => Ok(None),
    }
}

fn get_str<'a>(proxy: &'a Mapping, key: &str) -> Option<&'a str> {
    proxy.get(key).and_then(|value| value.as_str())
}

fn get_u16(proxy: &Mapping, key: &str) -> Option<u16> {
    match proxy.get(key) {
        Some(value) => value
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .or_else(|| value.as_str().and_then(|value| value.parse::<u16>().ok())),
        None => None,
    }
}

fn get_u32(proxy: &Mapping, key: &str) -> Option<u32> {
    match proxy.get(key) {
        Some(value) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .or_else(|| value.as_str().and_then(|value| value.parse::<u32>().ok())),
        None => None,
    }
}

fn get_u64(proxy: &Mapping, key: &str) -> Option<u64> {
    match proxy.get(key) {
        Some(value) => value
            .as_u64()
            .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
            .or_else(|| value.as_str().and_then(|value| value.parse::<u64>().ok())),
        None => None,
    }
}

fn get_required_str<'a>(proxy: &'a Mapping, key: &str, error: &str) -> Result<&'a str, String> {
    get_str(proxy, key).ok_or_else(|| error.to_string())
}

fn get_required_u16(proxy: &Mapping, key: &str, error: &str) -> Result<u16, String> {
    get_u16(proxy, key).ok_or_else(|| error.to_string())
}

fn get_bool(proxy: &Mapping, key: &str) -> bool {
    proxy.get(key).and_then(|value| value.as_bool()).unwrap_or(false)
}

fn get_transport(proxy: &Mapping) -> TransportType {
    match get_str(proxy, "network").unwrap_or("tcp") {
        "ws" => TransportType::Ws,
        "grpc" => TransportType::Grpc,
        "http" => TransportType::Http,
        _ => TransportType::Tcp,
    }
}

fn get_explicit_sni(proxy: &Mapping) -> String {
    get_str(proxy, "servername")
        .or_else(|| get_str(proxy, "sni"))
        .unwrap_or("")
        .to_string()
}

fn get_alpn(proxy: &Mapping) -> Vec<String> {
    if let Some(sequence) = proxy.get("alpn").and_then(|value| value.as_sequence()) {
        return sequence
            .iter()
            .filter_map(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect();
    }

    if let Some(value) = get_str(proxy, "alpn") {
        return value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToString::to_string)
            .collect();
    }

    Vec::new()
}

fn get_ws_opts(proxy: &Mapping) -> (String, String) {
    let ws_opts = proxy.get("ws-opts").and_then(|value| value.as_mapping());
    let path = ws_opts
        .and_then(|mapping| mapping.get("path"))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    let host = ws_opts
        .and_then(|mapping| mapping.get("headers"))
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get("Host"))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    (path, host)
}

fn get_grpc_service(proxy: &Mapping) -> String {
    proxy
        .get("grpc-opts")
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get("grpc-service-name"))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string()
}

fn get_reality_opts(proxy: &Mapping) -> (bool, String, String) {
    let Some(reality_opts) = proxy.get("reality-opts").and_then(|value| value.as_mapping()) else {
        return (false, String::new(), String::new());
    };

    let public_key = reality_opts
        .get("public-key")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    let short_id = reality_opts
        .get("short-id")
        .map(stringify_yaml_scalar)
        .unwrap_or_default();

    (true, public_key, short_id)
}

fn stringify_yaml_scalar(value: &serde_yaml::Value) -> String {
    if let Some(value) = value.as_str() {
        return value.to_string();
    }
    if let Some(value) = value.as_u64() {
        return value.to_string();
    }
    if let Some(value) = value.as_i64() {
        return value.to_string();
    }
    if let Some(value) = value.as_bool() {
        return value.to_string();
    }
    String::new()
}

fn apply_transport_fields(node: &mut ProxyNode, proxy: &Mapping) {
    node.transport = get_transport(proxy);

    match node.transport {
        TransportType::Ws => {
            let (path, host) = get_ws_opts(proxy);
            node.transport_path = path;
            node.transport_host = host;
            node.transport_service.clear();
        }
        TransportType::Grpc => {
            node.transport_service = get_grpc_service(proxy);
            node.transport_path.clear();
            node.transport_host.clear();
        }
        TransportType::Tcp | TransportType::Http => {
            node.transport_path.clear();
            node.transport_host.clear();
            node.transport_service.clear();
        }
    }
}

fn parse_clash_vmess(proxy: &Mapping, name: &str, server: &str, port: u16) -> Option<ProxyNode> {
    let uuid = get_str(proxy, "uuid")?;
    let mut node = ProxyNode::default_with(ProxyProtocol::Vmess, name, server, port);
    node.uuid = uuid.to_string();
    node.alter_id = get_u32(proxy, "alterId").unwrap_or(0);
    node.method = get_str(proxy, "cipher").unwrap_or("auto").to_string();
    node.tls_enabled = get_bool(proxy, "tls");
    node.tls_insecure = get_bool(proxy, "skip-cert-verify");
    node.tls_fingerprint = get_str(proxy, "client-fingerprint")
        .unwrap_or("")
        .to_string();
    node.tls_alpn = get_alpn(proxy);

    apply_transport_fields(&mut node, proxy);

    if node.tls_enabled {
        let explicit_sni = get_explicit_sni(proxy);
        node.tls_sni = if !explicit_sni.is_empty() {
            explicit_sni
        } else if !node.transport_host.is_empty() {
            node.transport_host.clone()
        } else {
            server.to_string()
        };
    }

    Some(node)
}

fn parse_clash_vless(proxy: &Mapping, name: &str, server: &str, port: u16) -> Option<ProxyNode> {
    let uuid = get_str(proxy, "uuid")?;
    let mut node = ProxyNode::default_with(ProxyProtocol::Vless, name, server, port);
    node.uuid = uuid.to_string();
    node.flow = get_str(proxy, "flow").unwrap_or("").to_string();
    node.tls_enabled = get_bool(proxy, "tls");
    node.tls_insecure = get_bool(proxy, "skip-cert-verify");
    node.tls_fingerprint = get_str(proxy, "client-fingerprint")
        .unwrap_or("")
        .to_string();
    node.tls_alpn = get_alpn(proxy);

    apply_transport_fields(&mut node, proxy);

    if node.tls_enabled {
        let explicit_sni = get_explicit_sni(proxy);
        node.tls_sni = if !explicit_sni.is_empty() {
            explicit_sni
        } else if !node.transport_host.is_empty() {
            node.transport_host.clone()
        } else {
            server.to_string()
        };
    }

    let (reality_enabled, reality_public_key, reality_short_id) = get_reality_opts(proxy);
    node.reality_enabled = reality_enabled;
    node.reality_public_key = reality_public_key;
    node.reality_short_id = reality_short_id;

    Some(node)
}

fn parse_clash_trojan(proxy: &Mapping, name: &str, server: &str, port: u16) -> Option<ProxyNode> {
    let password = get_str(proxy, "password")?;
    let mut node = ProxyNode::default_with(ProxyProtocol::Trojan, name, server, port);
    node.password = password.to_string();
    node.tls_enabled = true;
    node.tls_insecure = get_bool(proxy, "skip-cert-verify");
    node.tls_fingerprint = get_str(proxy, "client-fingerprint")
        .unwrap_or("")
        .to_string();
    node.tls_alpn = get_alpn(proxy);

    apply_transport_fields(&mut node, proxy);

    let explicit_sni = get_str(proxy, "sni")
        .or_else(|| get_str(proxy, "servername"))
        .unwrap_or("")
        .to_string();
    node.tls_sni = if !explicit_sni.is_empty() {
        explicit_sni
    } else if !node.transport_host.is_empty() {
        node.transport_host.clone()
    } else {
        server.to_string()
    };

    let (reality_enabled, reality_public_key, reality_short_id) = get_reality_opts(proxy);
    node.reality_enabled = reality_enabled;
    node.reality_public_key = reality_public_key;
    node.reality_short_id = reality_short_id;

    Some(node)
}

fn parse_clash_ss(proxy: &Mapping, name: &str) -> Result<ProxyNode, String> {
    let server = get_required_str(proxy, "server", "Clash SS proxy server is required")?;
    let port = get_required_u16(proxy, "port", "Clash SS proxy port is required")?;
    let method = get_required_str(proxy, "cipher", "Clash SS proxy cipher is required")?;
    let password = get_required_str(proxy, "password", "Clash SS proxy password is required")?;
    let mut node = ProxyNode::default_with(ProxyProtocol::Shadowsocks, name, server, port);
    node.method = method.to_string();
    node.password = password.to_string();
    node.ss_plugin = get_str(proxy, "plugin").unwrap_or("").to_string();
    node.ss_plugin_opts = get_str(proxy, "plugin-opts").unwrap_or("").to_string();
    Ok(node)
}

fn parse_clash_hysteria2(proxy: &Mapping, name: &str, server: &str, port: u16) -> Option<ProxyNode> {
    let password = get_str(proxy, "password")?;
    let mut node = ProxyNode::default_with(ProxyProtocol::Hysteria2, name, server, port);
    node.password = password.to_string();
    node.tls_enabled = true;
    node.tls_insecure = get_bool(proxy, "skip-cert-verify");
    node.tls_alpn = get_alpn(proxy);
    node.tls_sni = get_str(proxy, "sni")
        .or_else(|| get_str(proxy, "servername"))
        .unwrap_or(server)
        .to_string();
    node.hy2_obfs_type = get_str(proxy, "obfs").unwrap_or("").to_string();
    node.hy2_obfs_password = get_str(proxy, "obfs-password").unwrap_or("").to_string();
    node.hy2_up_mbps = get_u64(proxy, "up");
    node.hy2_down_mbps = get_u64(proxy, "down");
    Some(node)
}

fn parse_clash_ssr(proxy: &Mapping, name: &str) -> Result<ProxyNode, String> {
    let server = get_required_str(proxy, "server", "Clash SSR proxy server is required")?;
    let port = get_required_u16(proxy, "port", "Clash SSR proxy port is required")?;
    let method = get_required_str(proxy, "cipher", "Clash SSR proxy cipher is required")?;
    let password = get_required_str(proxy, "password", "Clash SSR proxy password is required")?;
    let mut node = ProxyNode::default_with(ProxyProtocol::ShadowsocksR, name, server, port);
    node.method = method.to_string();
    node.password = password.to_string();
    node.ssr_protocol = get_str(proxy, "protocol").unwrap_or("origin").to_string();
    node.ssr_protocol_param = get_str(proxy, "protocol-param")
        .or_else(|| get_str(proxy, "protocol_param"))
        .unwrap_or("")
        .to_string();
    node.ssr_obfs = get_str(proxy, "obfs").unwrap_or("plain").to_string();
    node.ssr_obfs_param = get_str(proxy, "obfs-param")
        .or_else(|| get_str(proxy, "obfs_param"))
        .unwrap_or("")
        .to_string();
    Ok(node)
}

fn parse_clash_anytls(proxy: &Mapping, name: &str, server: &str, port: u16) -> Option<ProxyNode> {
    let password = get_str(proxy, "password")?;
    let mut node = ProxyNode::default_with(ProxyProtocol::Anytls, name, server, port);
    node.password = password.to_string();
    node.tls_enabled = true;
    node.tls_insecure = get_bool(proxy, "skip-cert-verify");
    node.tls_fingerprint = get_str(proxy, "client-fingerprint")
        .unwrap_or("")
        .to_string();
    node.tls_alpn = get_alpn(proxy);

    apply_transport_fields(&mut node, proxy);

    let explicit_sni = get_explicit_sni(proxy);
    node.tls_sni = if !explicit_sni.is_empty() {
        explicit_sni
    } else if !node.transport_host.is_empty() {
        node.transport_host.clone()
    } else {
        server.to_string()
    };

    Some(node)
}

#[cfg(test)]
mod tests {
    use super::parse_clash_yaml;
    use super::super::types::{ProxyProtocol, TransportType};

    #[test]
    fn test_parse_clash_vmess_ws_tls_preserves_transport_and_tls_fields() {
        let yaml = r#"
proxies:
  - name: Test-VMess
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    alterId: 7
    cipher: auto
    tls: true
    servername: sni.example.com
    client-fingerprint: chrome
    alpn:
      - h2
      - http/1.1
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: cdn.example.com
"#;

        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);

        let node = &nodes[0];
        assert_eq!(node.protocol, ProxyProtocol::Vmess);
        assert_eq!(node.name, "Test-VMess");
        assert_eq!(node.server, "vmess.example.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.uuid, "11111111-1111-1111-1111-111111111111");
        assert_eq!(node.alter_id, 7);
        assert_eq!(node.method, "auto");
        assert_eq!(node.transport, TransportType::Ws);
        assert_eq!(node.transport_path, "/ws");
        assert_eq!(node.transport_host, "cdn.example.com");
        assert!(node.tls_enabled);
        assert_eq!(node.tls_sni, "sni.example.com");
        assert_eq!(node.tls_fingerprint, "chrome");
        assert_eq!(node.tls_alpn, vec!["h2", "http/1.1"]);
    }

    #[test]
    fn test_parse_clash_vless_reality_preserves_reality_and_grpc_fields() {
        let yaml = r#"
proxies:
  - name: Test-VLESS-Reality
    type: vless
    server: vless.example.com
    port: 8443
    uuid: 22222222-2222-2222-2222-222222222222
    flow: xtls-rprx-vision
    tls: true
    servername: reality.example.com
    client-fingerprint: firefox
    alpn: h2,http/1.1
    network: grpc
    grpc-opts:
      grpc-service-name: grpc-service
    reality-opts:
      public-key: pubkey123
      short-id: 1a2b
"#;

        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);

        let node = &nodes[0];
        assert_eq!(node.protocol, ProxyProtocol::Vless);
        assert_eq!(node.flow, "xtls-rprx-vision");
        assert_eq!(node.transport, TransportType::Grpc);
        assert_eq!(node.transport_service, "grpc-service");
        assert_eq!(node.transport_path, "");
        assert!(node.tls_enabled);
        assert_eq!(node.tls_sni, "reality.example.com");
        assert_eq!(node.tls_fingerprint, "firefox");
        assert_eq!(node.tls_alpn, vec!["h2", "http/1.1"]);
        assert!(node.reality_enabled);
        assert_eq!(node.reality_public_key, "pubkey123");
        assert_eq!(node.reality_short_id, "1a2b");
    }

    #[test]
    fn test_parse_clash_trojan_ws_preserves_tls_and_transport_fields() {
        let yaml = r#"
proxies:
  - name: Test-Trojan
    type: trojan
    server: trojan.example.com
    port: 443
    password: pass123
    sni: tls.example.com
    skip-cert-verify: true
    client-fingerprint: chrome
    alpn:
      - h2
    network: ws
    ws-opts:
      path: /trojan
      headers:
        Host: cdn.example.com
"#;

        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);

        let node = &nodes[0];
        assert_eq!(node.protocol, ProxyProtocol::Trojan);
        assert_eq!(node.password, "pass123");
        assert_eq!(node.transport, TransportType::Ws);
        assert_eq!(node.transport_path, "/trojan");
        assert_eq!(node.transport_host, "cdn.example.com");
        assert!(node.tls_enabled);
        assert_eq!(node.tls_sni, "tls.example.com");
        assert!(node.tls_insecure);
        assert_eq!(node.tls_fingerprint, "chrome");
        assert_eq!(node.tls_alpn, vec!["h2"]);
    }

    #[test]
    fn test_parse_clash_ss_preserves_plugin_fields() {
        let yaml = r#"
proxies:
  - name: Test-SS
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: ss-pass
    plugin: v2ray-plugin
    plugin-opts: mode=websocket;host=cdn.example.com
"#;

        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);

        let node = &nodes[0];
        assert_eq!(node.protocol, ProxyProtocol::Shadowsocks);
        assert_eq!(node.method, "aes-256-gcm");
        assert_eq!(node.password, "ss-pass");
        assert_eq!(node.ss_plugin, "v2ray-plugin");
        assert_eq!(node.ss_plugin_opts, "mode=websocket;host=cdn.example.com");
    }

    #[test]
    fn test_parse_clash_hysteria2_preserves_obfs_bandwidth_and_tls_fields() {
        let yaml = r#"
proxies:
  - name: Test-HY2
    type: hysteria2
    server: hy2.example.com
    port: 8443
    password: hy2-pass
    servername: hy2-sni.example.com
    skip-cert-verify: true
    alpn:
      - h3
      - h2
    obfs: salamander
    obfs-password: obfs-pass
    up: 50
    down: 120
"#;

        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);

        let node = &nodes[0];
        assert_eq!(node.protocol, ProxyProtocol::Hysteria2);
        assert_eq!(node.password, "hy2-pass");
        assert!(node.tls_enabled);
        assert_eq!(node.tls_sni, "hy2-sni.example.com");
        assert!(node.tls_insecure);
        assert_eq!(node.tls_alpn, vec!["h3", "h2"]);
        assert_eq!(node.hy2_obfs_type, "salamander");
        assert_eq!(node.hy2_obfs_password, "obfs-pass");
        assert_eq!(node.hy2_up_mbps, Some(50));
        assert_eq!(node.hy2_down_mbps, Some(120));
    }

    #[test]
    fn test_parse_clash_ssr_preserves_ssr_fields() {
        let yaml = r#"
proxies:
  - name: Test-SSR
    type: ssr
    server: ssr.example.com
    port: 9443
    cipher: aes-256-cfb
    password: ssr-pass
    protocol: auth_sha1_v4
    protocol-param: proto-param
    obfs: tls1.2_ticket_auth
    obfs-param: obfs-host.example.com
"#;

        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);

        let node = &nodes[0];
        assert_eq!(node.protocol, ProxyProtocol::ShadowsocksR);
        assert_eq!(node.name, "Test-SSR");
        assert_eq!(node.server, "ssr.example.com");
        assert_eq!(node.port, 9443);
        assert_eq!(node.method, "aes-256-cfb");
        assert_eq!(node.password, "ssr-pass");
        assert_eq!(node.ssr_protocol, "auth_sha1_v4");
        assert_eq!(node.ssr_protocol_param, "proto-param");
        assert_eq!(node.ssr_obfs, "tls1.2_ticket_auth");
        assert_eq!(node.ssr_obfs_param, "obfs-host.example.com");
    }

    #[test]
    fn test_parse_clash_anytls_defaults_tls_and_sni_when_flag_omitted() {
        let yaml = r#"
proxies:
  - name: anytls-no-tls-flag
    type: anytls
    server: anytls.example.com
    port: "443"
    password: anytls-pass
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: cdn.anytls.example.com
"#;

        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);
        let node = &nodes[0];

        assert_eq!(node.protocol, ProxyProtocol::Anytls);
        assert!(node.tls_enabled);
        assert_eq!(node.tls_sni, "cdn.anytls.example.com");
        assert_eq!(node.transport, TransportType::Ws);
        assert_eq!(node.transport_path, "/ws");
        assert_eq!(node.transport_host, "cdn.anytls.example.com");
    }

    #[test]
    fn test_parse_clash_anytls_preserves_tls_and_ws_fields() {
        let yaml = r#"
proxies:
  - name: Test-AnyTLS
    type: anytls
    server: anytls.example.com
    port: 443
    password: anytls-pass
    tls: true
    servername: tls.example.com
    skip-cert-verify: true
    client-fingerprint: chrome
    alpn:
      - h2
      - http/1.1
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: cdn.example.com
"#;

        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);

        let node = &nodes[0];
        assert_eq!(node.protocol, ProxyProtocol::Anytls);
        assert_eq!(node.name, "Test-AnyTLS");
        assert_eq!(node.server, "anytls.example.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.password, "anytls-pass");
        assert_eq!(node.transport, TransportType::Ws);
        assert_eq!(node.transport_path, "/ws");
        assert_eq!(node.transport_host, "cdn.example.com");
        assert!(node.tls_enabled);
        assert_eq!(node.tls_sni, "tls.example.com");
        assert!(node.tls_insecure);
        assert_eq!(node.tls_fingerprint, "chrome");
        assert_eq!(node.tls_alpn, vec!["h2", "http/1.1"]);
    }

    #[test]
    fn test_parse_clash_yaml_skips_unsupported_and_incomplete_entries() {
        let yaml = r#"
proxies:
  - name: Unsupported
    type: socks5
    server: socks.example.com
    port: 1080
  - name: Incomplete-VMess
    type: vmess
    server: bad.example.com
    port: 443
  - name: Valid-SS
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-128-gcm
    password: good-pass
"#;

        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "Valid-SS");
        assert_eq!(nodes[0].protocol, ProxyProtocol::Shadowsocks);
    }

    #[test]
    fn test_parse_clash_yaml_returns_error_for_invalid_yaml() {
        let err = parse_clash_yaml("proxies: [").unwrap_err();

        assert!(err.contains("Failed to parse Clash YAML"));
    }
}

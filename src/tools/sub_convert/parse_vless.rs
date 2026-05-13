use super::types::{ProxyNode, ProxyProtocol, TransportType};
use reqwest::Url;

pub fn parse_vless(url: &str) -> Result<ProxyNode, String> {
    let raw = url
        .strip_prefix("vless://")
        .ok_or_else(|| "Invalid vless URL prefix".to_string())?;
    let parsed = Url::parse(&format!("vless://{raw}"))
        .map_err(|e| format!("Failed to parse vless URL: {e}"))?;

    let uuid = parsed.username().to_string();
    let server = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port().unwrap_or(443);
    let name = parsed
        .fragment()
        .map(|value| {
            urlencoding::decode(value)
                .map(|decoded| decoded.into_owned())
                .unwrap_or_else(|_| value.to_string())
        })
        .unwrap_or_else(|| "vless".to_string());

    let mut transport = TransportType::Tcp;
    let mut transport_host = String::new();
    let mut transport_path = String::new();
    let mut transport_service = String::new();
    let mut flow = String::new();
    let mut security = String::new();
    let mut explicit_sni = String::new();
    let mut fingerprint = String::new();
    let mut alpn = Vec::new();
    let mut reality_public_key = String::new();
    let mut reality_short_id = String::new();

    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "type" => {
                transport = match value.as_ref() {
                    "ws" => TransportType::Ws,
                    "grpc" => TransportType::Grpc,
                    "http" => TransportType::Http,
                    _ => TransportType::Tcp,
                };
            }
            "security" => security = value.into_owned(),
            "host" => transport_host = value.into_owned(),
            "path" => transport_path = value.into_owned(),
            "flow" => flow = value.into_owned(),
            "sni" | "servername" if explicit_sni.is_empty() => explicit_sni = value.into_owned(),
            "fp" | "fingerprint" if fingerprint.is_empty() => fingerprint = value.into_owned(),
            "alpn" => {
                alpn = value
                    .split(',')
                    .map(|item| item.trim())
                    .filter(|item| !item.is_empty())
                    .map(ToString::to_string)
                    .collect();
            }
            "serviceName" => transport_service = value.into_owned(),
            "pbk" => reality_public_key = value.into_owned(),
            "sid" => reality_short_id = value.into_owned(),
            _ => {}
        }
    }

    let tls_enabled = matches!(security.as_str(), "tls" | "reality");
    let reality_enabled = security == "reality";
    let tls_sni = if tls_enabled {
        if !explicit_sni.is_empty() {
            explicit_sni.clone()
        } else if !transport_host.is_empty() {
            transport_host.clone()
        } else {
            server.clone()
        }
    } else {
        String::new()
    };

    let mut node = ProxyNode::default_with(ProxyProtocol::Vless, &name, &server, port);
    node.uuid = uuid;
    node.flow = flow;
    node.transport = transport;
    node.transport_host = transport_host;
    node.tls_enabled = tls_enabled;
    node.tls_sni = tls_sni;
    node.tls_fingerprint = fingerprint;
    node.tls_alpn = alpn;
    node.reality_enabled = reality_enabled;
    node.reality_public_key = reality_public_key;
    node.reality_short_id = reality_short_id;

    match node.transport {
        TransportType::Grpc => {
            node.transport_service = transport_service;
            node.transport_path.clear();
        }
        _ => {
            node.transport_path = transport_path;
            node.transport_service.clear();
        }
    }

    Ok(node)
}

#[cfg(test)]
mod tests {
    use super::super::types::{ProxyProtocol, TransportType};
    use super::parse_vless;

    #[test]
    fn test_parse_vless_reality() {
        let url = "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=grpc&security=reality&host=cdn.example.com&serviceName=grpc-service&flow=xtls-rprx-vision&sni=www.google.com&fp=chrome&alpn=h2,http/1.1&pbk=abcdef123456&sid=11#Reality%20Node";

        let node = parse_vless(url).unwrap();

        assert_eq!(node.protocol, ProxyProtocol::Vless);
        assert_eq!(node.name, "Reality Node");
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.uuid, "11111111-1111-1111-1111-111111111111");
        assert_eq!(node.flow, "xtls-rprx-vision");
        assert_eq!(node.transport, TransportType::Grpc);
        assert_eq!(node.transport_service, "grpc-service");
        assert_eq!(node.transport_path, "");
        assert_eq!(node.transport_host, "cdn.example.com");
        assert!(node.tls_enabled);
        assert!(node.reality_enabled);
        assert_eq!(node.tls_sni, "www.google.com");
        assert_eq!(node.tls_fingerprint, "chrome");
        assert_eq!(node.tls_alpn, vec!["h2", "http/1.1"]);
        assert_eq!(node.reality_public_key, "abcdef123456");
        assert_eq!(node.reality_short_id, "11");
    }

    #[test]
    fn test_parse_vless_tls_ws() {
        let url = "vless://22222222-2222-2222-2222-222222222222@ws.example.com:8443?type=ws&security=tls&host=cdn.example.com&path=%2Fwebsocket&fingerprint=firefox&alpn=h2#Ws%20Node";

        let node = parse_vless(url).unwrap();

        assert_eq!(node.protocol, ProxyProtocol::Vless);
        assert_eq!(node.name, "Ws Node");
        assert_eq!(node.transport, TransportType::Ws);
        assert_eq!(node.transport_path, "/websocket");
        assert_eq!(node.transport_service, "");
        assert_eq!(node.transport_host, "cdn.example.com");
        assert!(node.tls_enabled);
        assert!(!node.reality_enabled);
        assert_eq!(node.tls_sni, "cdn.example.com");
        assert_eq!(node.tls_fingerprint, "firefox");
        assert_eq!(node.tls_alpn, vec!["h2"]);
    }

    #[test]
    fn test_parse_vless_direct_tls() {
        let url = "vless://33333333-3333-3333-3333-333333333333@direct.example.com:443?security=tls#Direct%20TLS";

        let node = parse_vless(url).unwrap();

        assert_eq!(node.protocol, ProxyProtocol::Vless);
        assert_eq!(node.name, "Direct TLS");
        assert_eq!(node.transport, TransportType::Tcp);
        assert_eq!(node.transport_path, "");
        assert_eq!(node.transport_service, "");
        assert_eq!(node.transport_host, "");
        assert!(node.tls_enabled);
        assert!(!node.reality_enabled);
        assert_eq!(node.tls_sni, "direct.example.com");
        assert!(node.tls_alpn.is_empty());
    }
}

use super::types::{ProxyNode, ProxyProtocol, TransportType};
use reqwest::Url;

pub fn parse_trojan(url: &str) -> Result<ProxyNode, String> {
    let raw = url
        .strip_prefix("trojan://")
        .ok_or_else(|| "Invalid trojan URL prefix".to_string())?;
    let parsed = Url::parse(&format!("trojan://{raw}"))
        .map_err(|e| format!("Failed to parse trojan URL: {e}"))?;

    let password = decode_component(parsed.username());
    let server = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port().unwrap_or(443);
    let name = parsed
        .fragment()
        .map(|value| {
            urlencoding::decode(value)
                .map(|decoded| decoded.into_owned())
                .unwrap_or_else(|_| value.to_string())
        })
        .unwrap_or_else(|| "trojan".to_string());

    let mut transport = TransportType::Tcp;
    let mut transport_host = String::new();
    let mut transport_path = String::new();
    let mut transport_service = String::new();
    let mut sni = String::new();
    let mut servername = String::new();
    let mut fp = String::new();
    let mut fingerprint = String::new();
    let mut alpn = Vec::new();
    let mut security = String::from("tls");
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
            "host" => transport_host = value.into_owned(),
            "path" => transport_path = value.into_owned(),
            "sni" => sni = value.into_owned(),
            "servername" => servername = value.into_owned(),
            "fp" => fp = value.into_owned(),
            "fingerprint" => fingerprint = value.into_owned(),
            "alpn" => {
                alpn = value
                    .split(',')
                    .map(|item| item.trim())
                    .filter(|item| !item.is_empty())
                    .map(ToString::to_string)
                    .collect();
            }
            "security" => security = value.into_owned(),
            "serviceName" => transport_service = value.into_owned(),
            "pbk" => reality_public_key = value.into_owned(),
            "sid" => reality_short_id = value.into_owned(),
            _ => {}
        }
    }

    let explicit_sni = if !sni.is_empty() { sni } else { servername };
    let tls_sni = if !explicit_sni.is_empty() {
        explicit_sni
    } else if !transport_host.is_empty() {
        transport_host.clone()
    } else {
        server.clone()
    };

    let mut node = ProxyNode::default_with(ProxyProtocol::Trojan, &name, &server, port);
    node.password = password;
    node.transport = transport;
    node.transport_host = transport_host;
    node.tls_enabled = true;
    node.tls_sni = tls_sni;
    node.tls_fingerprint = if !fp.is_empty() { fp } else { fingerprint };
    node.tls_alpn = alpn;
    node.reality_enabled = security == "reality";

    if node.reality_enabled {
        node.reality_public_key = reality_public_key;
        node.reality_short_id = reality_short_id;
    }

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

fn decode_component(value: &str) -> String {
    urlencoding::decode(value)
        .map(|decoded| decoded.into_owned())
        .unwrap_or_else(|_| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_trojan;
    use super::super::types::{ProxyProtocol, TransportType};

    #[test]
    fn test_parse_trojan_basic() {
        let url = "trojan://secret@example.com:443#Basic%20Node";

        let node = parse_trojan(url).unwrap();

        assert_eq!(node.protocol, ProxyProtocol::Trojan);
        assert_eq!(node.name, "Basic Node");
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.password, "secret");
        assert_eq!(node.transport, TransportType::Tcp);
        assert!(node.tls_enabled);
        assert_eq!(node.tls_sni, "example.com");
        assert!(!node.reality_enabled);
        assert!(node.tls_alpn.is_empty());
    }

    #[test]
    fn test_parse_trojan_reality() {
        let url = "trojan://secret@example.com:8443?security=reality&servername=www.google.com&host=cdn.example.com&fp=chrome&alpn=h2,http/1.1&pbk=pubkey123&sid=beef#Reality%20Node";

        let node = parse_trojan(url).unwrap();

        assert_eq!(node.protocol, ProxyProtocol::Trojan);
        assert_eq!(node.name, "Reality Node");
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 8443);
        assert_eq!(node.password, "secret");
        assert_eq!(node.transport, TransportType::Tcp);
        assert!(node.tls_enabled);
        assert!(node.reality_enabled);
        assert_eq!(node.tls_sni, "www.google.com");
        assert_eq!(node.tls_fingerprint, "chrome");
        assert_eq!(node.tls_alpn, vec!["h2", "http/1.1"]);
        assert_eq!(node.reality_public_key, "pubkey123");
        assert_eq!(node.reality_short_id, "beef");
    }

    #[test]
    fn test_parse_trojan_ws() {
        let url = "trojan://secret@ws.example.com:443?type=ws&host=cdn.example.com&path=%2Fws#Ws%20Node";

        let node = parse_trojan(url).unwrap();

        assert_eq!(node.protocol, ProxyProtocol::Trojan);
        assert_eq!(node.name, "Ws Node");
        assert_eq!(node.server, "ws.example.com");
        assert_eq!(node.password, "secret");
        assert_eq!(node.transport, TransportType::Ws);
        assert_eq!(node.transport_host, "cdn.example.com");
        assert_eq!(node.transport_path, "/ws");
        assert_eq!(node.transport_service, "");
        assert!(node.tls_enabled);
        assert_eq!(node.tls_sni, "cdn.example.com");
    }

    #[test]
    fn test_parse_trojan_decodes_percent_encoded_password() {
        let url = "trojan://pa%40ss%3A%23%3F@example.com:443#Encoded%20Trojan";

        let node = parse_trojan(url).unwrap();

        assert_eq!(node.password, "pa@ss:#?");
    }
}

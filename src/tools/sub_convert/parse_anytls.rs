use super::types::{ProxyNode, ProxyProtocol, TransportType};
use reqwest::Url;

pub fn parse_anytls(url: &str) -> Result<ProxyNode, String> {
    let raw = url
        .strip_prefix("anytls://")
        .ok_or_else(|| "Invalid anytls URL prefix".to_string())?;
    let parsed = Url::parse(&format!("anytls://{raw}"))
        .map_err(|e| format!("Failed to parse anytls URL: {e}"))?;

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
        .unwrap_or_else(|| "anytls".to_string());

    let mut transport = TransportType::Tcp;
    let mut transport_host = String::new();
    let mut transport_path = String::new();
    let mut sni = String::new();
    let mut servername = String::new();
    let mut tls_fingerprint = String::new();
    let mut tls_alpn = Vec::new();
    let mut tls_insecure = false;

    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "type" => {
                transport = match value.as_ref() {
                    "ws" => TransportType::Ws,
                    _ => TransportType::Tcp,
                };
            }
            "host" => transport_host = value.into_owned(),
            "path" => transport_path = value.into_owned(),
            "sni" if sni.is_empty() => sni = value.into_owned(),
            "servername" if servername.is_empty() => servername = value.into_owned(),
            "fp" | "fingerprint" if tls_fingerprint.is_empty() => {
                tls_fingerprint = value.into_owned()
            }
            "alpn" => {
                tls_alpn = value
                    .split(',')
                    .map(|item| item.trim())
                    .filter(|item| !item.is_empty())
                    .map(ToString::to_string)
                    .collect();
            }
            "insecure" => {
                tls_insecure = value == "1" || value.eq_ignore_ascii_case("true");
            }
            _ => {}
        }
    }

    let mut node = ProxyNode::default_with(ProxyProtocol::Anytls, &name, &server, port);
    node.password = password;
    node.transport = transport;
    node.transport_host = transport_host;
    node.tls_enabled = true;
    node.tls_sni = if !sni.is_empty() {
        sni
    } else if !servername.is_empty() {
        servername
    } else {
        server.clone()
    };
    node.tls_insecure = tls_insecure;
    node.tls_fingerprint = tls_fingerprint;
    node.tls_alpn = tls_alpn;

    match node.transport {
        TransportType::Ws => node.transport_path = transport_path,
        TransportType::Tcp | TransportType::Grpc | TransportType::Http => node.transport_path.clear(),
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
    use super::parse_anytls;
    use super::super::types::{ProxyProtocol, TransportType};

    #[test]
    fn test_parse_anytls_ws_url() {
        let url = "anytls://secret@example.com:443?type=ws&host=cdn.example.com&path=%2Fws&sni=tls.example.com&fp=chrome&alpn=h2,http/1.1&insecure=true#Shared%20Anytls";

        let node = parse_anytls(url).unwrap();

        assert_eq!(node.protocol, ProxyProtocol::Anytls);
        assert_eq!(node.name, "Shared Anytls");
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.password, "secret");
        assert_eq!(node.transport, TransportType::Ws);
        assert_eq!(node.transport_host, "cdn.example.com");
        assert_eq!(node.transport_path, "/ws");
        assert!(node.tls_enabled);
        assert_eq!(node.tls_sni, "tls.example.com");
        assert!(node.tls_insecure);
        assert_eq!(node.tls_fingerprint, "chrome");
        assert_eq!(node.tls_alpn, vec!["h2", "http/1.1"]);
    }

    #[test]
    fn test_parse_anytls_tcp_transport_and_host_fallback() {
        let url = "anytls://secret@example.com:8443?type=tcp&host=cdn.example.com&fingerprint=firefox&alpn=h2#Tcp%20Anytls";

        let node = parse_anytls(url).unwrap();

        assert_eq!(node.protocol, ProxyProtocol::Anytls);
        assert_eq!(node.transport, TransportType::Tcp);
        assert_eq!(node.transport_host, "cdn.example.com");
        assert_eq!(node.transport_path, "");
        assert_eq!(node.tls_sni, "example.com");
        assert_eq!(node.tls_fingerprint, "firefox");
        assert_eq!(node.tls_alpn, vec!["h2"]);
    }

    #[test]
    fn test_parse_anytls_ignores_host_for_tls_sni_fallback() {
        let url = "anytls://secret@example.com:8443?type=tcp&host=cdn.example.com&fingerprint=firefox&alpn=h2#Tcp%20Anytls";

        let node = parse_anytls(url).unwrap();

        assert_eq!(node.protocol, ProxyProtocol::Anytls);
        assert_eq!(node.transport, TransportType::Tcp);
        assert_eq!(node.transport_host, "cdn.example.com");
        assert_eq!(node.transport_path, "");
        assert_eq!(node.tls_sni, "example.com");
        assert_eq!(node.tls_fingerprint, "firefox");
        assert_eq!(node.tls_alpn, vec!["h2"]);
    }

    #[test]
    fn test_parse_anytls_prefers_sni_over_servername_regardless_of_query_order() {
        let url = "anytls://secret@example.com:443?servername=legacy.example.com&sni=sni.example.com#Alias%20Anytls";

        let node = parse_anytls(url).unwrap();

        assert_eq!(node.tls_sni, "sni.example.com");
    }

    #[test]
    fn test_parse_anytls_defaults_sni_to_server() {
        let url = "anytls://secret@server.example.com:443#Server%20Fallback";

        let node = parse_anytls(url).unwrap();

        assert_eq!(node.transport, TransportType::Tcp);
        assert_eq!(node.tls_sni, "server.example.com");
        assert!(node.tls_enabled);
        assert!(!node.tls_insecure);
    }

    #[test]
    fn test_parse_anytls_decodes_percent_encoded_password() {
        let url = "anytls://pa%40ss%3A%23%3F@example.com:443#Encoded%20Anytls";

        let node = parse_anytls(url).unwrap();

        assert_eq!(node.password, "pa@ss:#?");
    }
}

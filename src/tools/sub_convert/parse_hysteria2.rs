use super::types::{ProxyNode, ProxyProtocol};
use reqwest::Url;

pub fn parse_hysteria2(url: &str) -> Result<ProxyNode, String> {
    let raw = url
        .strip_prefix("hysteria2://")
        .or_else(|| url.strip_prefix("hy2://"))
        .ok_or_else(|| "Invalid hysteria2 URL prefix".to_string())?;
    let parsed = Url::parse(&format!("hysteria2://{raw}"))
        .map_err(|e| format!("Failed to parse hysteria2 URL: {e}"))?;

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
        .unwrap_or_else(|| "hysteria2".to_string());

    let mut sni = String::new();
    let mut peer = String::new();
    let mut tls_insecure = false;
    let mut tls_alpn = Vec::new();
    let mut hy2_obfs_type = String::new();
    let mut hy2_obfs_password = String::new();
    let mut hy2_up_mbps = None;
    let mut hy2_down_mbps = None;

    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "sni" if sni.is_empty() => sni = value.into_owned(),
            "peer" if peer.is_empty() => peer = value.into_owned(),
            "insecure" => {
                tls_insecure = value == "1" || value.eq_ignore_ascii_case("true");
            }
            "alpn" => {
                tls_alpn = value
                    .split(',')
                    .map(|item| item.trim())
                    .filter(|item| !item.is_empty())
                    .map(ToString::to_string)
                    .collect();
            }
            "obfs" => hy2_obfs_type = value.into_owned(),
            "obfs-password" | "obfs_password" if hy2_obfs_password.is_empty() => {
                hy2_obfs_password = value.into_owned()
            }
            "upmbps" | "up" if hy2_up_mbps.is_none() => hy2_up_mbps = value.parse::<u64>().ok(),
            "downmbps" | "down" if hy2_down_mbps.is_none() => {
                hy2_down_mbps = value.parse::<u64>().ok()
            }
            _ => {}
        }
    }

    let mut node = ProxyNode::default_with(ProxyProtocol::Hysteria2, &name, &server, port);
    node.password = password;
    node.tls_enabled = true;
    node.tls_sni = if !sni.is_empty() {
        sni
    } else if !peer.is_empty() {
        peer
    } else {
        server.clone()
    };
    node.tls_insecure = tls_insecure;
    node.tls_alpn = tls_alpn;
    node.hy2_obfs_type = hy2_obfs_type;
    node.hy2_obfs_password = hy2_obfs_password;
    node.hy2_up_mbps = hy2_up_mbps;
    node.hy2_down_mbps = hy2_down_mbps;
    Ok(node)
}

fn decode_component(value: &str) -> String {
    urlencoding::decode(value)
        .map(|decoded| decoded.into_owned())
        .unwrap_or_else(|_| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::super::types::ProxyProtocol;
    use super::parse_hysteria2;

    #[test]
    fn test_parse_hysteria2_full_url() {
        let url = "hysteria2://secret@example.com:8443?sni=peer.example.com&insecure=1&alpn=h3,h2&obfs=salamander&obfs-password=obfs-pass&up=120&downmbps=240#Shared%20HY2";

        let node = parse_hysteria2(url).unwrap();

        assert_eq!(node.protocol, ProxyProtocol::Hysteria2);
        assert_eq!(node.name, "Shared HY2");
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 8443);
        assert_eq!(node.password, "secret");
        assert!(node.tls_enabled);
        assert_eq!(node.tls_sni, "peer.example.com");
        assert!(node.tls_insecure);
        assert_eq!(node.tls_alpn, vec!["h3", "h2"]);
        assert_eq!(node.hy2_obfs_type, "salamander");
        assert_eq!(node.hy2_obfs_password, "obfs-pass");
        assert_eq!(node.hy2_up_mbps, Some(120));
        assert_eq!(node.hy2_down_mbps, Some(240));
    }

    #[test]
    fn test_parse_hysteria2_uses_peer_and_server_fallbacks() {
        let url = "hy2://secret@fallback.example.com:443?peer=peer.example.com#Fallback%20HY2";

        let node = parse_hysteria2(url).unwrap();

        assert_eq!(node.protocol, ProxyProtocol::Hysteria2);
        assert_eq!(node.tls_sni, "peer.example.com");
        assert!(node.tls_enabled);
        assert!(!node.tls_insecure);
        assert!(node.tls_alpn.is_empty());
        assert_eq!(node.hy2_up_mbps, None);
        assert_eq!(node.hy2_down_mbps, None);
    }

    #[test]
    fn test_parse_hysteria2_prefers_sni_over_peer_regardless_of_query_order() {
        let url =
            "hy2://secret@example.com:443?peer=peer.example.com&sni=sni.example.com#Alias%20HY2";

        let node = parse_hysteria2(url).unwrap();

        assert_eq!(node.tls_sni, "sni.example.com");
    }

    #[test]
    fn test_parse_hysteria2_defaults_sni_to_server() {
        let url = "hysteria2://secret@server.example.com:443#Server%20Fallback";

        let node = parse_hysteria2(url).unwrap();

        assert_eq!(node.tls_sni, "server.example.com");
        assert!(node.tls_enabled);
    }

    #[test]
    fn test_parse_hysteria2_decodes_percent_encoded_password() {
        let url = "hysteria2://pa%40ss%3A%23%3F@example.com:443#Encoded%20HY2";

        let node = parse_hysteria2(url).unwrap();

        assert_eq!(node.password, "pa@ss:#?");
    }
}

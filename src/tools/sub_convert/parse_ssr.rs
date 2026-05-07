use super::types::{ProxyNode, ProxyProtocol};
use base64::{Engine as _, engine::general_purpose::STANDARD};

pub fn parse_ssr(url: &str) -> Result<ProxyNode, String> {
    let base64_part = url
        .strip_prefix("ssr://")
        .ok_or_else(|| "Invalid ssr URL prefix".to_string())?;
    let decoded = base64_decode(base64_part)?;
    let (server_part, query_part) = decoded.split_once("/?").unwrap_or((decoded.as_str(), ""));
    let server_part = server_part.trim_end_matches('/');
    let server_parts: Vec<&str> = server_part.split(':').collect();

    if server_parts.len() < 6 {
        return Err("Invalid SSR format".to_string());
    }

    let server = server_parts[0];
    let port = server_parts[1]
        .parse::<u16>()
        .map_err(|_| "Invalid SSR port".to_string())?;
    let protocol = server_parts[2];
    let method = server_parts[3];
    let obfs = server_parts[4];
    let password = base64_decode(server_parts[5])?;

    let mut name = String::from("ssr");
    let mut protocol_param = String::new();
    let mut obfs_param = String::new();

    for pair in query_part.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "remarks" => name = decode_optional_base64(value).unwrap_or_else(|| value.to_string()),
            "protoparam" => {
                protocol_param = decode_optional_base64(value).unwrap_or_else(|| value.to_string())
            }
            "obfsparam" => {
                obfs_param = decode_optional_base64(value).unwrap_or_else(|| value.to_string())
            }
            _ => {}
        }
    }

    let mut node = ProxyNode::default_with(ProxyProtocol::ShadowsocksR, &name, server, port);
    node.method = method.to_string();
    node.password = password;
    node.ssr_protocol = protocol.to_string();
    node.ssr_protocol_param = protocol_param;
    node.ssr_obfs = obfs.to_string();
    node.ssr_obfs_param = obfs_param;
    Ok(node)
}

fn decode_optional_base64(input: &str) -> Option<String> {
    if input.is_empty() {
        return Some(String::new());
    }
    base64_decode(input).ok()
}

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

#[cfg(test)]
mod tests {
    use super::parse_ssr;
    use super::super::types::ProxyProtocol;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    #[test]
    fn test_parse_ssr_retains_protocol_and_obfs_params() {
        let password = STANDARD.encode("secret-pass");
        let remarks = STANDARD.encode("SSR Node");
        let protoparam = STANDARD.encode("proto-param");
        let obfsparam = STANDARD.encode("obfs-host.example.com");
        let decoded = format!(
            "ssr.example.com:9443:auth_sha1_v4:aes-256-cfb:tls1.2_ticket_auth:{}//?remarks={}&protoparam={}&obfsparam={}",
            password, remarks, protoparam, obfsparam
        );
        let encoded = STANDARD.encode(decoded);
        let url = format!("ssr://{}", encoded);

        let node = parse_ssr(&url).unwrap();

        assert_eq!(node.protocol, ProxyProtocol::ShadowsocksR);
        assert_eq!(node.server, "ssr.example.com");
        assert_eq!(node.port, 9443);
        assert_eq!(node.method, "aes-256-cfb");
        assert_eq!(node.password, "secret-pass");
        assert_eq!(node.ssr_protocol, "auth_sha1_v4");
        assert_eq!(node.ssr_protocol_param, "proto-param");
        assert_eq!(node.ssr_obfs, "tls1.2_ticket_auth");
        assert_eq!(node.ssr_obfs_param, "obfs-host.example.com");
    }

    #[test]
    fn test_parse_ssr_rejects_invalid_port() {
        let password = STANDARD.encode("secret-pass");
        let decoded = format!(
            "ssr.example.com:notaport:origin:aes-256-cfb:plain:{}//?remarks={}",
            password,
            STANDARD.encode("Bad Port")
        );
        let encoded = STANDARD.encode(decoded);
        let url = format!("ssr://{}", encoded);

        let err = parse_ssr(&url).unwrap_err();

        assert!(err.contains("Invalid SSR port"));
    }
}

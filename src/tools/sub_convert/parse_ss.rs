use super::types::{ProxyNode, ProxyProtocol};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::Url;

pub fn parse_ss(url: &str) -> Result<ProxyNode, String> {
    let raw = url
        .strip_prefix("ss://")
        .ok_or_else(|| "Invalid ss URL prefix".to_string())?;

    let authority_part = raw.split_once('#').map(|(head, _)| head).unwrap_or(raw);
    if !authority_part.contains('@') {
        return parse_legacy_ss(raw);
    }

    let parsed = Url::parse(&format!("ss://{raw}"))
        .map_err(|e| format!("Failed to parse ss URL: {e}"))?;

    let server = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port().unwrap_or(8388);
    let name = decode_fragment(parsed.fragment(), "ss");
    let (method, password) = if let Some(password) = parsed.password() {
        (
            decode_component(parsed.username()),
            decode_component(password),
        )
    } else {
        let userinfo = base64_decode(parsed.username())?;
        split_method_password(&userinfo)?
    };
    let (plugin, plugin_opts) = parsed
        .query_pairs()
        .find(|(key, _)| key == "plugin")
        .map(|(_, value)| parse_plugin(&value))
        .unwrap_or_else(|| (String::new(), String::new()));

    let mut node = ProxyNode::default_with(ProxyProtocol::Shadowsocks, &name, &server, port);
    node.method = method;
    node.password = password;
    node.ss_plugin = plugin;
    node.ss_plugin_opts = plugin_opts;
    Ok(node)
}

fn parse_legacy_ss(raw: &str) -> Result<ProxyNode, String> {
    let (encoded, fragment) = raw.split_once('#').unwrap_or((raw, ""));
    let decoded = base64_decode(encoded)?;
    let (userinfo, server_part) = decoded
        .rsplit_once('@')
        .ok_or_else(|| "Invalid legacy ss format".to_string())?;
    let (server, port) = split_server_port(server_part)?;
    let (method, password) = split_method_password(userinfo)?;
    let name = decode_fragment((!fragment.is_empty()).then_some(fragment), "ss");

    let mut node = ProxyNode::default_with(ProxyProtocol::Shadowsocks, &name, &server, port);
    node.method = method;
    node.password = password;
    Ok(node)
}

fn parse_plugin(value: &str) -> (String, String) {
    if let Some((plugin, plugin_opts)) = value.split_once(';') {
        return (plugin.to_string(), plugin_opts.to_string());
    }
    (value.to_string(), String::new())
}

fn split_method_password(value: &str) -> Result<(String, String), String> {
    let (method, password) = value
        .split_once(':')
        .ok_or_else(|| "Invalid ss userinfo".to_string())?;
    Ok((method.to_string(), password.to_string()))
}

fn split_server_port(value: &str) -> Result<(String, u16), String> {
    let (server, port) = value
        .rsplit_once(':')
        .ok_or_else(|| "Invalid ss server format".to_string())?;
    let port = port.parse().map_err(|_| "Invalid ss port".to_string())?;
    Ok((server.to_string(), port))
}

fn decode_component(value: &str) -> String {
    urlencoding::decode(value)
        .map(|decoded| decoded.into_owned())
        .unwrap_or_else(|_| value.to_string())
}

fn decode_fragment(fragment: Option<&str>, default: &str) -> String {
    fragment
        .map(|value| {
            urlencoding::decode(value)
                .map(|decoded| decoded.into_owned())
                .unwrap_or_else(|_| value.to_string())
        })
        .unwrap_or_else(|| default.to_string())
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
    use super::parse_ss;
    use super::super::types::ProxyProtocol;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    #[test]
    fn test_parse_ss_sip002_userinfo() {
        let userinfo = STANDARD.encode("aes-256-gcm:secret");
        let url = format!("ss://{}@example.com:8388#SIP002%20Node", userinfo);

        let node = parse_ss(&url).unwrap();

        assert_eq!(node.protocol, ProxyProtocol::Shadowsocks);
        assert_eq!(node.name, "SIP002 Node");
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 8388);
        assert_eq!(node.method, "aes-256-gcm");
        assert_eq!(node.password, "secret");
    }

    #[test]
    fn test_parse_ss_sip002_plugin_fields() {
        let userinfo = STANDARD.encode("aes-256-gcm:secret");
        let url = format!(
            "ss://{}@example.com:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dcdn.example.com#Plugin%20Node",
            userinfo
        );

        let node = parse_ss(&url).unwrap();

        assert_eq!(node.protocol, ProxyProtocol::Shadowsocks);
        assert_eq!(node.name, "Plugin Node");
        assert_eq!(node.ss_plugin, "v2ray-plugin");
        assert_eq!(node.ss_plugin_opts, "mode=websocket;host=cdn.example.com");
    }

    #[test]
    fn test_parse_ss_legacy_inline_userinfo_with_host() {
        let url = "ss://aes-256-gcm:inline-pass@inline.example.com:443#Inline%20Node";

        let node = parse_ss(url).unwrap();

        assert_eq!(node.protocol, ProxyProtocol::Shadowsocks);
        assert_eq!(node.name, "Inline Node");
        assert_eq!(node.server, "inline.example.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.method, "aes-256-gcm");
        assert_eq!(node.password, "inline-pass");
    }

    #[test]
    fn test_parse_ss_legacy_full_base64_with_at_in_fragment() {
        let encoded = STANDARD.encode("aes-128-gcm:legacy-pass@legacy.example.com:8388");
        let url = format!("ss://{}#user%40example.com", encoded);

        let node = parse_ss(&url).unwrap();

        assert_eq!(node.protocol, ProxyProtocol::Shadowsocks);
        assert_eq!(node.name, "user@example.com");
        assert_eq!(node.server, "legacy.example.com");
        assert_eq!(node.port, 8388);
        assert_eq!(node.method, "aes-128-gcm");
        assert_eq!(node.password, "legacy-pass");
    }

    #[test]
    fn test_parse_ss_legacy_full_base64() {
        let encoded = STANDARD.encode("chacha20-ietf-poly1305:legacy-pass@legacy.example.com:443");
        let url = format!("ss://{}#Legacy%20Node", encoded);

        let node = parse_ss(&url).unwrap();

        assert_eq!(node.protocol, ProxyProtocol::Shadowsocks);
        assert_eq!(node.name, "Legacy Node");
        assert_eq!(node.server, "legacy.example.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.method, "chacha20-ietf-poly1305");
        assert_eq!(node.password, "legacy-pass");
    }
}

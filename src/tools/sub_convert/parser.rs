use super::{
    parse_anytls, parse_clash, parse_hysteria2, parse_ss, parse_ssr, parse_trojan, parse_vless,
    parse_vmess, types::ProxyNode,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};

const SUPPORTED_PREFIXES: &[&str] = &[
    "vmess://",
    "vless://",
    "trojan://",
    "ss://",
    "ssr://",
    "hysteria2://",
    "hy2://",
    "anytls://",
];

pub fn parse_proxy_url(url: &str) -> Result<ProxyNode, String> {
    if url.starts_with("vmess://") {
        parse_vmess::parse_vmess(url)
    } else if url.starts_with("vless://") {
        parse_vless::parse_vless(url)
    } else if url.starts_with("trojan://") {
        parse_trojan::parse_trojan(url)
    } else if url.starts_with("ss://") {
        parse_ss::parse_ss(url)
    } else if url.starts_with("ssr://") {
        parse_ssr::parse_ssr(url)
    } else if url.starts_with("hysteria2://") || url.starts_with("hy2://") {
        parse_hysteria2::parse_hysteria2(url)
    } else if url.starts_with("anytls://") {
        parse_anytls::parse_anytls(url)
    } else {
        Err("Unsupported proxy URL scheme".to_string())
    }
}

pub fn parse_subscription_content(content: &str) -> Result<Vec<ProxyNode>, String> {
    let trimmed = content.trim().trim_start_matches('\u{feff}').trim();
    if trimmed.is_empty() {
        return Err("订阅内容为空，请检查订阅是否过期或链接是否正确".to_string());
    }
    if trimmed.starts_with('<') {
        return Err(
            "订阅返回了 HTML 页面，而不是节点数据；请检查登录状态、订阅链接或 User-Agent"
                .to_string(),
        );
    }
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if serde_json::from_str::<serde_json::Value>(trimmed).is_err() {
            return Err("订阅 JSON 格式错误，无法转换".to_string());
        }
        return Err(
            "暂不支持此 JSON 订阅格式，请让订阅提供方返回 Clash YAML 或节点链接列表".to_string(),
        );
    }
    if looks_like_clash_yaml(trimmed) {
        return parse_clash::parse_clash_yaml(trimmed);
    }
    if trimmed.contains("://") || trimmed.starts_with('#') {
        return parse_proxy_lines(trimmed);
    }
    let decoded = base64_decode(trimmed).map_err(|_| {
        "无法识别订阅格式：仅支持 Clash YAML、节点链接列表及其 Base64 编码".to_string()
    })?;
    let decoded = decoded.trim().trim_start_matches('\u{feff}').trim();
    if decoded.is_empty() {
        return Err("Base64 解码后的订阅内容为空".to_string());
    }
    if looks_like_clash_yaml(decoded) {
        return parse_clash::parse_clash_yaml(decoded);
    }
    if decoded.starts_with('<') {
        return Err("Base64 解码后的订阅是 HTML 页面，不包含节点数据".to_string());
    }
    parse_proxy_lines(decoded)
}

fn parse_proxy_lines(content: &str) -> Result<Vec<ProxyNode>, String> {
    let mut nodes = Vec::new();
    for (index, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !SUPPORTED_PREFIXES
            .iter()
            .any(|prefix| line.starts_with(prefix))
        {
            return Err(format!(
                "第 {} 行：不支持的节点协议或无效节点链接",
                index + 1
            ));
        }
        let node = parse_proxy_url(line)
            .map_err(|error| format!("第 {} 行节点解析失败：{error}", index + 1))?;
        validate_required_fields(&node)
            .map_err(|error| format!("第 {} 行节点解析失败：{error}", index + 1))?;
        nodes.push(node);
    }
    if nodes.is_empty() {
        return Err("订阅中没有节点；空行和注释不会被转换".to_string());
    }
    Ok(nodes)
}

pub(crate) fn validate_required_fields(node: &ProxyNode) -> Result<(), String> {
    use super::types::ProxyProtocol;
    if node.server.trim().is_empty() || node.server.chars().any(char::is_whitespace) {
        return Err("server 不能为空或包含空白字符".to_string());
    }
    if node.port == 0 {
        return Err("port 必须在 1–65535 之间".to_string());
    }
    if matches!(node.protocol, ProxyProtocol::Vmess | ProxyProtocol::Vless) {
        if node.uuid.is_empty() {
            return Err("缺少 uuid".to_string());
        }
    } else if node.password.is_empty() {
        return Err("缺少 password".to_string());
    }
    if matches!(
        node.protocol,
        ProxyProtocol::Shadowsocks | ProxyProtocol::ShadowsocksR
    ) && node.method.is_empty()
    {
        return Err("缺少 cipher / method".to_string());
    }
    Ok(())
}

pub(crate) fn parse_transport(value: &str) -> Result<super::types::TransportType, String> {
    use super::types::TransportType;
    match value {
        "" | "tcp" => Ok(TransportType::Tcp),
        "ws" => Ok(TransportType::Ws),
        "grpc" => Ok(TransportType::Grpc),
        "http" | "h2" => Ok(TransportType::Http),
        _ => Err("不支持此 transport / network；无法无损转换为 sing-box".to_string()),
    }
}

pub(crate) fn validate_url_parameters(url: &reqwest::Url) -> Result<(), String> {
    for (key, value) in url.query_pairs() {
        if value.is_empty() {
            continue;
        }
        if key == "path" && (value.contains("?ed=") || value.contains("&ed=")) {
            return Err("暂不支持通过 path 声明 WebSocket early data，无法无损转换".to_string());
        }
        let allowed: &[&str] = match url.scheme() {
            "ss" => &["plugin"],
            "hysteria2" | "hy2" => &[
                "sni",
                "peer",
                "insecure",
                "allowInsecure",
                "alpn",
                "obfs",
                "obfs-password",
                "obfs_password",
                "up",
                "upmbps",
                "down",
                "downmbps",
                "type",
                "security",
            ],
            "anytls" => &[
                "type",
                "host",
                "path",
                "sni",
                "servername",
                "fp",
                "fingerprint",
                "alpn",
                "insecure",
                "allowInsecure",
                "security",
            ],
            _ => &[
                "type",
                "host",
                "path",
                "sni",
                "servername",
                "fp",
                "fingerprint",
                "alpn",
                "insecure",
                "allowInsecure",
                "security",
                "serviceName",
                "pbk",
                "sid",
                "flow",
                "encryption",
                "headerType",
            ],
        };
        if !allowed.contains(&key.as_ref()) {
            return Err(format!("不支持参数 {key}，无法无损转换"));
        }
        match key.as_ref() {
            "flow" if url.scheme() != "vless" => {
                return Err("仅 VLESS 支持 flow 参数".to_string());
            }
            "security" if !matches!(value.as_ref(), "none" | "tls" | "reality") => {
                return Err("不支持此 security，仅支持 none、tls 和 reality".to_string());
            }
            "encryption" if value != "none" => {
                return Err("不支持此 encryption，仅支持 none".to_string());
            }
            "headerType" if value != "none" => {
                return Err("不支持 TCP header 伪装，无法无损转换".to_string());
            }
            "packetEncoding"
            | "packet-encoding"
            | "mode"
            | "extra"
            | "ed"
            | "eh"
            | "earlyDataHeaderName"
            | "maxEarlyData"
            | "mport"
            | "ports"
            | "pinSHA256"
            | "allowInsecureCert"
            | "smux"
            | "mux" => {
                return Err(format!("不支持参数 {key}，无法无损转换"));
            }
            "insecure" | "allowInsecure"
                if !matches!(value.as_ref(), "0" | "1" | "true" | "false") =>
            {
                return Err(format!("{key} 必须为 0、1、true 或 false"));
            }
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn url_password(url: &reqwest::Url) -> String {
    let value = match url.password() {
        Some(password) => format!("{}:{password}", url.username()),
        None => url.username().to_string(),
    };
    urlencoding::decode(&value)
        .map(|value| value.into_owned())
        .unwrap_or(value)
}

pub(crate) fn url_server(url: &reqwest::Url) -> String {
    url.host_str()
        .unwrap_or("")
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

fn looks_like_clash_yaml(content: &str) -> bool {
    content.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with("proxies:") || line.starts_with("proxy-providers:")
    })
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
    use super::parse_subscription_content;
    use crate::tools::sub_convert::types::ProxyProtocol;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde_json::json;

    fn vmess_url(payload: serde_json::Value) -> String {
        let encoded = STANDARD.encode(serde_json::to_string(&payload).unwrap());
        format!("vmess://{encoded}")
    }

    #[test]
    fn test_parser_parses_raw_uri_lines_into_proxy_nodes() {
        let vmess = vmess_url(json!({
            "add": "vmess.example.com",
            "port": "443",
            "id": "11111111-1111-1111-1111-111111111111",
            "net": "ws",
            "ps": "VMess Node",
            "tls": "tls",
            "host": "cdn.example.com",
            "path": "/ws",
            "aid": "0"
        }));
        let trojan = "trojan://secret@trojan.example.com:443#Trojan%20Node";
        let content = format!("{vmess}\n{trojan}");

        let nodes = parse_subscription_content(&content).unwrap();

        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].protocol, ProxyProtocol::Vmess);
        assert_eq!(nodes[0].name, "VMess Node");
        assert_eq!(nodes[1].protocol, ProxyProtocol::Trojan);
        assert_eq!(nodes[1].name, "Trojan Node");
    }

    #[test]
    fn test_parser_parses_base64_encoded_subscription_content() {
        let raw = concat!(
            "vless://22222222-2222-2222-2222-222222222222@vless.example.com:443?security=tls#Vless%20Node\n",
            "hy2://secret@hy2.example.com:8443?sni=peer.example.com#Hy2%20Node"
        );
        let encoded = STANDARD.encode(raw);

        let nodes = parse_subscription_content(&encoded).unwrap();

        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].protocol, ProxyProtocol::Vless);
        assert_eq!(nodes[0].name, "Vless Node");
        assert_eq!(nodes[1].protocol, ProxyProtocol::Hysteria2);
        assert_eq!(nodes[1].name, "Hy2 Node");
    }

    #[test]
    fn rejects_empty_html_json_and_unknown_formats() {
        for content in [
            "",
            "  ",
            "<html>login required</html>",
            "{\"error\":\"expired\"}",
            "{broken",
            "not a subscription",
            "# comment only",
        ] {
            assert!(parse_subscription_content(content).is_err(), "{content}");
        }
    }

    #[test]
    fn does_not_silently_skip_unknown_or_malformed_lines() {
        let good = "trojan://secret@example.com:443#Good";
        for bad in [
            "wireguard://hidden-password@example.com",
            "garbage",
            "vmess://invalid-base64",
        ] {
            let error =
                parse_subscription_content(&format!("# comment\n{good}\n{bad}")).unwrap_err();
            assert!(error.contains("第 3 行"));
            assert!(!error.contains("hidden-password"));
        }
    }

    #[test]
    fn retains_real_nodes_with_metadata_like_names() {
        let nodes = parse_subscription_content(
            "trojan://secret@example.com:443#subscription%20expire%20官网",
        )
        .unwrap();
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn raw_and_base64_inputs_share_strict_validation() {
        let raw = "trojan://secret@example.com:443\nunsupported://secret@example.com";
        let error = parse_subscription_content(&STANDARD.encode(raw)).unwrap_err();
        assert!(error.contains("第 2 行"));
    }

    #[test]
    fn rejects_unknown_transport_and_critical_parameters() {
        for query in [
            "type=xhttp",
            "type=kcp",
            "type=quic",
            "security=xtls",
            "encryption=post-quantum",
            "headerType=http",
            "packetEncoding=xudp",
            "maxEarlyData=2048",
        ] {
            let error = parse_subscription_content(&format!(
                "vless://11111111-1111-1111-1111-111111111111@example.com:443?{query}"
            ))
            .unwrap_err();
            assert!(error.contains("第 1 行"));
        }
    }

    #[test]
    fn preserves_ipv6_colon_password_and_insecure_alias() {
        for protocol in ["trojan", "anytls", "hysteria2"] {
            let nodes = parse_subscription_content(&format!(
                "{protocol}://user:pa%3Ass@[2001:db8::1]:443?allowInsecure=1"
            ))
            .unwrap();
            assert_eq!(nodes[0].server, "2001:db8::1");
            assert_eq!(nodes[0].password, "user:pa:ss");
            assert!(nodes[0].tls_insecure);
        }
    }

    #[test]
    fn rejects_empty_credentials_and_zero_ports() {
        for url in [
            "trojan://@example.com:443",
            "trojan://secret@example.com:0",
            "vless://@example.com:443",
        ] {
            assert!(parse_subscription_content(url).is_err());
        }
    }

    #[test]
    fn test_parser_returns_error_for_invalid_clash_yaml() {
        let err = parse_subscription_content("proxies: [").unwrap_err();

        assert!(err.contains("Failed to parse Clash YAML"));
    }
}

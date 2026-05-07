use super::{
    parse_anytls, parse_clash, parse_hysteria2, parse_ss, parse_ssr, parse_trojan,
    parse_vless, parse_vmess,
    types::ProxyNode,
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

const INFO_NODE_KEYWORDS: &[&str] = &[
    "剩余流量",
    "总流量",
    "已用流量",
    "到期时间",
    "过期时间",
    "流量重置",
    "订阅",
    "官网",
    "套餐",
    "群组",
    "过滤掉",
    "更新订阅",
    "警告",
    "提示",
    "网址",
    "频道",
    "tg群",
    "公告",
    "remaining traffic",
    "used traffic",
    "total traffic",
    "subscription",
    "expire",
    "expires",
    "traffic reset",
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
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if looks_like_clash_yaml(trimmed) {
        return parse_clash::parse_clash_yaml(trimmed).map(filter_info_nodes);
    }

    let raw_urls = extract_proxy_urls(trimmed);
    if !raw_urls.is_empty() {
        return parse_proxy_urls(&raw_urls);
    }

    let decoded = match base64_decode(trimmed) {
        Ok(decoded) => decoded,
        Err(_) => trimmed.to_string(),
    };

    if looks_like_clash_yaml(&decoded) {
        return parse_clash::parse_clash_yaml(&decoded).map(filter_info_nodes);
    }

    let decoded_urls = extract_proxy_urls(&decoded);
    if !decoded_urls.is_empty() {
        return parse_proxy_urls(&decoded_urls);
    }

    Ok(Vec::new())
}


fn parse_proxy_urls(urls: &[&str]) -> Result<Vec<ProxyNode>, String> {
    urls.iter()
        .map(|url| parse_proxy_url(url))
        .collect::<Result<Vec<_>, _>>()
        .map(filter_info_nodes)
}

fn filter_info_nodes(nodes: Vec<ProxyNode>) -> Vec<ProxyNode> {
    nodes.into_iter()
        .filter(|node| !is_info_node_name(&node.name))
        .collect()
}

fn is_info_node_name(name: &str) -> bool {
    let normalized = name.trim().to_lowercase();
    INFO_NODE_KEYWORDS
        .iter()
        .any(|keyword| normalized.contains(&keyword.to_lowercase()))
}

fn extract_proxy_urls(content: &str) -> Vec<&str> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| SUPPORTED_PREFIXES.iter().any(|prefix| line.starts_with(prefix)))
        .collect()
}

fn looks_like_clash_yaml(content: &str) -> bool {
    let trimmed = content.trim_start();
    trimmed.starts_with("port:")
        || trimmed.starts_with("mixed-port:")
        || trimmed.contains("\nproxies:")
        || trimmed.starts_with("proxies:")
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
    fn test_parser_returns_error_for_invalid_clash_yaml() {
        let err = parse_subscription_content("proxies: [").unwrap_err();

        assert!(err.contains("Failed to parse Clash YAML"));
    }
}


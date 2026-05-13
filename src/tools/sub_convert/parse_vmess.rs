use super::types::{ProxyNode, ProxyProtocol, TransportType};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use std::collections::HashMap;

pub fn parse_vmess(url: &str) -> Result<ProxyNode, String> {
    let encoded = url
        .strip_prefix("vmess://")
        .ok_or_else(|| "Invalid vmess URL prefix".to_string())?;

    let json_str = base64_decode(encoded)?;
    let vmess: HashMap<String, Value> =
        serde_json::from_str(&json_str).map_err(|e| format!("Failed to parse vmess JSON: {e}"))?;

    let server = get_string(&vmess, "add", "");
    let port = get_u16(&vmess, "port").unwrap_or(443);
    let uuid = get_string(&vmess, "id", "");
    let net = get_string(&vmess, "net", "tcp");
    let name = get_string(&vmess, "ps", "vmess");
    let tls = get_string(&vmess, "tls", "");
    let method = get_string(&vmess, "scy", "");
    let transport_host = get_string(&vmess, "host", "");
    let path = get_string(&vmess, "path", "");
    let sni = get_string(&vmess, "sni", "");
    let alter_id = get_u32(&vmess, "aid").unwrap_or(0);

    let transport = match net.as_str() {
        "ws" => TransportType::Ws,
        "grpc" => TransportType::Grpc,
        "http" => TransportType::Http,
        _ => TransportType::Tcp,
    };

    let tls_enabled = tls == "tls";
    let tls_sni = if tls_enabled {
        if !sni.is_empty() {
            sni
        } else if transport_host.is_empty() {
            server.clone()
        } else {
            transport_host.clone()
        }
    } else {
        String::new()
    };

    let mut node = ProxyNode::default_with(ProxyProtocol::Vmess, &name, &server, port);
    node.uuid = uuid;
    node.alter_id = alter_id;
    node.method = method;
    node.transport = transport;
    node.transport_host = transport_host;
    node.tls_enabled = tls_enabled;
    node.tls_sni = tls_sni;

    match node.transport {
        TransportType::Grpc => {
            node.transport_service = path;
            node.transport_path.clear();
        }
        _ => {
            node.transport_path = path;
            node.transport_service.clear();
        }
    }

    Ok(node)
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

fn get_string(values: &HashMap<String, Value>, key: &str, default: &str) -> String {
    match values.get(key) {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        _ => default.to_string(),
    }
}

fn get_u16(values: &HashMap<String, Value>, key: &str) -> Option<u16> {
    match values.get(key) {
        Some(Value::Number(value)) => value.as_u64().and_then(|value| value.try_into().ok()),
        Some(Value::String(value)) => value.parse().ok(),
        _ => None,
    }
}

fn get_u32(values: &HashMap<String, Value>, key: &str) -> Option<u32> {
    match values.get(key) {
        Some(Value::Number(value)) => value.as_u64().and_then(|value| value.try_into().ok()),
        Some(Value::String(value)) => value.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::{ProxyProtocol, TransportType};
    use super::parse_vmess;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde_json::json;

    fn vmess_url(payload: serde_json::Value) -> String {
        let encoded = STANDARD.encode(serde_json::to_string(&payload).unwrap());
        format!("vmess://{}", encoded)
    }

    #[test]
    fn test_parse_vmess_ws_tls() {
        let url = vmess_url(json!({
            "add": "ws.example.com",
            "port": "443",
            "id": "11111111-1111-1111-1111-111111111111",
            "net": "ws",
            "ps": "ws-node",
            "tls": "tls",
            "host": "cdn.example.com",
            "path": "/websocket",
            "aid": "0"
        }));

        let node = parse_vmess(&url).unwrap();

        assert_eq!(node.protocol, ProxyProtocol::Vmess);
        assert_eq!(node.transport, TransportType::Ws);
        assert_eq!(node.transport_path, "/websocket");
        assert_eq!(node.transport_host, "cdn.example.com");
        assert!(node.tls_enabled);
        assert_eq!(node.tls_sni, "cdn.example.com");
    }

    #[test]
    fn test_parse_vmess_tcp_no_tls() {
        let url = vmess_url(json!({
            "add": "tcp.example.com",
            "port": "80",
            "id": "22222222-2222-2222-2222-222222222222",
            "net": "tcp",
            "ps": "tcp-node",
            "tls": "",
            "host": "",
            "path": "",
            "aid": "2"
        }));

        let node = parse_vmess(&url).unwrap();

        assert_eq!(node.transport, TransportType::Tcp);
        assert!(!node.tls_enabled);
    }

    #[test]
    fn test_parse_vmess_grpc_tls() {
        let url = vmess_url(json!({
            "add": "grpc.example.com",
            "port": "443",
            "id": "33333333-3333-3333-3333-333333333333",
            "net": "grpc",
            "ps": "grpc-node",
            "tls": "tls",
            "host": "grpc-host.example.com",
            "path": "grpc-service",
            "aid": "0"
        }));

        let node = parse_vmess(&url).unwrap();

        assert_eq!(node.transport, TransportType::Grpc);
        assert_eq!(node.transport_service, "grpc-service");
        assert_eq!(node.transport_path, "");
        assert_eq!(node.tls_sni, "grpc-host.example.com");
    }

    #[test]
    fn test_parse_vmess_tls_no_host() {
        let url = vmess_url(json!({
            "add": "fallback.example.com",
            "port": "443",
            "id": "44444444-4444-4444-4444-444444444444",
            "net": "ws",
            "ps": "fallback-node",
            "tls": "tls",
            "host": "",
            "path": "/ws",
            "aid": "0"
        }));

        let node = parse_vmess(&url).unwrap();

        assert!(node.tls_enabled);
        assert_eq!(node.tls_sni, "fallback.example.com");
    }

    #[test]
    fn test_parse_vmess_preserves_scy_method() {
        let url = vmess_url(serde_json::json!({
            "add": "cipher.example.com",
            "port": "443",
            "id": "66666666-6666-6666-6666-666666666666",
            "net": "ws",
            "ps": "cipher-node",
            "tls": "tls",
            "host": "cdn.example.com",
            "path": "/ws",
            "aid": "0",
            "scy": "aes-128-gcm"
        }));

        let node = parse_vmess(&url).unwrap();

        assert_eq!(node.method, "aes-128-gcm");
    }

    #[test]
    fn test_parse_vmess_preserves_explicit_sni_when_different_from_host() {
        let url = vmess_url(json!({
            "add": "edge.example.com",
            "port": "443",
            "id": "55555555-5555-5555-5555-555555555555",
            "net": "ws",
            "ps": "explicit-sni",
            "tls": "tls",
            "host": "cdn.example.com",
            "path": "/ws",
            "sni": "tls.example.com",
            "aid": "0"
        }));

        let node = parse_vmess(&url).unwrap();

        assert_eq!(node.transport_host, "cdn.example.com");
        assert_eq!(node.tls_sni, "tls.example.com");
    }
}

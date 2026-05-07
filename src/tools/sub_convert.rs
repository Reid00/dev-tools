pub mod types;
pub mod parse_vmess;
pub mod parse_vless;
pub mod parse_trojan;
pub mod parse_ss;
pub mod parse_ssr;
pub mod parse_hysteria2;
pub mod parse_anytls;
pub mod parser;
pub mod gen_subscription;
pub mod gen_singbox;
pub mod gen_clash;
pub mod generator;
pub mod parse_clash;
pub mod token;
pub mod runtime;

use axum::{
    Json, Router,
    extract::{Path, Query},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use generator::{ProxyInfo, TargetFormat};
use runtime::*;
use serde::{Deserialize, Serialize};
use token::{build_token_subscription_path, get_token_entry};
use urlencoding::encode;

#[derive(Deserialize)]
pub struct ConvertRequest {
    #[serde(default)]
    pub subscription_url: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub format: TargetFormat,
    #[serde(default)]
    pub include_direct: bool,
    #[serde(default)]
    pub include_dns: bool,
}

#[derive(Serialize)]
pub struct ConvertResponse {
    pub success: bool,
    pub subscription_path: Option<String>,
    pub preview_content: Option<String>,
    pub content_type: Option<String>,
    pub code_class: Option<String>,
    pub format: Option<String>,
    pub proxies: Vec<ProxyInfo>,
    pub outbounds_count: usize,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct SubscribeQuery {
    pub source: String,
    #[serde(default)]
    pub format: TargetFormat,
    #[serde(default)]
    pub include_direct: bool,
    #[serde(default)]
    pub include_dns: bool,
}

async fn subscribe_by_token(Path(id): Path<String>) -> impl IntoResponse {
    let entry = match get_token_entry(&id) {
        Ok(Some(entry)) => entry,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                "Subscription link expired or invalid",
            )
                .into_response();
        }
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
        }
    };

    let allow_passthrough = matches!(entry.format, TargetFormat::Subscription | TargetFormat::V2ray)
        && decode_base64_to_string(entry.content.trim())
            .map(|decoded| !extract_raw_proxy_urls(decoded.trim()).is_empty())
            .unwrap_or(false);

    let result = match build_passthrough_or_generated_output(
        &entry.content,
        &entry.format,
        entry.include_direct,
        entry.include_dns,
        allow_passthrough,
    ) {
        Ok(result) => result,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(entry.format.content_type())
            .unwrap_or(HeaderValue::from_static("text/plain; charset=utf-8")),
    );

    (StatusCode::OK, headers, result.content).into_response()
}

fn build_passthrough_or_generated_output(
    content: &str,
    format: &TargetFormat,
    include_direct: bool,
    include_dns: bool,
    allow_passthrough: bool,
) -> Result<generator::GenerateResult, String> {
    let nodes = parser::parse_subscription_content(content)?;
    if nodes.is_empty() {
        return Err("No valid proxy URLs found".to_string());
    }

    if allow_passthrough {
        match format {
            TargetFormat::Subscription | TargetFormat::V2ray => {
                let trimmed = content.trim();
                if let Some((raw_content, proxy_lines)) = passthrough_proxy_content(trimmed, format) {
                    if passthrough_matches_parsed_nodes(&proxy_lines, &nodes) {
                        return Ok(build_passthrough_result(raw_content, &nodes, proxy_lines.len()));
                    }
                }
            }
            _ => {}
        }
    }

    generator::generate_output(&nodes, format, include_direct, include_dns)
}

fn passthrough_matches_parsed_nodes(raw_proxy_lines: &[String], nodes: &[types::ProxyNode]) -> bool {
    if raw_proxy_lines.len() != nodes.len() {
        return false;
    }

    let raw_set = raw_proxy_lines
        .iter()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect::<std::collections::HashSet<_>>();
    let parsed_set = nodes
        .iter()
        .map(gen_subscription::node_to_uri)
        .collect::<std::collections::HashSet<_>>();

    raw_set == parsed_set
}

fn build_passthrough_result(
    raw_content: String,
    nodes: &[types::ProxyNode],
    outbounds_count: usize,
) -> generator::GenerateResult {
    generator::GenerateResult {
        content: raw_content,
        proxy_info: nodes
            .iter()
            .map(|node| generator::ProxyInfo {
                name: node.name.clone(),
                server: node.server.clone(),
                port: node.port,
                protocol: node.protocol.protocol_str().to_string(),
            })
            .collect(),
        outbounds_count,
    }
}

fn build_subscription_path(source: &str, req: &ConvertRequest, content: &str) -> Option<String> {
    if source.starts_with("raw:") {
        return build_token_subscription_path(content, &req.format, req.include_direct, req.include_dns)
            .ok();
    }

    Some(format!(
        "/api/sub/subscribe?source={}&format={}&include_direct={}&include_dns={}",
        encode(source),
        req.format.as_str(),
        req.include_direct,
        req.include_dns
    ))
}

fn passthrough_proxy_content(content: &str, format: &TargetFormat) -> Option<(String, Vec<String>)> {
    let raw_urls = extract_raw_proxy_urls(content);
    if !raw_urls.is_empty() {
        return Some((
            if matches!(format, TargetFormat::Subscription) {
                content.to_string()
            } else {
                raw_urls.join("\n")
            },
            raw_urls,
        ));
    }

    let decoded = decode_base64_to_string(content)?;
    let decoded_trimmed = decoded.trim();
    let decoded_urls = extract_raw_proxy_urls(decoded_trimmed);
    if decoded_urls.is_empty() {
        return None;
    }

    Some((
        if matches!(format, TargetFormat::Subscription) {
            content.to_string()
        } else {
            decoded_urls.join("\n")
        },
        decoded_urls,
    ))
}

fn extract_raw_proxy_urls(content: &str) -> Vec<String> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| {
            line.starts_with("vmess://")
                || line.starts_with("vless://")
                || line.starts_with("trojan://")
                || line.starts_with("ss://")
                || line.starts_with("ssr://")
                || line.starts_with("hysteria2://")
                || line.starts_with("hy2://")
                || line.starts_with("anytls://")
        })
        .map(ToString::to_string)
        .collect()
}

fn decode_base64_to_string(input: &str) -> Option<String> {
    let input: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let input = input.replace('-', "+").replace('_', "/");
    let padding = (4 - input.len() % 4) % 4;
    let input = input + &"=".repeat(padding);

    STANDARD
        .decode(input)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

async fn convert_subscription(Json(req): Json<ConvertRequest>) -> Json<ConvertResponse> {
    let source = match source_from_request(&req) {
        Ok(source) => source,
        Err(e) => {
            return Json(ConvertResponse {
                success: false,
                subscription_path: None,
                preview_content: None,
                content_type: None,
                code_class: None,
                format: None,
                proxies: vec![],
                outbounds_count: 0,
                error: Some(e),
            });
        }
    };

    let content = match parse_source_async(&source, &req.format).await {
        Ok(content) => content,
        Err(e) => {
            return Json(ConvertResponse {
                success: false,
                subscription_path: None,
                preview_content: None,
                content_type: None,
                code_class: None,
                format: None,
                proxies: vec![],
                outbounds_count: 0,
                error: Some(e),
            });
        }
    };

    let result = match build_passthrough_or_generated_output(
        &content,
        &req.format,
        req.include_direct,
        req.include_dns,
        false,
    ) {
        Ok(result) => result,
        Err(e) => {
            return Json(ConvertResponse {
                success: false,
                subscription_path: None,
                preview_content: None,
                content_type: None,
                code_class: None,
                format: None,
                proxies: vec![],
                outbounds_count: 0,
                error: Some(e),
            });
        }
    };

    let subscription_path = build_subscription_path(&source, &req, &content);

    Json(ConvertResponse {
        success: true,
        subscription_path,
        preview_content: Some(result.content),
        content_type: Some(req.format.content_type().to_string()),
        code_class: Some(req.format.code_class().to_string()),
        format: Some(req.format.as_str().to_string()),
        proxies: result.proxy_info,
        outbounds_count: result.outbounds_count,
        error: None,
    })
}

async fn subscribe(Query(req): Query<SubscribeQuery>) -> impl IntoResponse {
    let source = match sanitize_source(&req.source) {
        Ok(source) => source,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let content = match parse_source_async(&source, &req.format).await {
        Ok(content) => content,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let result = match build_passthrough_or_generated_output(
        &content,
        &req.format,
        req.include_direct,
        req.include_dns,
        true,
    ) {
        Ok(result) => result,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(req.format.content_type())
            .unwrap_or(HeaderValue::from_static("text/plain; charset=utf-8")),
    );

    (StatusCode::OK, headers, result.content).into_response()
}

pub fn router() -> Router {
    Router::new()
        .route("/convert", post(convert_subscription))
        .route("/subscribe", get(subscribe))
        .route("/subscribe/{id}", get(subscribe_by_token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use base64::engine::general_purpose::STANDARD;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn post_convert(body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let app = router();
        let req = Request::builder()
            .method("POST")
            .uri("/convert")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, json)
    }

    async fn get_subscribe(uri: &str) -> (StatusCode, String, Option<String>) {
        let app = router();
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&bytes).to_string();
        (status, body, content_type)
    }

    const SAMPLE_SUB: &str = "vmess://eyJ2IjoiMiIsInBzIjoiVGVzdC1WbWVzcyIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiNzQwNjYwYjktYmQxMi00NWE2LTk2MGYtNmI0N2RkNGNiZTY2IiwiYWlkIjoiMCIsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiZXhhbXBsZS5jb20iLCJwYXRoIjoiLyIsInRscyI6InRscyJ9";

    #[test]
    fn test_parse_ss_adapter_uses_shared_parser() {
        let userinfo = STANDARD.encode("aes-256-gcm:secret");
        let outbound = parse_ss(&format!("ss://{}@example.com:8388#Shared%20SS", userinfo)).unwrap();

        assert_eq!(outbound["type"], "shadowsocks");
        assert_eq!(outbound["tag"], "Shared SS");
        assert_eq!(outbound["server"], "example.com");
        assert_eq!(outbound["server_port"], 8388);
        assert_eq!(outbound["method"], "aes-256-gcm");
        assert_eq!(outbound["password"], "secret");
    }

    #[test]
    fn test_parse_ss_adapter_retains_plugin_fields() {
        let userinfo = STANDARD.encode("aes-256-gcm:secret");
        let outbound = parse_ss(&format!(
            "ss://{}@example.com:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dcdn.example.com#Plugin%20SS",
            userinfo
        ))
        .unwrap();

        assert_eq!(outbound["type"], "shadowsocks");
        assert_eq!(outbound["tag"], "Plugin SS");
        assert_eq!(outbound["plugin"], "v2ray-plugin");
        assert_eq!(outbound["plugin_opts"], "mode=websocket;host=cdn.example.com");
    }

    #[test]
    fn test_parse_ssr_adapter_retains_ssr_fields() {
        let password = STANDARD.encode("secret-pass");
        let remarks = STANDARD.encode("Shared SSR");
        let protoparam = STANDARD.encode("proto-param");
        let obfsparam = STANDARD.encode("obfs-host.example.com");
        let decoded = format!(
            "ssr.example.com:9443:auth_sha1_v4:aes-256-cfb:tls1.2_ticket_auth:{}//?remarks={}&protoparam={}&obfsparam={}",
            password, remarks, protoparam, obfsparam
        );
        let url = format!("ssr://{}", STANDARD.encode(decoded));

        let outbound = parse_ssr(&url).unwrap();

        assert_eq!(outbound["type"], "shadowsocksr");
        assert_eq!(outbound["tag"], "Shared SSR");
        assert_eq!(outbound["server"], "ssr.example.com");
        assert_eq!(outbound["server_port"], 9443);
        assert_eq!(outbound["method"], "aes-256-cfb");
        assert_eq!(outbound["password"], "secret-pass");
        assert_eq!(outbound["protocol"], "auth_sha1_v4");
        assert_eq!(outbound["protocol_param"], "proto-param");
        assert_eq!(outbound["obfs"], "tls1.2_ticket_auth");
        assert_eq!(outbound["obfs_param"], "obfs-host.example.com");
    }

    #[test]
    fn test_build_proxy_outbound_supports_ssr_adapter() {
        let password = STANDARD.encode("secret-pass");
        let remarks = STANDARD.encode("Build SSR");
        let decoded = format!(
            "ssr.example.com:9443:origin:aes-256-cfb:plain:{}//?remarks={}",
            password, remarks
        );
        let url = format!("ssr://{}", STANDARD.encode(decoded));

        let outbound = build_proxy_outbound(&url).unwrap().unwrap();

        assert_eq!(outbound["type"], "shadowsocksr");
        assert_eq!(outbound["tag"], "Build SSR");
    }

    #[test]
    fn test_build_proxy_outbound_rejects_invalid_ssr_port() {
        let password = STANDARD.encode("secret-pass");
        let remarks = STANDARD.encode("Bad SSR");
        let decoded = format!(
            "ssr.example.com:notaport:origin:aes-256-cfb:plain:{}//?remarks={}",
            password, remarks
        );
        let url = format!("ssr://{}", STANDARD.encode(decoded));

        let err = build_proxy_outbound(&url).unwrap_err();

        assert!(err.contains("Invalid SSR port"));
    }

    #[tokio::test]
    async fn test_convert_subscription_surfaces_invalid_ssr_parse_error() {
        let password = STANDARD.encode("secret-pass");
        let remarks = STANDARD.encode("Bad SSR");
        let decoded = format!(
            "ssr.example.com:notaport:origin:aes-256-cfb:plain:{}//?remarks={}",
            password, remarks
        );
        let url = format!("ssr://{}", STANDARD.encode(decoded));

        let (status, body) = post_convert(serde_json::json!({
            "content": url,
            "format": "singbox"
        }))
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], false);
        assert_eq!(body["outbounds_count"], 0);
        assert_eq!(body["proxies"].as_array().unwrap().len(), 0);
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("Invalid SSR port"));
    }

    #[test]
    fn test_generate_clash_yaml_retains_ssr_fields() {
        let password = STANDARD.encode("secret-pass");
        let remarks = STANDARD.encode("Clash SSR");
        let protoparam = STANDARD.encode("proto-param");
        let obfsparam = STANDARD.encode("obfs-host.example.com");
        let decoded = format!(
            "ssr.example.com:9443:auth_sha1_v4:aes-256-cfb:tls1.2_ticket_auth:{}//?remarks={}&protoparam={}&obfsparam={}",
            password, remarks, protoparam, obfsparam
        );
        let url = format!("ssr://{}", STANDARD.encode(decoded));

        let (yaml, _) = generate_clash_yaml(&[url], false, false).unwrap();
        let doc: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let proxy = &doc["proxies"].as_sequence().unwrap()[0];

        assert_eq!(proxy["type"].as_str().unwrap(), "ssr");
        assert_eq!(proxy["cipher"].as_str().unwrap(), "aes-256-cfb");
        assert_eq!(proxy["password"].as_str().unwrap(), "secret-pass");
        assert_eq!(proxy["protocol"].as_str().unwrap(), "auth_sha1_v4");
        assert_eq!(proxy["protocol-param"].as_str().unwrap(), "proto-param");
        assert_eq!(proxy["obfs"].as_str().unwrap(), "tls1.2_ticket_auth");
        assert_eq!(proxy["obfs-param"].as_str().unwrap(), "obfs-host.example.com");
    }

    #[test]
    fn test_generate_singbox_config_retains_ss_plugin_fields() {
        let userinfo = STANDARD.encode("aes-256-gcm:secret");
        let url = format!(
            "ss://{}@example.com:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dcdn.example.com#Plugin%20SS",
            userinfo
        );

        let (config, _) = generate_singbox_config(&[url], false, false).unwrap();
        let outbound = config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|outbound| outbound["type"] == "shadowsocks")
            .unwrap();

        assert_eq!(outbound["plugin"], "v2ray-plugin");
        assert_eq!(outbound["plugin_opts"], "mode=websocket;host=cdn.example.com");
    }

    #[test]
    fn test_parse_hysteria2_adapter_uses_shared_parser() {
        let outbound = parse_hysteria2("hysteria2://secret@example.com:8443?sni=peer.example.com&insecure=1&alpn=h3,h2&obfs=salamander&obfs-password=obfs-pass&up=120&downmbps=240#Shared%20HY2").unwrap();

        assert_eq!(outbound["type"], "hysteria2");
        assert_eq!(outbound["tag"], "Shared HY2");
        assert_eq!(outbound["server"], "example.com");
        assert_eq!(outbound["server_port"], 8443);
        assert_eq!(outbound["password"], "secret");
        assert_eq!(outbound["tls"]["enabled"], true);
        assert_eq!(outbound["tls"]["server_name"], "peer.example.com");
        assert_eq!(outbound["tls"]["insecure"], true);
        assert_eq!(outbound["tls"]["alpn"][0], "h3");
        assert_eq!(outbound["tls"]["alpn"][1], "h2");
        assert_eq!(outbound["obfs"]["type"], "salamander");
        assert_eq!(outbound["obfs"]["password"], "obfs-pass");
        assert_eq!(outbound["up_mbps"], 120);
        assert_eq!(outbound["down_mbps"], 240);
    }

    #[test]
    fn test_parse_anytls_adapter_uses_shared_parser() {
        let outbound = parse_anytls("anytls://secret@example.com:443?type=ws&host=cdn.example.com&path=%2Fws&sni=tls.example.com&fp=chrome&alpn=h2,http/1.1&insecure=true#Shared%20Anytls").unwrap();

        assert_eq!(outbound["type"], "anytls");
        assert_eq!(outbound["tag"], "Shared Anytls");
        assert_eq!(outbound["server"], "example.com");
        assert_eq!(outbound["server_port"], 443);
        assert_eq!(outbound["password"], "secret");
        assert_eq!(outbound["tls"]["enabled"], true);
        assert_eq!(outbound["tls"]["server_name"], "tls.example.com");
        assert_eq!(outbound["tls"]["insecure"], true);
        assert_eq!(outbound["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(outbound["tls"]["alpn"][0], "h2");
        assert_eq!(outbound["tls"]["alpn"][1], "http/1.1");
        assert_eq!(outbound["transport"]["type"], "ws");
        assert_eq!(outbound["transport"]["path"], "/ws");
        assert_eq!(outbound["transport"]["headers"]["Host"], "cdn.example.com");
    }

    #[test]
    fn test_vmess_proxy_node_to_outbound_uses_method_with_auto_fallback() {
        let mut method_node = types::ProxyNode::default_with(
            types::ProxyProtocol::Vmess,
            "method-node",
            "vmess.example.com",
            443,
        );
        method_node.uuid = "88888888-8888-8888-8888-888888888888".to_string();
        method_node.method = "aes-128-gcm".to_string();

        let mut default_node = types::ProxyNode::default_with(
            types::ProxyProtocol::Vmess,
            "default-node",
            "vmess.example.com",
            443,
        );
        default_node.uuid = "99999999-9999-9999-9999-999999999999".to_string();

        let method_outbound = vmess_proxy_node_to_outbound(method_node);
        let default_outbound = vmess_proxy_node_to_outbound(default_node);

        assert_eq!(method_outbound["security"], "aes-128-gcm");
        assert_eq!(default_outbound["security"], "auto");
    }

    #[test]
    fn test_vmess_proxy_node_to_outbound_defaults_empty_ws_http_path_to_root() {
        let mut ws_node = types::ProxyNode::default_with(
            types::ProxyProtocol::Vmess,
            "ws-node",
            "ws.example.com",
            443,
        );
        ws_node.uuid = "66666666-6666-6666-6666-666666666666".to_string();
        ws_node.transport = types::TransportType::Ws;

        let mut http_node = types::ProxyNode::default_with(
            types::ProxyProtocol::Vmess,
            "http-node",
            "http.example.com",
            80,
        );
        http_node.uuid = "77777777-7777-7777-7777-777777777777".to_string();
        http_node.transport = types::TransportType::Http;

        let ws_outbound = vmess_proxy_node_to_outbound(ws_node);
        let http_outbound = vmess_proxy_node_to_outbound(http_node);

        assert_eq!(ws_outbound["transport"]["path"], "/");
        assert_eq!(http_outbound["transport"]["path"], "/");
    }

    #[test]
    fn test_generate_singbox_config_uses_shared_vmess_parser_for_numeric_fields() {
        let vmess_json = serde_json::json!({
            "v": "2",
            "ps": "numeric-vmess",
            "add": "numeric.example.com",
            "port": 8443,
            "id": "55555555-5555-5555-5555-555555555555",
            "aid": 7,
            "net": "ws",
            "type": "none",
            "host": "cdn.numeric.example.com",
            "path": "/numeric",
            "tls": "tls"
        });
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_string(&vmess_json).unwrap());
        let url = format!("vmess://{}", encoded);

        let (config, proxies) = generate_singbox_config(&[url], false, false).unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();
        let outbound = outbounds
            .iter()
            .find(|outbound| outbound["type"] == "vmess")
            .unwrap();

        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].port, 8443);
        assert_eq!(outbound["server_port"].as_u64().unwrap(), 8443);
        assert_eq!(outbound["alter_id"].as_u64().unwrap(), 7);
        assert_eq!(outbound["transport"]["type"], "ws");
        assert_eq!(outbound["transport"]["path"], "/numeric");
        assert_eq!(outbound["transport"]["headers"]["Host"], "cdn.numeric.example.com");
        assert_eq!(outbound["tls"]["server_name"], "cdn.numeric.example.com");
    }

    #[tokio::test]
    async fn test_convert_subscription_format_preview_is_base64_uri_list() {
        let body = serde_json::json!({
            "content": SAMPLE_SUB,
            "format": "subscription",
            "include_direct": false,
            "include_dns": false
        });

        let (status, json) = post_convert(body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["success"], true);
        assert_eq!(json["format"], "subscription");

        let preview = json["preview_content"].as_str().unwrap().trim();
        let decoded = STANDARD.decode(preview).unwrap();
        let decoded_text = String::from_utf8(decoded).unwrap();
        assert!(
            decoded_text.contains("vmess://")
                || decoded_text.contains("vless://")
                || decoded_text.contains("trojan://")
        );
    }

    #[tokio::test]
    async fn test_convert_singbox_format_preview_uses_selector_without_urltest() {
        let body = serde_json::json!({
            "content": SAMPLE_SUB,
            "format": "singbox",
            "include_direct": false,
            "include_dns": false
        });

        let (status, json) = post_convert(body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["success"], true);
        assert_eq!(json["format"], "singbox");

        let preview = json["preview_content"].as_str().unwrap();
        let config: serde_json::Value = serde_json::from_str(preview).unwrap();
        assert!(config["outbounds"].is_array());
        assert!(config["inbounds"].is_array());

        let outbounds = config["outbounds"].as_array().unwrap();
        let selector = outbounds
            .iter()
            .find(|outbound| outbound["type"] == "selector")
            .unwrap();
        assert_eq!(selector["tag"], "proxy");
        assert!(selector["default"].is_string());
        assert!(outbounds.iter().all(|outbound| outbound["type"] != "urltest"));
    }

    #[tokio::test]
    async fn test_convert_hiddify_safe_filters_out_unsupported_protocols() {
        let body = serde_json::json!({
            "content": concat!(
                "vmess://eyJ2IjoiMiIsInBzIjoiVGVzdC1WbWVzcyIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiNzQwNjYwYjktYmQxMi00NWE2LTk2MGYtNmI0N2RkNGNiZTY2IiwiYWlkIjoiMCIsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiZXhhbXBsZS5jb20iLCJwYXRoIjoiLyIsInRscyI6InRscyJ9\n",
                "trojan://secret@trojan.example.com:443#Trojan%20Node\n",
                "vmess://eyJ2IjoiMiIsInBzIjoiUGxhaW4gVk1lc3MiLCJhZGQiOiJwbGFpbi5leGFtcGxlLmNvbSIsInBvcnQiOiI4MCIsImlkIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5MGFiIiwiYWlkIjoiMCIsIm5ldCI6InRjcCIsInR5cGUiOiJub25lIiwiaG9zdCI6IiIsInBhdGgiOiIvIiwidGxzIjoiIn0=\n",
                "hy2://secret@hy2.example.com:8443?sni=peer.example.com#Hy2%20Node"
            ),
            "format": "hiddify_safe",
            "include_direct": false,
            "include_dns": false
        });

        let (status, json) = post_convert(body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["success"], true);
        assert_eq!(json["format"], "hiddify_safe");
        assert_eq!(json["content_type"], "application/json; charset=utf-8");
        assert_eq!(json["code_class"], "language-json");
        assert_eq!(json["proxies"].as_array().unwrap().len(), 2);
        assert!(json["proxies"].as_array().unwrap().iter().all(|proxy| {
            matches!(proxy["protocol"].as_str(), Some("vmess" | "trojan" | "vless"))
        }));
        assert!(json["proxies"].as_array().unwrap().iter().all(|proxy| {
            proxy["name"].as_str() != Some("Plain VMess")
        }));

        let preview = json["preview_content"].as_str().unwrap();
        let config: serde_json::Value = serde_json::from_str(preview).unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();
        assert!(outbounds.iter().any(|outbound| outbound["type"] == "vmess"));
        assert!(outbounds.iter().any(|outbound| outbound["type"] == "trojan"));
        assert!(outbounds.iter().all(|outbound| outbound["type"] != "hysteria2"));
    }

    #[tokio::test]
    async fn test_convert_hiddify_safe_filters_out_reality_nodes() {
        let body = serde_json::json!({
            "content": concat!(
                "vless://11111111-1111-1111-1111-111111111111@vless.example.com:443?security=tls#TLS%20VLESS\n",
                "vless://22222222-2222-2222-2222-222222222222@reality-vless.example.com:443?security=reality&pbk=pubkey&sid=beef#Reality%20VLESS\n",
                "trojan://secret@trojan.example.com:443#Trojan%20Node\n",
                "trojan://secret@reality-trojan.example.com:443?security=reality&pbk=pubkey&sid=beef#Reality%20Trojan"
            ),
            "format": "hiddify_safe",
            "include_direct": false,
            "include_dns": false
        });

        let (status, json) = post_convert(body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["success"], true);
        assert_eq!(json["proxies"].as_array().unwrap().len(), 2);
        assert!(json["proxies"].as_array().unwrap().iter().all(|proxy| {
            proxy["name"].as_str() != Some("Reality VLESS")
                && proxy["name"].as_str() != Some("Reality Trojan")
        }));

        let preview = json["preview_content"].as_str().unwrap();
        let config: serde_json::Value = serde_json::from_str(preview).unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();
        let tags = outbounds
            .iter()
            .filter_map(|outbound| outbound["tag"].as_str())
            .collect::<Vec<_>>();
        assert!(tags.contains(&"TLS VLESS"));
        assert!(tags.contains(&"Trojan Node"));
        assert!(!tags.contains(&"Reality VLESS"));
        assert!(!tags.contains(&"Reality Trojan"));
    }

    #[tokio::test]
    async fn test_convert_singbox_format_normalizes_invalid_proxy_tags_for_groups() {
        let body = serde_json::json!({
            "content": concat!(
                "vless://11111111-1111-1111-1111-111111111111@vless.example.com:443?security=tls#auto\n",
                "trojan://secret@trojan.example.com:443#auto\n",
                "trojan://secret2@blank.example.com:443#"
            ),
            "format": "singbox",
            "include_direct": false,
            "include_dns": false
        });

        let (status, json) = post_convert(body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["success"], true);
        assert_eq!(json["format"], "singbox");

        let preview = json["preview_content"].as_str().unwrap();
        let config: serde_json::Value = serde_json::from_str(preview).unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();
        let selector = outbounds.iter().find(|outbound| outbound["tag"] == "proxy").unwrap();

        let proxy_tags = outbounds
            .iter()
            .filter_map(|outbound| outbound["tag"].as_str())
            .filter(|tag| *tag != "proxy" && *tag != "direct")
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        assert_eq!(proxy_tags.len(), 3);
        assert!(proxy_tags.iter().all(|tag| !tag.trim().is_empty()));
        assert!(proxy_tags
            .iter()
            .all(|tag| tag != "proxy" && tag != "direct"));

        let unique_proxy = proxy_tags.iter().collect::<std::collections::HashSet<_>>();
        assert_eq!(unique_proxy.len(), proxy_tags.len());
        assert_eq!(selector["outbounds"], serde_json::json!(proxy_tags));
        assert_eq!(selector["default"], selector["outbounds"][0]);
    }

    #[tokio::test]
    async fn test_convert_clash_format_preview_has_proxy_sections() {
        let body = serde_json::json!({
            "content": SAMPLE_SUB,
            "format": "clash",
            "include_direct": false,
            "include_dns": false
        });

        let (status, json) = post_convert(body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["success"], true);
        assert_eq!(json["format"], "clash");

        let preview = json["preview_content"].as_str().unwrap();
        assert!(preview.contains("proxies:"));
        assert!(preview.contains("proxy-groups:"));
    }

    #[test]
    fn test_build_passthrough_or_generated_output_rebuilds_subscription_when_raw_lines_include_info_node() {
        let content = concat!(
            "trojan://secret@good.example.com:443#Good%20Node\n",
            "trojan://secret@info.example.com:443#Remaining%20Traffic%20100GB"
        );

        let result = build_passthrough_or_generated_output(
            content,
            &TargetFormat::Subscription,
            false,
            false,
            true,
        )
        .unwrap();

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&result.content)
            .unwrap();
        let decoded = String::from_utf8(decoded).unwrap();
        let lines = decoded.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("#Good%20Node"));
        assert_eq!(result.proxy_info.len(), 1);
        assert_eq!(result.outbounds_count, 1);
    }

    #[test]
    fn test_build_passthrough_or_generated_output_keeps_v2ray_passthrough_when_sets_match() {
        let content =
            "trojan://secret@good.example.com:443?security=tls&sni=good.example.com#Good%20Node";

        let result = build_passthrough_or_generated_output(
            content,
            &TargetFormat::V2ray,
            false,
            false,
            true,
        )
        .unwrap();

        assert_eq!(result.content, content);
        assert_eq!(result.proxy_info.len(), 1);
        assert_eq!(result.outbounds_count, 1);
    }

    #[tokio::test]
    async fn test_convert_subscription_rebuilds_subscription_preview_when_input_contains_info_node() {
        let content = concat!(
            "trojan://secret@good.example.com:443#Good%20Node\n",
            "trojan://secret@info.example.com:443#Remaining%20Traffic%20100GB"
        );

        let (status, body) = post_convert(serde_json::json!({
            "content": content,
            "format": "subscription"
        }))
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], true);

        let decoded = decode_base64_to_string(body["preview_content"].as_str().unwrap()).unwrap();
        let lines = decoded.lines().collect::<Vec<_>>();
        assert_eq!(lines, vec!["trojan://secret@good.example.com:443?security=tls&sni=good.example.com#Good%20Node"]);
        assert_eq!(body["proxies"].as_array().unwrap().len(), 1);
        assert_eq!(body["outbounds_count"], 1);
    }

    #[tokio::test]
    async fn test_convert_subscription_rebuilds_v2ray_preview_when_input_contains_info_node() {
        let content = concat!(
            "trojan://secret@good.example.com:443#Good%20Node\n",
            "trojan://secret@info.example.com:443#Remaining%20Traffic%20100GB"
        );

        let (status, body) = post_convert(serde_json::json!({
            "content": content,
            "format": "v2ray"
        }))
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], true);
        assert_eq!(
            body["preview_content"].as_str().unwrap(),
            "trojan://secret@good.example.com:443?security=tls&sni=good.example.com#Good%20Node"
        );
        assert_eq!(body["proxies"].as_array().unwrap().len(), 1);
        assert_eq!(body["outbounds_count"], 1);
    }

    #[tokio::test]
    async fn test_convert_subscription_path_round_trip_rebuilds_token_output_when_input_contains_info_node() {
        let content = concat!(
            "trojan://secret@good.example.com:443#Good%20Node\n",
            "trojan://secret@info.example.com:443#Remaining%20Traffic%20100GB"
        );

        let (status, json) = post_convert(serde_json::json!({
            "content": content,
            "format": "subscription",
            "include_direct": false,
            "include_dns": false
        }))
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["success"], true);

        let path = json["subscription_path"].as_str().unwrap();
        let api_uri = path.trim_start_matches("/api/sub");
        let (status, body, _) = get_subscribe(api_uri).await;

        assert_eq!(status, StatusCode::OK);
        let decoded = decode_base64_to_string(body.trim()).unwrap();
        let lines = decoded.lines().collect::<Vec<_>>();
        assert_eq!(lines, vec!["trojan://secret@good.example.com:443?security=tls&sni=good.example.com#Good%20Node"]);
    }

    #[tokio::test]
    async fn test_convert_default_format_is_subscription() {
        let body = serde_json::json!({
            "content": SAMPLE_SUB,
            "include_direct": true,
            "include_dns": false
        });

        let (status, json) = post_convert(body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["success"], true);
        assert_eq!(json["format"], "subscription");
        assert_eq!(json["content_type"], "text/plain; charset=utf-8");

        let preview = json["preview_content"].as_str().unwrap().trim();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(preview)
            .unwrap();
        let decoded_text = String::from_utf8(decoded).unwrap();
        assert!(decoded_text.contains("vmess://"));
    }

    #[test]
    fn test_build_subscription_path_uses_token_for_raw_content() {
        let req = ConvertRequest {
            subscription_url: None,
            content: Some(SAMPLE_SUB.to_string()),
            format: TargetFormat::Singbox,
            include_direct: true,
            include_dns: false,
        };

        let path = build_subscription_path("raw:sample", &req, SAMPLE_SUB).unwrap();
        assert!(path.starts_with("/api/sub/subscribe/"));
        assert!(path.len() > "/api/sub/subscribe/".len());
    }

    #[test]
    fn test_build_subscription_path_uses_live_link_for_url_source() {
        let req = ConvertRequest {
            subscription_url: Some("https://example.com/sub?token=abc def".to_string()),
            content: None,
            format: TargetFormat::Clash,
            include_direct: true,
            include_dns: false,
        };

        let path = build_subscription_path(
            "https://example.com/sub?token=abc def",
            &req,
            SAMPLE_SUB,
        )
        .unwrap();

        assert_eq!(
            path,
            "/api/sub/subscribe?source=https%3A%2F%2Fexample.com%2Fsub%3Ftoken%3Dabc%20def&format=clash&include_direct=true&include_dns=false"
        );
    }

    #[tokio::test]
    async fn test_convert_returns_subscription_path() {
        let body = serde_json::json!({
            "content": SAMPLE_SUB,
            "format": "singbox",
            "include_direct": true,
            "include_dns": true
        });

        let (status, json) = post_convert(body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["success"], true);
        let path = json["subscription_path"].as_str().unwrap();
        assert!(path.starts_with("/api/sub/subscribe/"));
        assert!(path.len() > "/api/sub/subscribe/".len());
        assert!(
            json["preview_content"]
                .as_str()
                .unwrap()
                .contains("outbounds")
        );
    }

    #[test]
    fn test_build_token_subscription_path() {
        let path = build_token_subscription_path(
            SAMPLE_SUB,
            &TargetFormat::Clash,
            true,
            false,
        )
        .unwrap();
        assert!(path.starts_with("/api/sub/subscribe/"));
        assert!(path.len() > "/api/sub/subscribe/".len());
    }

    #[tokio::test]
    async fn test_subscribe_subscription_passthrough_keeps_base64_content_when_sets_match() {
        let canonical = STANDARD.encode(
            "trojan://secret@good.example.com:443?security=tls&sni=good.example.com#Good%20Node",
        );
        let path = build_token_subscription_path(
            &canonical,
            &TargetFormat::Subscription,
            false,
            false,
        )
        .unwrap();
        let api_uri = path.trim_start_matches("/api/sub");

        let (status, body, content_type) = get_subscribe(api_uri).await;
        assert_eq!(status, StatusCode::OK);
        assert!(content_type.unwrap_or_default().starts_with("text/plain"));
        assert_eq!(body.trim(), canonical);
    }

    #[tokio::test]
    async fn test_subscribe_by_token_singbox_content_type() {
        let body = serde_json::json!({
            "content": SAMPLE_SUB,
            "format": "singbox",
            "include_direct": true,
            "include_dns": false
        });

        let (status, json) = post_convert(body).await;
        assert_eq!(status, StatusCode::OK);
        let path = json["subscription_path"].as_str().unwrap();

        let api_uri = path.trim_start_matches("/api/sub");
        let (status, body, content_type) = get_subscribe(api_uri).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            content_type
                .unwrap_or_default()
                .starts_with("application/json")
        );
        assert!(body.contains("outbounds"));
        assert!(!body.contains("\"type\": \"block\""));
        assert!(!body.contains("\"type\": \"dns\""));
    }

    #[tokio::test]
    async fn test_subscribe_by_token_hiddify_safe_content_type() {
        let body = serde_json::json!({
            "content": concat!(
                "trojan://secret@trojan.example.com:443#Trojan%20Node\n",
                "hy2://secret@hy2.example.com:8443?sni=peer.example.com#Hy2%20Node"
            ),
            "format": "hiddify_safe",
            "include_direct": true,
            "include_dns": false
        });

        let (status, json) = post_convert(body).await;
        assert_eq!(status, StatusCode::OK);
        let path = json["subscription_path"].as_str().unwrap();

        let api_uri = path.trim_start_matches("/api/sub");
        let (status, body, content_type) = get_subscribe(api_uri).await;
        assert_eq!(status, StatusCode::OK);
        assert!(content_type
            .unwrap_or_default()
            .starts_with("application/json"));
        let config: serde_json::Value = serde_json::from_str(&body).unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();
        assert!(outbounds.iter().any(|outbound| outbound["type"] == "trojan"));
        assert!(outbounds.iter().all(|outbound| outbound["type"] != "hysteria2"));
    }

    #[tokio::test]
    async fn test_subscribe_by_token_not_found() {
        let (status, body, _) = get_subscribe("/subscribe/not-found-token").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("expired") || body.contains("invalid"));
    }

    #[test]
    fn test_generate_singbox_config_rejects_anytls_websocket_from_urls() {
        let url = "anytls://secret@example.com:443?type=ws&host=cdn.example.com&path=%2Fws&sni=tls.example.com#Shared%20Anytls".to_string();

        let result = generate_singbox_config(&[url], false, false);

        match result {
            Ok(_) => panic!("expected AnyTLS websocket sing-box generation to fail"),
            Err(err) => assert_eq!(
                err,
                "AnyTLS websocket transport is not supported for sing-box output"
            ),
        }
    }

    #[test]
    fn test_generate_singbox_config_rejects_ssr_urls() {
        let password = STANDARD.encode("secret-pass");
        let remarks = STANDARD.encode("SSR Node");
        let protoparam = STANDARD.encode("proto-param");
        let obfsparam = STANDARD.encode("obfs-host.example.com");
        let decoded = format!(
            "ssr.example.com:9443:auth_sha1_v4:aes-256-cfb:tls1.2_ticket_auth:{}//?remarks={}&protoparam={}&obfsparam={}",
            password, remarks, protoparam, obfsparam
        );
        let url = format!("ssr://{}", STANDARD.encode(decoded));

        let result = generate_singbox_config(&[url], false, false);

        match result {
            Ok(_) => panic!("expected SSR sing-box generation to fail"),
            Err(err) => assert_eq!(err, "ShadowsocksR is not supported for sing-box output"),
        }
    }


    #[test]
    fn test_generate_singbox_config_uses_mixed_inbound() {
        let (config, _) = generate_singbox_config(&[SAMPLE_SUB.to_string()], true, true).unwrap();
        let inbounds = config["inbounds"].as_array().unwrap();
        let first = inbounds.first().unwrap();
        assert_eq!(first["type"].as_str().unwrap(), "mixed");
        assert_eq!(first["listen"].as_str().unwrap(), "127.0.0.1");
        assert_eq!(first["listen_port"].as_u64().unwrap(), 10808);
    }

    #[tokio::test]
    async fn test_subscribe_v2ray_content_type_and_plain_lines() {
        let source = format!("raw:{}", SAMPLE_SUB);
        let uri = format!(
            "/subscribe?source={}&format=v2ray&include_direct=true&include_dns=false",
            urlencoding::encode(&source)
        );
        let (status, body, content_type) = get_subscribe(&uri).await;
        assert_eq!(status, StatusCode::OK);
        assert!(content_type.unwrap_or_default().starts_with("text/plain"));
        let text = body.trim();
        assert!(text.starts_with("vmess://"));
        assert!(
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .is_err(),
            "v2ray format should be plain URI lines, not base64 wrapped"
        );
    }

    #[tokio::test]
    async fn test_convert_singbox_clash_vless_reality_preserves_grpc_and_reality_fields() {
        let clash_yaml = r#"
proxies:
  - name: clash-vless-reality
    type: vless
    server: vless.example.com
    port: 443
    uuid: 88888888-8888-8888-8888-888888888888
    tls: true
    servername: reality.example.com
    client-fingerprint: firefox
    alpn:
      - h2
    network: grpc
    grpc-opts:
      grpc-service-name: grpc-service
    reality-opts:
      public-key: pubkey123
      short-id: 1a2b
"#;

        let (status, body) = post_convert(serde_json::json!({
            "content": clash_yaml,
            "format": "singbox"
        }))
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], true);

        let preview = body["preview_content"].as_str().unwrap();
        let config: serde_json::Value = serde_json::from_str(preview).unwrap();
        let outbound = config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|outbound| outbound["type"] == "vless")
            .unwrap();

        assert_eq!(outbound["transport"]["type"], "grpc");
        assert_eq!(outbound["transport"]["service_name"], "grpc-service");
        assert_eq!(outbound["tls"]["server_name"], "reality.example.com");
        assert_eq!(outbound["tls"]["utls"]["fingerprint"], "firefox");
        assert_eq!(outbound["tls"]["alpn"][0], "h2");
        assert_eq!(outbound["tls"]["reality"]["enabled"], true);
        assert_eq!(outbound["tls"]["reality"]["public_key"], "pubkey123");
        assert_eq!(outbound["tls"]["reality"]["short_id"], "1a2b");
    }

    #[test]
    fn test_parse_vless_reality_preserves_tls_fields() {
        let url = "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=reality&sni=www.google.com&fp=chrome&pbk=abcdef123456&sid=11#r1";
        let outbound = parse_vless(url).unwrap();
        assert_eq!(outbound["type"], "vless");
        assert_eq!(outbound["tls"]["enabled"], true);
        assert_eq!(outbound["tls"]["server_name"], "www.google.com");
        assert_eq!(outbound["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(outbound["tls"]["reality"]["enabled"], true);
        assert_eq!(outbound["tls"]["reality"]["public_key"], "abcdef123456");
    }

    #[test]
    fn test_parse_trojan_runtime_adapter_decodes_name_and_defaults_ws_path() {
        let url = "trojan://pass@example.com:443?type=ws&host=cdn.example.com#Ws%20Node";
        let outbound = parse_trojan(url).unwrap();
        assert_eq!(outbound["type"], "trojan");
        assert_eq!(outbound["tag"], "Ws Node");
        assert_eq!(outbound["tls"]["server_name"], "cdn.example.com");
        assert_eq!(outbound["transport"]["type"], "ws");
        assert_eq!(outbound["transport"]["path"], "/");
        assert_eq!(outbound["transport"]["headers"]["Host"], "cdn.example.com");
    }

    #[test]
    fn test_parse_trojan_preserves_sni_fingerprint() {
        let url = "trojan://pass@example.com:443?type=ws&host=cdn.example.com&path=%2Fws&sni=www.google.com&fp=chrome&alpn=h2,http/1.1#t1";
        let outbound = parse_trojan(url).unwrap();
        assert_eq!(outbound["type"], "trojan");
        assert_eq!(outbound["tls"]["server_name"], "www.google.com");
        assert_eq!(outbound["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(outbound["tls"]["alpn"][0], "h2");
        assert_eq!(outbound["transport"]["type"], "ws");
    }

    #[test]
    fn test_generate_clash_yaml_uses_shared_node_generator_for_vmess_cipher() {
        let payload = serde_json::json!({
            "v": "2",
            "ps": "vmess-cipher",
            "add": "vmess.example.com",
            "port": "443",
            "id": "11111111-1111-1111-1111-111111111111",
            "aid": "0",
            "net": "ws",
            "type": "none",
            "host": "cdn.example.com",
            "path": "/ws",
            "tls": "tls",
            "scy": "aes-128-gcm"
        });
        let url = format!(
            "vmess://{}",
            STANDARD.encode(serde_json::to_string(&payload).unwrap())
        );

        let (yaml, _) = generate_clash_yaml(&[url], false, false).unwrap();
        let doc: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let proxy = doc["proxies"].as_sequence().unwrap().first().unwrap();

        assert_eq!(proxy["type"].as_str().unwrap(), "vmess");
        assert_eq!(proxy["cipher"].as_str().unwrap(), "aes-128-gcm");
        assert_eq!(proxy["network"].as_str().unwrap(), "ws");
        assert_eq!(proxy["ws-opts"]["path"].as_str().unwrap(), "/ws");
    }

    #[test]
    fn test_generate_clash_yaml_preserves_grpc_tls_fields() {
        let vless = "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=grpc&serviceName=svc&sni=www.google.com&security=tls&fp=chrome&alpn=h2,http/1.1#g1";
        let (yaml, _) = generate_clash_yaml(&[vless.to_string()], true, false).unwrap();
        let doc: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let proxies = doc["proxies"].as_sequence().unwrap();
        let first = proxies.first().unwrap();
        assert_eq!(first["network"].as_str().unwrap(), "grpc");
        assert_eq!(
            first["grpc-opts"]["grpc-service-name"].as_str().unwrap(),
            "svc"
        );
        assert_eq!(first["client-fingerprint"].as_str().unwrap(), "chrome");
        assert_eq!(first["alpn"][0].as_str().unwrap(), "h2");
        assert_eq!(first["servername"].as_str().unwrap(), "www.google.com");
    }

    #[test]
    fn test_clash_trojan_to_url_preserves_servername_host_and_fingerprint() {
        let yaml = r#"
proxies:
  - name: trojan-test
    type: trojan
    server: example.com
    port: 443
    password: pass
    tls: true
    servername: www.google.com
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

        let urls = parse_clash_yaml(yaml).unwrap();
        assert_eq!(urls.len(), 1);
        let url = &urls[0];
        assert!(url.starts_with("trojan://pass@example.com:443?"));
        assert!(url.contains("security=tls"));
        assert!(url.contains("sni=www.google.com"));
        assert!(url.contains("fp=chrome"));
        assert!(url.contains("alpn=h2%2Chttp%2F1.1"));
        assert!(url.contains("type=ws"));
        assert!(url.contains("path=%2Fws"));
        assert!(url.contains("host=cdn.example.com"));
    }

    #[test]
    fn test_clash_ssr_to_url_preserves_protocol_and_obfs_params() {
        let yaml = r#"
proxies:
  - name: ssr-test
    type: ssr
    server: ssr.example.com
    port: 9443
    cipher: aes-256-cfb
    password: secret-pass
    protocol: auth_sha1_v4
    protocol-param: proto-param
    obfs: tls1.2_ticket_auth
    obfs-param: obfs-host.example.com
"#;

        let urls = parse_clash_yaml(yaml).unwrap();
        assert_eq!(urls.len(), 1);

        let rebuilt = &urls[0];
        let encoded = rebuilt.strip_prefix("ssr://").unwrap();
        let decoded = base64_decode(encoded).unwrap();

        assert!(decoded.contains("remarks="));
        assert!(decoded.contains(&format!(
            "protoparam={}",
            base64::engine::general_purpose::STANDARD.encode("proto-param")
        )));
        assert!(decoded.contains(&format!(
            "obfsparam={}",
            base64::engine::general_purpose::STANDARD.encode("obfs-host.example.com")
        )));
    }

    #[test]
    fn test_parse_subscription_content_accepts_anytls_raw_lines() {
        let content = "anytls://pass@example.com:443?sni=www.google.com#any\nvmess://abc";
        let urls = parse_subscription_content(content).unwrap();
        assert_eq!(urls.len(), 2);
        assert!(urls.iter().any(|u| u.starts_with("anytls://")));
    }

    #[test]
    fn test_parse_subscription_content_accepts_anytls_in_base64_subscription() {
        let raw = "anytls://pass@example.com:443?sni=www.google.com#any\nvmess://abc";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        let urls = parse_subscription_content(&encoded).unwrap();
        assert_eq!(urls.len(), 2);
        assert!(urls.iter().any(|u| u.starts_with("anytls://")));
    }

    #[test]
    fn test_parse_anytls_preserves_tls_ws_fields() {
        let url = "anytls://pass@example.com:443?type=ws&path=%2Fws&host=cdn.example.com&sni=www.google.com&fp=chrome&alpn=h2,http/1.1&insecure=1#a1";
        let outbound = parse_anytls(url).unwrap();

        assert_eq!(outbound["type"], "anytls");
        assert_eq!(outbound["password"], "pass");
        assert_eq!(outbound["tls"]["server_name"], "www.google.com");
        assert_eq!(outbound["tls"]["insecure"], true);
        assert_eq!(outbound["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(outbound["tls"]["alpn"][0], "h2");
        assert_eq!(outbound["transport"]["type"], "ws");
        assert_eq!(outbound["transport"]["path"], "/ws");
        assert_eq!(outbound["transport"]["headers"]["Host"], "cdn.example.com");
    }

    #[test]
    fn test_clash_hysteria2_to_url_percent_encodes_password() {
        let yaml = r#"
proxies:
  - name: hy2-encoded
    type: hysteria2
    server: hy.example.com
    port: 443
    password: pa@ss:#?
"#;

        let urls = parse_clash_yaml(yaml).unwrap();
        assert_eq!(urls.len(), 1);
        assert!(urls[0].starts_with("hysteria2://pa%40ss%3A%23%3F@hy.example.com:443"));

        let outbound = parse_hysteria2(&urls[0]).unwrap();
        assert_eq!(outbound["password"], "pa@ss:#?");
    }

    #[test]
    fn test_clash_anytls_to_url_percent_encodes_password() {
        let yaml = r#"
proxies:
  - name: anytls-encoded
    type: anytls
    server: any.example.com
    port: 443
    password: pa@ss:#?
"#;

        let urls = parse_clash_yaml(yaml).unwrap();
        assert_eq!(urls.len(), 1);
        assert!(urls[0].starts_with("anytls://pa%40ss%3A%23%3F@any.example.com:443"));

        let outbound = parse_anytls(&urls[0]).unwrap();
        assert_eq!(outbound["password"], "pa@ss:#?");
    }

    #[tokio::test]
    async fn test_convert_subscription_rejects_anytls_ws_for_singbox() {
        let url = "anytls://pass@example.com:443?type=ws&path=%2Fws&host=cdn.example.com&sni=www.google.com#bad-anytls";

        let (status, body) = post_convert(serde_json::json!({
            "content": url,
            "format": "singbox"
        }))
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], false);
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("AnyTLS websocket transport is not supported for sing-box output"));
    }

    #[test]
    fn test_clash_hysteria2_to_url_preserves_tls_obfs_bandwidth() {
        let yaml = r#"
proxies:
  - name: hy2-test
    type: hysteria2
    server: hy.example.com
    port: 443
    password: pass
    sni: www.google.com
    skip-cert-verify: true
    alpn:
      - h3
    obfs: salamander
    obfs-password: obfspass
    up: 50
    down: 120
"#;

        let urls = parse_clash_yaml(yaml).unwrap();
        assert_eq!(urls.len(), 1);
        let url = &urls[0];
        assert!(url.starts_with("hysteria2://pass@hy.example.com:443?"));
        assert!(url.contains("sni=www.google.com"));
        assert!(url.contains("insecure=1"));
        assert!(url.contains("alpn=h3"));
        assert!(url.contains("obfs=salamander"));
        assert!(url.contains("obfs-password=obfspass"));
        assert!(url.contains("up=50"));
        assert!(url.contains("down=120"));
    }

    #[test]
    fn test_clash_anytls_to_url_preserves_ws_tls_fields() {
        let yaml = r#"
proxies:
  - name: anytls-test
    type: anytls
    server: any.example.com
    port: 443
    password: pass
    servername: www.google.com
    client-fingerprint: chrome
    alpn:
      - h2
      - http/1.1
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: cdn.example.com
"#;

        let urls = parse_clash_yaml(yaml).unwrap();
        assert_eq!(urls.len(), 1);
        let url = &urls[0];
        assert!(url.starts_with("anytls://pass@any.example.com:443?"));
        assert!(url.contains("sni=www.google.com"));
        assert!(url.contains("fp=chrome"));
        assert!(url.contains("alpn=h2%2Chttp%2F1.1"));
        assert!(url.contains("insecure=1"));
        assert!(url.contains("type=ws"));
        assert!(url.contains("path=%2Fws"));
        assert!(url.contains("host=cdn.example.com"));
    }

    #[test]
    fn test_generate_subscription_content_uses_shared_generator_to_encode_trojan_password() {
        let input = "trojan://pa%40ss%3A%23%3F@example.com:443?sni=www.google.com#Trojan".to_string();

        let (content, proxies) = generate_subscription_content(&[input]).unwrap();
        let decoded = base64_decode(&content).unwrap();

        assert_eq!(proxies.len(), 1);
        assert!(decoded.starts_with("trojan://pa%40ss%3A%23%3F@example.com:443?"));
        assert!(decoded.contains("security=tls"));
    }

    #[test]
    fn test_generate_v2ray_subscription_content_uses_shared_generator_to_encode_anytls_password() {
        let input = "anytls://pa%40ss%3A%23%3F@example.com:443?sni=www.google.com#AnyTLS".to_string();

        let (content, proxies) = generate_v2ray_subscription_content(&[input]).unwrap();

        assert_eq!(proxies.len(), 1);
        assert!(content.starts_with("anytls://pa%40ss%3A%23%3F@example.com:443?"));
        assert!(content.contains("sni=www.google.com"));
    }

    #[tokio::test]
    async fn test_convert_subscription_rebuilds_subscription_output_from_proxy_nodes() {
        let (status, body) = post_convert(serde_json::json!({
            "content": "trojan://pa%40ss%3A%23%3F@example.com:443?sni=www.google.com#Trojan",
            "format": "subscription"
        }))
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], true);

        let preview = body["preview_content"].as_str().unwrap();
        let decoded = base64_decode(preview).unwrap();
        assert!(decoded.starts_with("trojan://pa%40ss%3A%23%3F@example.com:443?"));
        assert!(decoded.contains("security=tls"));
    }

    #[test]
    fn test_generate_v2ray_subscription_content_uses_shared_generator_to_encode_hysteria2_password() {
        let input = "hy2://pa%40ss%3A%23%3F@example.com:443?sni=www.google.com#HY2".to_string();

        let (content, proxies) = generate_v2ray_subscription_content(&[input]).unwrap();

        assert_eq!(proxies.len(), 1);
        assert!(content.starts_with("hysteria2://pa%40ss%3A%23%3F@example.com:443?"));
        assert!(content.contains("sni=www.google.com"));
    }

    #[test]
    fn test_generate_v2ray_subscription_content_preserves_vmess_explicit_sni() {
        let vmess_json = serde_json::json!({
            "v": "2",
            "ps": "vmess-sni",
            "add": "edge.example.com",
            "port": "443",
            "id": "66666666-6666-6666-6666-666666666666",
            "aid": "0",
            "net": "ws",
            "type": "none",
            "host": "cdn.example.com",
            "path": "/ws",
            "tls": "tls",
            "sni": "tls.example.com"
        });
        let input = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(&vmess_json).unwrap())
        );

        let (content, proxies) = generate_v2ray_subscription_content(&[input]).unwrap();
        let rebuilt = content.strip_prefix("vmess://").unwrap();
        let decoded = base64_decode(rebuilt).unwrap();
        let rebuilt_json: serde_json::Value = serde_json::from_str(&decoded).unwrap();

        assert_eq!(proxies.len(), 1);
        assert_eq!(rebuilt_json["host"], "cdn.example.com");
        assert_eq!(rebuilt_json["sni"], "tls.example.com");
    }

    #[tokio::test]
    async fn test_convert_subscription_rebuilds_hysteria2_password_encoding_from_proxy_nodes() {
        let (status, body) = post_convert(serde_json::json!({
            "content": "hy2://pa%40ss%3A%23%3F@example.com:443?sni=www.google.com#HY2",
            "format": "v2ray"
        }))
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], true);

        let preview = body["preview_content"].as_str().unwrap();
        assert!(preview.starts_with("hysteria2://pa%40ss%3A%23%3F@example.com:443?"));
        assert!(preview.contains("sni=www.google.com"));
    }

    #[tokio::test]
    async fn test_convert_subscription_rebuilds_vmess_explicit_sni_from_proxy_nodes() {
        let vmess_json = serde_json::json!({
            "v": "2",
            "ps": "vmess-sni",
            "add": "edge.example.com",
            "port": "443",
            "id": "77777777-7777-7777-7777-777777777777",
            "aid": "0",
            "net": "ws",
            "type": "none",
            "host": "cdn.example.com",
            "path": "/ws",
            "tls": "tls",
            "sni": "tls.example.com"
        });
        let content = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(&vmess_json).unwrap())
        );

        let (status, body) = post_convert(serde_json::json!({
            "content": content,
            "format": "v2ray"
        }))
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], true);

        let preview = body["preview_content"].as_str().unwrap();
        let rebuilt = preview.strip_prefix("vmess://").unwrap();
        let decoded = base64_decode(rebuilt).unwrap();
        let rebuilt_json: serde_json::Value = serde_json::from_str(&decoded).unwrap();
        assert_eq!(rebuilt_json["host"], "cdn.example.com");
        assert_eq!(rebuilt_json["sni"], "tls.example.com");
    }

    #[tokio::test]
    async fn test_convert_subscription_surfaces_malformed_clash_ss_error() {
        let yaml = r#"
proxies:
  - name: bad-ss
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
"#;

        let (status, body) = post_convert(serde_json::json!({
            "content": yaml,
            "format": "singbox"
        }))
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], false);
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("Clash SS proxy password is required"));
    }

    #[tokio::test]
    async fn test_convert_subscription_surfaces_malformed_clash_ssr_error() {
        let yaml = r#"
proxies:
  - name: bad-ssr
    type: ssr
    server: ssr.example.com
    port: 9443
    password: secret-pass
"#;

        let (status, body) = post_convert(serde_json::json!({
            "content": yaml,
            "format": "singbox"
        }))
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], false);
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("Clash SSR proxy cipher is required"));
    }

    #[tokio::test]
    async fn test_private_ip_url_rejected() {
        let body = serde_json::json!({
            "subscription_url": "http://127.0.0.1/test",
            "format": "singbox",
            "include_direct": true,
            "include_dns": true
        });

        let (status, json) = post_convert(body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["success"], false);
        assert!(
            json["error"].as_str().unwrap().contains("Private IP")
                || json["error"].as_str().unwrap().contains("localhost")
        );
    }
}

pub mod gen_clash;
pub mod gen_singbox;
pub mod gen_subscription;
pub mod generator;
pub mod parse_anytls;
pub mod parse_clash;
pub mod parse_hysteria2;
pub mod parse_ss;
pub mod parse_ssr;
pub mod parse_trojan;
pub mod parse_vless;
pub mod parse_vmess;
pub mod parser;
pub mod publish;
pub mod render;
pub mod runtime;
pub mod source;
pub mod template;
pub mod types;

use axum::{
    Json, Router,
    extract::{OriginalUri, Path},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use generator::{ProxyInfo, TargetFormat};
#[cfg(test)]
use runtime::*;
use serde::{Deserialize, Serialize};

const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";
const JSON_CODE_CLASS: &str = "language-json";

#[derive(Deserialize)]
pub struct ConvertRequest {
    pub subscription_url: String,
    #[serde(default)]
    pub template: Option<String>,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub ua: Option<String>,
    #[serde(default)]
    pub emoji: Option<String>,
    #[serde(default)]
    pub eps: Option<String>,
}

#[derive(Serialize)]
pub struct TemplateInfoResponse {
    pub id: String,
    pub name: String,
    pub description: String,
    pub reference_value: String,
    pub source: String,
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
    pub template_info: Option<TemplateInfoResponse>,
    pub error: Option<String>,
}

pub async fn list_templates() -> Json<Vec<template::TemplateDescriptor>> {
    Json(template::builtin_templates())
}

async fn convert_subscription(Json(req): Json<ConvertRequest>) -> Json<ConvertResponse> {
    match convert_subscription_inner(req).await {
        Ok(response) => Json(response),
        Err(error) => Json(error_response(error)),
    }
}

async fn convert_subscription_inner(req: ConvertRequest) -> Result<ConvertResponse, String> {
    let query_params = publish::ReferenceQueryParams::new(
        req.ua.as_deref(),
        req.emoji.as_deref(),
        req.eps.as_deref(),
    );
    let subscription_url = source::validate_subscription_input(&req.subscription_url)?;
    let subscription_url = publish::append_reference_query_params(&subscription_url, &query_params);
    let resolved_template =
        template::resolve_template(req.template.as_deref(), req.file.as_deref())?;
    let template_text = template::load_template_text(&resolved_template).await?;
    let source_content =
        runtime::fetch_subscription(&subscription_url, &TargetFormat::Singbox).await?;
    let nodes = parser::parse_subscription_content(&source_content)?;
    if nodes.is_empty() {
        return Err("No valid proxy URLs found".to_string());
    }

    let rendered = render::render_template(&template_text, &nodes)?;
    let preview_content = serde_json::to_string_pretty(&rendered)
        .map_err(|error| format!("Failed to serialize rendered config: {error}"))?;
    let outbounds_count = rendered["outbounds"]
        .as_array()
        .map(|outbounds| outbounds.len())
        .unwrap_or(0);
    let proxies = proxy_info_from_nodes(&nodes);
    let template_info = template_info_response(&resolved_template);
    let subscription_path = publish::build_config_path(
        &subscription_url,
        &template_file_value(&resolved_template),
        &query_params,
    );

    Ok(ConvertResponse {
        success: true,
        subscription_path: Some(subscription_path),
        preview_content: Some(preview_content),
        content_type: Some(JSON_CONTENT_TYPE.to_string()),
        code_class: Some(JSON_CODE_CLASS.to_string()),
        format: Some(TargetFormat::Singbox.as_str().to_string()),
        proxies,
        outbounds_count,
        template_info: Some(template_info),
        error: None,
    })
}

async fn config(
    Path(raw_source): Path<String>,
    OriginalUri(uri): OriginalUri,
) -> impl IntoResponse {
    match config_inner(raw_source, uri.query()).await {
        Ok(body) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(JSON_CONTENT_TYPE),
            );
            (StatusCode::OK, headers, body).into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error).into_response(),
    }
}

async fn config_inner(raw_source: String, query: Option<&str>) -> Result<String, String> {
    let raw_source = match query {
        Some(query) if !query.is_empty() => format!("{raw_source}?{query}"),
        _ => raw_source,
    };
    let parsed_source = source::split_config_source_and_query(&raw_source)?;
    let query_params = publish::ReferenceQueryParams::default();
    let subscription_url =
        publish::append_reference_query_params(&parsed_source.subscription_url, &query_params);
    let resolved_template = template::resolve_template(None, parsed_source.file.as_deref())?;
    let template_text = template::load_template_text(&resolved_template).await?;
    let source_content =
        runtime::fetch_subscription(&subscription_url, &TargetFormat::Singbox).await?;
    let nodes = parser::parse_subscription_content(&source_content)?;
    if nodes.is_empty() {
        return Err("No valid proxy URLs found".to_string());
    }

    let rendered = render::render_template(&template_text, &nodes)?;
    serde_json::to_string_pretty(&rendered)
        .map_err(|error| format!("Failed to serialize rendered config: {error}"))
}

fn proxy_info_from_nodes(nodes: &[types::ProxyNode]) -> Vec<ProxyInfo> {
    nodes
        .iter()
        .map(|node| generator::ProxyInfo {
            name: node.name.clone(),
            server: node.server.clone(),
            port: node.port,
            protocol: node.protocol.protocol_str().to_string(),
        })
        .collect()
}

fn template_info_response(resolved_template: &template::ResolvedTemplate) -> TemplateInfoResponse {
    TemplateInfoResponse {
        id: resolved_template.descriptor.id.to_string(),
        name: resolved_template.descriptor.name.to_string(),
        description: resolved_template.descriptor.description.to_string(),
        reference_value: template_file_value(resolved_template),
        source: match resolved_template.content_type {
            template::TemplateSource::Builtin => "builtin",
            template::TemplateSource::Remote => "remote",
        }
        .to_string(),
    }
}

fn template_file_value(resolved_template: &template::ResolvedTemplate) -> String {
    resolved_template
        .descriptor
        .index
        .map(|index| index.to_string())
        .unwrap_or_else(|| resolved_template.reference_value.clone())
}

fn error_response(error: String) -> ConvertResponse {
    ConvertResponse {
        success: false,
        subscription_path: None,
        preview_content: None,
        content_type: Some(JSON_CONTENT_TYPE.to_string()),
        code_class: Some(JSON_CODE_CLASS.to_string()),
        format: Some(TargetFormat::Singbox.as_str().to_string()),
        proxies: Vec::new(),
        outbounds_count: 0,
        template_info: None,
        error: Some(error),
    }
}

pub fn router() -> Router {
    Router::new()
        .route("/templates", get(list_templates))
        .route("/convert", post(convert_subscription))
        .route("/config/{*source}", get(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn post_convert_raw(body: serde_json::Value) -> (StatusCode, String) {
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
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    async fn post_convert(body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let (status, body) = post_convert_raw(body).await;
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        (status, json)
    }

    async fn get_route(uri: &str) -> (StatusCode, String, Option<String>) {
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

    #[tokio::test]
    async fn test_templates_route_returns_builtin_descriptors() {
        let (status, body, content_type) = get_route("/templates").await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            content_type
                .unwrap_or_default()
                .starts_with("application/json")
        );
        let templates: serde_json::Value = serde_json::from_str(&body).unwrap();
        let templates = templates.as_array().unwrap();
        assert!(
            templates
                .iter()
                .any(|template| template["id"] == "sb-config-1.14")
        );
        assert!(
            templates
                .iter()
                .all(|template| template["source"] == "builtin")
        );
    }

    #[tokio::test]
    async fn test_convert_rejects_missing_subscription_url() {
        let (status, body) = post_convert_raw(serde_json::json!({
            "template": "sb-config-1.14"
        }))
        .await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body.contains("subscription_url") || body.contains("missing field"));
    }

    #[tokio::test]
    async fn test_config_route_with_url_and_file_is_registered() {
        let (status, body, _) = get_route("/config/https://example.com/sub?token=abc&file=5").await;

        assert_ne!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("HTTP error") || body.contains("Failed to fetch subscription"));
    }

    const SAMPLE_SUB: &str = "vmess://eyJ2IjoiMiIsInBzIjoiVGVzdC1WbWVzcyIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiNzQwNjYwYjktYmQxMi00NWE2LTk2MGYtNmI0N2RkNGNiZTY2IiwiYWlkIjoiMCIsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiZXhhbXBsZS5jb20iLCJwYXRoIjoiLyIsInRscyI6InRscyJ9";

    #[test]
    fn test_parse_ss_adapter_uses_shared_parser() {
        let userinfo = STANDARD.encode("aes-256-gcm:secret");
        let outbound =
            parse_ss(&format!("ss://{}@example.com:8388#Shared%20SS", userinfo)).unwrap();

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
        assert_eq!(
            outbound["plugin_opts"],
            "mode=websocket;host=cdn.example.com"
        );
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
        assert_eq!(
            proxy["obfs-param"].as_str().unwrap(),
            "obfs-host.example.com"
        );
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
        assert_eq!(
            outbound["plugin_opts"],
            "mode=websocket;host=cdn.example.com"
        );
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
        assert_eq!(
            outbound["transport"]["headers"]["Host"],
            "cdn.numeric.example.com"
        );
        assert_eq!(outbound["tls"]["server_name"], "cdn.numeric.example.com");
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
        let input =
            "trojan://pa%40ss%3A%23%3F@example.com:443?sni=www.google.com#Trojan".to_string();

        let (content, proxies) = generate_subscription_content(&[input]).unwrap();
        let decoded = base64_decode(&content).unwrap();

        assert_eq!(proxies.len(), 1);
        assert!(decoded.starts_with("trojan://pa%40ss%3A%23%3F@example.com:443?"));
        assert!(decoded.contains("security=tls"));
    }

    #[test]
    fn test_generate_v2ray_subscription_content_uses_shared_generator_to_encode_anytls_password() {
        let input =
            "anytls://pa%40ss%3A%23%3F@example.com:443?sni=www.google.com#AnyTLS".to_string();

        let (content, proxies) = generate_v2ray_subscription_content(&[input]).unwrap();

        assert_eq!(proxies.len(), 1);
        assert!(content.starts_with("anytls://pa%40ss%3A%23%3F@example.com:443?"));
        assert!(content.contains("sni=www.google.com"));
    }

    #[test]
    fn test_generate_v2ray_subscription_content_uses_shared_generator_to_encode_hysteria2_password()
    {
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
            base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_string(&vmess_json).unwrap())
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

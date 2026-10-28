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
pub mod validate;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Query, rejection::JsonRejection},
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
    #[serde(default)]
    pub subscription_url: String,
    #[serde(default)]
    pub subscription_content: String,
    #[serde(default)]
    pub template: Option<String>,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub ua: Option<String>,
    #[serde(default)]
    pub skip_unsupported: bool,
}

#[derive(Deserialize)]
pub struct ConfigQuery {
    source: String,
    template: Option<String>,
    ua: Option<String>,
    #[serde(default)]
    skip_unsupported: bool,
}

struct ConversionError {
    status: StatusCode,
    message: String,
    skipped_nodes: Vec<parser::SkippedNode>,
}

impl ConversionError {
    fn with_skipped(mut self, mut skipped_nodes: Vec<parser::SkippedNode>) -> Self {
        skipped_nodes.sort_by_key(|node| node.index);
        self.skipped_nodes = skipped_nodes;
        self
    }

    fn response(self) -> ConvertResponse {
        let mut response = error_response(self.message);
        response.skipped_nodes = self.skipped_nodes;
        response
    }
}

impl From<String> for ConversionError {
    fn from(message: String) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            message,
            skipped_nodes: Vec::new(),
        }
    }
}

impl From<validate::ValidationError> for ConversionError {
    fn from(error: validate::ValidationError) -> Self {
        Self {
            status: if error.unavailable {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::UNPROCESSABLE_ENTITY
            },
            message: error.message,
            skipped_nodes: Vec::new(),
        }
    }
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
    pub validation: Option<validate::ValidationInfo>,
    pub skipped_nodes: Vec<parser::SkippedNode>,
    pub error: Option<String>,
}

pub async fn list_templates() -> Json<Vec<template::TemplateDescriptor>> {
    Json(template::builtin_templates())
}

async fn convert_subscription(
    payload: Result<Json<ConvertRequest>, JsonRejection>,
) -> impl IntoResponse {
    let req = match payload {
        Ok(Json(req)) => req,
        Err(error) => return (error.status(), Json(error_response(
            "请求体必须是有效 JSON，subscription_url / subscription_content、template 和 ua 必须为字符串".to_string()
        ))),
    };
    match convert_subscription_inner(req).await {
        Ok(response) => (StatusCode::OK, Json(response)),
        Err(error) => (error.status, Json(error.response())),
    }
}

async fn convert_subscription_inner(
    req: ConvertRequest,
) -> Result<ConvertResponse, ConversionError> {
    convert_subscription_with(
        req,
        runtime::fetch_subscription_with_user_agent,
        validate::check_config,
    )
    .await
}

async fn convert_subscription_with(
    req: ConvertRequest,
    fetch: impl AsyncFn(&str, &str) -> Result<String, String>,
    check: impl AsyncFn(
        &serde_json::Value,
    ) -> Result<validate::ValidationInfo, validate::ValidationError>,
) -> Result<ConvertResponse, ConversionError> {
    let url_input = req.subscription_url.trim();
    let content_input = req.subscription_content.trim();
    if url_input.is_empty() == content_input.is_empty() {
        return Err("请提供 subscription_url（订阅链接）或 subscription_content（原始内容），且只能提供其中一个".to_string().into());
    }
    if content_input.len() > 2 * 1024 * 1024 {
        return Err("订阅内容超过 2 MiB，请缩小订阅后重试".to_string().into());
    }
    let resolved_template =
        template::resolve_template(req.template.as_deref(), req.file.as_deref())?;
    let user_agent = req
        .ua
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("clashmeta");
    if user_agent.len() > 256 || HeaderValue::from_str(user_agent).is_err() {
        return Err("UA 请求头无效：请使用不含换行的客户端名称（最多 256 字符）"
            .to_string()
            .into());
    }
    let subscription_url = if url_input.is_empty() {
        None
    } else {
        Some(source::validate_subscription_input(url_input)?)
    };
    let source_content = match subscription_url.as_deref() {
        Some(url) => fetch(url, user_agent).await?,
        None => content_input.to_string(),
    };
    let entries = parser::parse_subscription_entries(&source_content)?;
    if entries.len() > 2000 {
        return Err("订阅节点超过 2000 个，请拆分订阅后重试".to_string().into());
    }
    let template_text = template::load_template_text(&resolved_template).await?;
    let ValidatedNodes {
        config: rendered,
        validation,
        nodes,
        skipped_nodes,
    } = convert_nodes(&template_text, entries, req.skip_unsupported, check).await?;
    let preview_content = serde_json::to_string_pretty(&rendered)
        .map_err(|_| "无法序列化 sing-box 配置".to_string())?;
    let outbounds_count = rendered["outbounds"].as_array().map_or(0, Vec::len);
    let mut proxies = proxy_info_from_nodes(&nodes);
    if let Some(outbounds) = rendered["outbounds"].as_array() {
        for (proxy, outbound) in proxies
            .iter_mut()
            .zip(outbounds.iter().rev().take(nodes.len()).rev())
        {
            proxy.name = outbound["tag"].as_str().unwrap_or(&proxy.name).to_string();
        }
    }
    let subscription_path = subscription_url.as_deref().map(|url| {
        publish::build_config_path(
            url,
            &template_file_value(&resolved_template),
            user_agent,
            req.skip_unsupported,
        )
    });
    Ok(ConvertResponse {
        success: true,
        subscription_path,
        preview_content: Some(preview_content),
        content_type: Some(JSON_CONTENT_TYPE.to_string()),
        code_class: Some(JSON_CODE_CLASS.to_string()),
        format: Some(TargetFormat::Singbox.as_str().to_string()),
        proxies,
        outbounds_count,
        template_info: Some(template_info_response(&resolved_template)),
        validation: Some(validation),
        skipped_nodes,
        error: None,
    })
}

struct ValidatedNodes {
    config: serde_json::Value,
    validation: validate::ValidationInfo,
    nodes: Vec<types::ProxyNode>,
    skipped_nodes: Vec<parser::SkippedNode>,
}

async fn convert_nodes(
    template_text: &str,
    entries: Vec<parser::ParsedNode>,
    skip_unsupported: bool,
    check: impl AsyncFn(
        &serde_json::Value,
    ) -> Result<validate::ValidationInfo, validate::ValidationError>,
) -> Result<ValidatedNodes, ConversionError> {
    let mut accepted = Vec::new();
    let mut skipped = Vec::new();
    for entry in entries {
        let result = entry.result.and_then(|node| {
            gen_singbox::node_to_singbox_outbound(&node).map_err(|error| {
                format!(
                    "第 {} 个节点「{}」（{}）无法转换：{error}",
                    entry.index,
                    node.name,
                    node.protocol.protocol_str()
                )
            })?;
            Ok(node)
        });
        match result {
            Ok(node) => accepted.push((entry.index, node)),
            Err(reason) if skip_unsupported => skipped.push(parser::SkippedNode {
                index: entry.index,
                name: entry.name,
                reason,
            }),
            Err(reason) => return Err(reason.into()),
        }
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if accepted.is_empty() {
            return Err(ConversionError::from(format!(
                "过滤后没有可转换节点，已过滤 {} 个节点，请查看过滤原因或更换订阅",
                skipped.len()
            ))
            .with_skipped(skipped));
        }
        let nodes = accepted
            .iter()
            .map(|(_, node)| node.clone())
            .collect::<Vec<_>>();
        let config = render::render_template(template_text, &nodes)
            .map_err(|error| ConversionError::from(error).with_skipped(skipped.clone()))?;
        let result = tokio::time::timeout_at(deadline, check(&config)).await;
        let result = match result {
            Ok(result) => result,
            Err(_) => {
                return Err(ConversionError {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    message: "节点过滤校验超过 30 秒，请拆分订阅后重试".to_string(),
                    skipped_nodes: skipped,
                });
            }
        };
        match result {
            Ok(validation) => {
                skipped.sort_by_key(|node| node.index);
                return Ok(ValidatedNodes {
                    config,
                    validation,
                    nodes,
                    skipped_nodes: skipped,
                });
            }
            Err(error) => {
                let template_outbounds = config["outbounds"]
                    .as_array()
                    .expect("rendered outbounds")
                    .len()
                    - nodes.len();
                let node_index = error
                    .outbound_index
                    .and_then(|index| index.checked_sub(template_outbounds))
                    .filter(|index| *index < accepted.len());
                if skip_unsupported
                    && !error.unavailable
                    && let Some(node_index) = node_index
                {
                    let (index, node) = accepted.remove(node_index);
                    skipped.push(parser::SkippedNode {
                        index,
                        name: node.name,
                        reason: error.message,
                    });
                } else {
                    return Err(ConversionError::from(error).with_skipped(skipped));
                }
            }
        }
    }
}

async fn config(
    query: Result<Query<ConfigQuery>, axum::extract::rejection::QueryRejection>,
) -> axum::response::Response {
    config_with(
        query,
        runtime::fetch_subscription_with_user_agent,
        validate::check_config,
    )
    .await
}

async fn config_with(
    query: Result<Query<ConfigQuery>, axum::extract::rejection::QueryRejection>,
    fetch: impl AsyncFn(&str, &str) -> Result<String, String>,
    check: impl AsyncFn(
        &serde_json::Value,
    ) -> Result<validate::ValidationInfo, validate::ValidationError>,
) -> axum::response::Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(error_response(
                    "订阅链接参数无效，必须包含 source".to_string(),
                )),
            )
                .into_response();
        }
    };
    let response = convert_subscription_with(
        ConvertRequest {
            subscription_url: query.source,
            subscription_content: String::new(),
            template: query.template,
            file: None,
            ua: query.ua,
            skip_unsupported: query.skip_unsupported,
        },
        fetch,
        check,
    )
    .await;
    let mut response = match response {
        Ok(result) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(JSON_CONTENT_TYPE),
            );
            (
                StatusCode::OK,
                headers,
                result.preview_content.unwrap_or_default(),
            )
                .into_response()
        }
        Err(error) => (error.status, Json(error.response())).into_response(),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
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
        source: "builtin".to_string(),
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
        validation: None,
        skipped_nodes: Vec::new(),
        error: Some(error),
    }
}

pub fn router() -> Router {
    Router::new()
        .route("/templates", get(list_templates))
        .route("/convert", post(convert_subscription))
        .route("/config", get(config))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn valid_test_config(
        _: &serde_json::Value,
    ) -> Result<validate::ValidationInfo, validate::ValidationError> {
        Ok(validate::ValidationInfo {
            engine: "test",
            version: "test".to_string(),
            checked: true,
        })
    }

    #[tokio::test]
    async fn published_link_returns_the_same_complete_config_and_updates_nodes() {
        let source = "https://example.com/sub?token=a%2Bb%26c&x=1";
        let checks = std::sync::atomic::AtomicUsize::new(0);
        let preview = convert_subscription_with(
            ConvertRequest {
                subscription_url: source.to_string(),
                subscription_content: String::new(),
                template: None,
                file: None,
                ua: Some("clashmeta".to_string()),
                skip_unsupported: true,
            },
            async |url, ua| {
                assert_eq!(url, source);
                assert_eq!(ua, "clashmeta");
                Ok("trojan://secret@example.com:443#First".to_string())
            },
            async |config| {
                validate::validate_references(config).unwrap();
                checks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                valid_test_config(config).await
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{}", error.message));
        let path = preview.subscription_path.as_ref().unwrap();
        let query: ConfigQuery = Query::try_from_uri(&path.parse().unwrap()).unwrap().0;
        assert_eq!(query.source, source);
        assert_eq!(query.template.as_deref(), Some("1"));
        assert!(query.skip_unsupported);
        let response = config_with(
            Ok(Query(query)),
            async |url, ua| {
                assert_eq!(url, source);
                assert_eq!(ua, "clashmeta");
                Ok("trojan://secret@example.com:443#First".to_string())
            },
            async |config| {
                validate::validate_references(config).unwrap();
                checks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                valid_test_config(config).await
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], JSON_CONTENT_TYPE);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let config: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let preview: serde_json::Value =
            serde_json::from_str(preview.preview_content.as_ref().unwrap()).unwrap();
        assert_eq!(config, preview);
        assert!(config.get("success").is_none());
        assert_eq!(config["inbounds"][0]["type"], "tun");
        assert!(config["dns"]["servers"][0].get("detour").is_none());
        assert_eq!(checks.load(std::sync::atomic::Ordering::Relaxed), 2);
        let query = Query::try_from_uri(&path.parse().unwrap()).unwrap();
        let response = config_with(
            Ok(query),
            async |_, _| Ok("trojan://secret@example.com:443#Updated\ntuic://secret@example.com:443#Unsupported".to_string()),
            valid_test_config,
        ).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let updated: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            updated["outbounds"][1]["outbounds"],
            serde_json::json!(["Updated"])
        );
    }

    #[tokio::test]
    async fn published_link_never_returns_a_config_when_validation_fails() {
        let response = config_with(
            Ok(Query(ConfigQuery {
                source: "https://example.com/sub".to_string(),
                template: None,
                ua: None,
                skip_unsupported: true,
            })),
            async |_, _| Ok("trojan://secret@example.com:443#Good".to_string()),
            async |_| {
                Err(validate::ValidationError {
                    unavailable: false,
                    message: "DNS startup configuration rejected".to_string(),
                    outbound_index: None,
                })
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let error: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(error["success"], false);
        assert!(error["preview_content"].is_null());
        assert!(error.get("outbounds").is_none());
        assert!(error["error"].as_str().unwrap().contains("DNS"));
    }

    #[tokio::test]
    async fn filtering_keeps_valid_nodes_and_original_indexes() {
        let content = concat!(
            "# comment\n",
            "trojan://secret@example.com:443#Good\n",
            "tuic://secret@example.com:443#Unsupported\n",
            "vless://bad-uuid@example.com:443#InvalidUUID\n",
            "anytls://secret@example.com:443?type=grpc#BadTransport"
        );
        let template =
            template::builtin_template_content("config_template_groups_rule_set_tun").unwrap();
        let strict = convert_nodes(
            template,
            parser::parse_subscription_entries(content).unwrap(),
            false,
            valid_test_config,
        )
        .await
        .err()
        .unwrap();
        assert!(strict.message.contains("第 3 行"));
        let result = convert_nodes(
            template,
            parser::parse_subscription_entries(content).unwrap(),
            true,
            valid_test_config,
        )
        .await
        .unwrap_or_else(|error| panic!("{}", error.message));
        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.nodes[0].name, "Good");
        assert_eq!(
            result
                .skipped_nodes
                .iter()
                .map(|node| node.index)
                .collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
        assert_eq!(result.skipped_nodes[0].name, "Unsupported");
        assert!(result.skipped_nodes[1].reason.contains("UUID"));
        assert_eq!(
            result.config["outbounds"][1]["outbounds"],
            serde_json::json!(["Good"])
        );
    }

    #[tokio::test]
    async fn filtering_clash_nodes_does_not_abort_at_the_first_unsupported_entry() {
        let source = "proxies:\n  - {name: Good, type: trojan, server: example.com, port: 443, password: secret}\n  - {name: Unknown, type: tuic}\n  - {name: Bad, type: vless, server: example.com, port: 443, uuid: bad}\n  - {name: 日本-优化, type: trojan, server: example.com, port: 443, password: secret, network: ws, ws-path: /ws}";
        let template =
            template::builtin_template_content("config_template_groups_rule_set_tun").unwrap();
        let result = convert_nodes(
            template,
            parser::parse_subscription_entries(source).unwrap(),
            true,
            valid_test_config,
        )
        .await
        .unwrap_or_else(|error| panic!("{}", error.message));
        assert_eq!(
            result
                .nodes
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Good", "日本-优化"]
        );
        assert_eq!(
            result
                .skipped_nodes
                .iter()
                .map(|node| node.index)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(result.nodes[1].transport_path, "/ws");
    }

    #[tokio::test]
    async fn filtering_native_errors_removes_only_the_attributed_node_and_rebuilds_groups() {
        let source = "trojan://secret@example.com:443#Good\nss://bad-cipher:secret@example.com:8388#InvalidCipher";
        let template =
            template::builtin_template_content("config_template_groups_rule_set_tun").unwrap();
        let checks = std::sync::atomic::AtomicUsize::new(0);
        let result = convert_nodes(
            template,
            parser::parse_subscription_entries(source).unwrap(),
            true,
            async |config: &serde_json::Value| {
                checks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let outbounds = config["outbounds"].as_array().unwrap();
                if let Some(index) = outbounds
                    .iter()
                    .position(|outbound| outbound["tag"] == "InvalidCipher")
                {
                    return Err(validate::ValidationError {
                        unavailable: false,
                        message: "invalid method".to_string(),
                        outbound_index: Some(index),
                    });
                }
                validate::validate_references(config).unwrap();
                valid_test_config(config).await
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{}", error.message));
        assert_eq!(checks.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.skipped_nodes[0].index, 2);
        assert_eq!(result.skipped_nodes[0].name, "InvalidCipher");
        assert_eq!(
            result.config["outbounds"][1]["outbounds"],
            serde_json::json!(["Good"])
        );
    }

    #[tokio::test]
    async fn filtering_does_not_swallow_engine_or_template_errors() {
        let source = "trojan://secret@example.com:443#Good\ntuic://secret@example.com:443#Bad";
        let template =
            template::builtin_template_content("config_template_groups_rule_set_tun").unwrap();
        for (unavailable, outbound_index, expected_status) in [
            (true, Some(3), StatusCode::SERVICE_UNAVAILABLE),
            (false, Some(0), StatusCode::UNPROCESSABLE_ENTITY),
            (false, None, StatusCode::UNPROCESSABLE_ENTITY),
        ] {
            let error = convert_nodes(
                template,
                parser::parse_subscription_entries(source).unwrap(),
                true,
                async |_: &serde_json::Value| {
                    Err(validate::ValidationError {
                        unavailable,
                        message: "engine or template failure".to_string(),
                        outbound_index,
                    })
                },
            )
            .await
            .err()
            .unwrap();
            assert_eq!(error.status, expected_status);
            assert_eq!(error.skipped_nodes.len(), 1);
            assert_eq!(error.skipped_nodes[0].name, "Bad");
            assert_eq!(error.message, "engine or template failure");
        }
    }

    #[tokio::test]
    async fn all_filtered_nodes_return_json_diagnostics_without_a_config() {
        let (status, response) = post_convert(serde_json::json!({
            "subscription_content":"tuic://secret@example.com:443#Bad\nanytls://secret@example.com:443?type=grpc#AlsoBad",
            "skip_unsupported":true,
        })).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(response["error"].as_str().unwrap().contains("过滤后没有"));
        assert_eq!(response["skipped_nodes"].as_array().unwrap().len(), 2);
        assert!(response["preview_content"].is_null());
        assert!(!response.to_string().contains("secret"));
        let (status, _) = post_convert(
            serde_json::json!({"subscription_content":"proxies: [", "skip_unsupported":true}),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

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
    async fn test_convert_rejects_ambiguous_and_malformed_requests() {
        for request in [
            serde_json::json!({"subscription_url":"https://example.com/sub", "subscription_content":"trojan://secret@example.com:443"}),
            serde_json::json!({"subscription_content":123}),
            serde_json::json!({"subscription_content":"trojan://secret@example.com:443", "ua":"bad\r\nheader"}),
        ] {
            let (status, response) = post_convert(request).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(response["success"], false);
            assert!(
                response["error"]
                    .as_str()
                    .is_some_and(|error| !error.is_empty())
            );
            assert!(response["preview_content"].is_null());
        }
    }

    #[tokio::test]
    async fn test_convert_preserves_node_error_context_and_never_returns_partial_output() {
        for (content, expected) in [
            (
                "trojan://secret@example.com:443#Good\ntuic://secret@example.com:443#Bad",
                "第 2 行",
            ),
            ("vless://bad-uuid@example.com:443#Bad", "UUID"),
            ("anytls://secret@example.com:443?type=grpc#Bad", "AnyTLS"),
            (
                "proxies:\n  - name: Bad\n    type: trojan\n    server: example.com\n    port: 443",
                "password",
            ),
            ("{\"outbounds\":[]}", "JSON"),
        ] {
            let (status, response) =
                post_convert(serde_json::json!({"subscription_content":content})).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            assert!(
                response["error"].as_str().unwrap().contains(expected),
                "{response}"
            );
            assert!(response["preview_content"].is_null());
            assert!(response["proxies"].as_array().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn test_config_rejects_missing_source_as_json() {
        let (status, body, content_type) = get_route("/config?template=1").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(content_type.unwrap().starts_with("application/json"));
        let error: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(error["error"].as_str().unwrap().contains("source"));
    }

    #[tokio::test]
    async fn test_config_route_returns_json_error_without_fetching_private_source() {
        let (status, body, content_type) =
            get_route("/config?source=http%3A%2F%2F127.0.0.1%2Fsub&template=1").await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(content_type.unwrap().starts_with("application/json"));
        let error: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(error["success"], false);
        assert!(error["error"].as_str().unwrap().contains("Private IP"));
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
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(json["success"], false);
        assert!(
            json["error"].as_str().unwrap().contains("Private IP")
                || json["error"].as_str().unwrap().contains("localhost")
        );
    }
}

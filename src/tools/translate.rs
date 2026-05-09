use axum::{Json, Router, http::StatusCode, routing::post};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::collections::BTreeMap;
use uuid::Uuid;

// ── Request / Response types ───────────────────────────────────────

#[derive(Deserialize)]
pub struct TranslateRequest {
    pub text: String,
    pub from: Option<String>, // "zh" | "en" | "auto"
    pub to: String,           // "zh" | "en" | "auto"
}

#[derive(Serialize)]
pub struct TranslateResponse {
    pub result: String,
    pub from: String,
    pub to: String,
}

struct TranslationDirection {
    source: String,
    target: String,
}

enum TranslationOutcome {
    Passthrough { from: String, to: String },
    Translate(TranslationDirection),
}

#[derive(Deserialize)]
struct AlibabaTranslateResponse {
    #[serde(rename = "Code", deserialize_with = "deserialize_alibaba_code")]
    code: Option<String>,
    #[serde(rename = "Data")]
    data: Option<AlibabaTranslateData>,
}

#[derive(Deserialize)]
struct AlibabaTranslateData {
    #[serde(rename = "Translated")]
    translated: String,
}

struct AlibabaCredentials {
    access_key_id: String,
    access_key_secret: String,
}

const ALIBABA_TRANSLATE_ENDPOINT: &str = "https://mt.cn-hangzhou.aliyuncs.com/";

type HmacSha1 = Hmac<Sha1>;

fn detect_has_chinese(text: &str) -> bool {
    text.chars()
        .any(|c| matches!(c, '\u{4e00}'..='\u{9fff}' | '\u{3400}'..='\u{4dbf}'))
}

fn resolve_translation_direction(from: &str, to: &str, text: &str) -> TranslationDirection {
    let has_chinese = detect_has_chinese(text);

    match (from, to) {
        ("en", "zh") => TranslationDirection {
            source: "en".to_string(),
            target: "zh".to_string(),
        },
        ("zh", "en") => TranslationDirection {
            source: "zh".to_string(),
            target: "en".to_string(),
        },
        (_, "auto") => {
            if has_chinese {
                TranslationDirection {
                    source: "zh".to_string(),
                    target: "en".to_string(),
                }
            } else {
                TranslationDirection {
                    source: "en".to_string(),
                    target: "zh".to_string(),
                }
            }
        }
        ("auto", "zh") => TranslationDirection {
            source: "en".to_string(),
            target: "zh".to_string(),
        },
        ("auto", "en") => TranslationDirection {
            source: "zh".to_string(),
            target: "en".to_string(),
        },
        _ => {
            if has_chinese {
                TranslationDirection {
                    source: "zh".to_string(),
                    target: "en".to_string(),
                }
            } else {
                TranslationDirection {
                    source: "en".to_string(),
                    target: "zh".to_string(),
                }
            }
        }
    }
}

fn resolve_translation_outcome(from: &str, to: &str, text: &str) -> TranslationOutcome {
    match (from, to) {
        ("zh", "zh") => TranslationOutcome::Passthrough {
            from: "zh".to_string(),
            to: "zh".to_string(),
        },
        ("en", "en") => TranslationOutcome::Passthrough {
            from: "en".to_string(),
            to: "en".to_string(),
        },
        _ => TranslationOutcome::Translate(resolve_translation_direction(from, to, text)),
    }
}

fn build_alibaba_query(
    access_key_id: &str,
    source_text: &str,
    source_language: &str,
    target_language: &str,
    timestamp: &str,
    nonce: &str,
) -> BTreeMap<String, String> {
    let mut query = BTreeMap::new();
    query.insert("AccessKeyId".to_string(), access_key_id.to_string());
    query.insert("Action".to_string(), "TranslateGeneral".to_string());
    query.insert("Format".to_string(), "JSON".to_string());
    query.insert("FormatType".to_string(), "text".to_string());
    query.insert("Scene".to_string(), "general".to_string());
    query.insert("SignatureMethod".to_string(), "HMAC-SHA1".to_string());
    query.insert("SignatureNonce".to_string(), nonce.to_string());
    query.insert("SignatureVersion".to_string(), "1.0".to_string());
    query.insert("SourceLanguage".to_string(), source_language.to_string());
    query.insert("SourceText".to_string(), source_text.to_string());
    query.insert("TargetLanguage".to_string(), target_language.to_string());
    query.insert("Timestamp".to_string(), timestamp.to_string());
    query.insert("Version".to_string(), "2018-10-12".to_string());
    query
}

fn load_alibaba_credentials_from_reader<F>(read_env: F) -> Result<AlibabaCredentials, &'static str>
where
    F: Fn(&str) -> Option<String>,
{
    let access_key_id = read_env("ALIBABA_CLOUD_ACCESS_KEY_ID");
    let access_key_secret = read_env("ALIBABA_CLOUD_ACCESS_KEY_SECRET");

    match (access_key_id, access_key_secret) {
        (Some(access_key_id), Some(access_key_secret))
            if !access_key_id.trim().is_empty() && !access_key_secret.trim().is_empty() =>
        {
            Ok(AlibabaCredentials {
                access_key_id,
                access_key_secret,
            })
        }
        _ => Err(
            "Alibaba Cloud credentials are not configured: ALIBABA_CLOUD_ACCESS_KEY_ID / ALIBABA_CLOUD_ACCESS_KEY_SECRET",
        ),
    }
}

fn deserialize_alibaba_code<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct AlibabaCodeVisitor;

    impl<'de> serde::de::Visitor<'de> for AlibabaCodeVisitor {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("an Alibaba response code as string, number, or null")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(self)
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Some(value.to_string()))
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Some(value.to_string()))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Some(value.to_string()))
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Some(value))
        }
    }

    deserializer.deserialize_option(AlibabaCodeVisitor)
}

fn load_alibaba_credentials_from_env() -> Result<AlibabaCredentials, &'static str> {
    load_alibaba_credentials_from_reader(|name| std::env::var(name).ok())
}

fn percent_encode_alibaba(value: &str) -> String {
    urlencoding::encode(value)
        .into_owned()
        .replace('+', "%20")
        .replace('*', "%2A")
        .replace("%7E", "~")
}

fn canonical_query_string(query: &BTreeMap<String, String>) -> String {
    query.iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                percent_encode_alibaba(key),
                percent_encode_alibaba(value)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn build_alibaba_signature(canonical_query: &str, access_key_secret: &str) -> String {
    let string_to_sign = format!(
        "GET&{}&{}",
        percent_encode_alibaba("/"),
        percent_encode_alibaba(canonical_query)
    );
    let signing_key = format!("{}&", access_key_secret);
    let mut mac = HmacSha1::new_from_slice(signing_key.as_bytes())
        .expect("HMAC-SHA1 should accept Alibaba signing key");
    mac.update(string_to_sign.as_bytes());
    let signature = mac.finalize().into_bytes();
    STANDARD.encode(signature)
}

fn build_signed_alibaba_request_url(
    query: &BTreeMap<String, String>,
    credentials: &AlibabaCredentials,
) -> String {
    let canonical_query = canonical_query_string(query);
    let signature = build_alibaba_signature(&canonical_query, &credentials.access_key_secret);
    let signed_query = format!(
        "Signature={}&{}",
        percent_encode_alibaba(&signature),
        canonical_query
    );
    format!("{}?{}", ALIBABA_TRANSLATE_ENDPOINT, signed_query)
}

fn current_alibaba_timestamp() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn current_alibaba_nonce() -> String {
    Uuid::new_v4().to_string()
}

fn extract_translated_text(body: &AlibabaTranslateResponse) -> Result<&str, ()> {
    match (body.code.as_deref(), &body.data) {
        (Some("200"), Some(data)) => Ok(data.translated.as_str()),
        _ => Err(()),
    }
}

// ── Handlers ───────────────────────────────────────────────────────

async fn translate(
    Json(req): Json<TranslateRequest>,
) -> Result<Json<TranslateResponse>, (StatusCode, Json<serde_json::Value>)> {
    let from_lang = req.from.as_deref().unwrap_or("auto");
    let to_lang = req.to.as_str();

    let direction = match resolve_translation_outcome(from_lang, to_lang, &req.text) {
        TranslationOutcome::Passthrough { from, to } => {
            return Ok(Json(TranslateResponse {
                result: req.text,
                from,
                to,
            }));
        }
        TranslationOutcome::Translate(direction) => direction,
    };

    let credentials = load_alibaba_credentials_from_env().map_err(|message| {
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": message})),
        )
    })?;

    let query = build_alibaba_query(
        &credentials.access_key_id,
        &req.text,
        &direction.source,
        &direction.target,
        &current_alibaba_timestamp(),
        &current_alibaba_nonce(),
    );
    let url = build_signed_alibaba_request_url(&query, &credentials);

    let client = reqwest::Client::new();
    let resp = client.get(&url).send().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("翻译请求失败: {}", e)})),
        )
    })?;

    let body: AlibabaTranslateResponse = resp.json().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("解析翻译结果失败: {}", e)})),
        )
    })?;

    let translated = extract_translated_text(&body).map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": "翻译服务返回错误"})),
        )
    })?;

    Ok(Json(TranslateResponse {
        result: translated.to_string(),
        from: direction.source,
        to: direction.target,
    }))
}

// ── Router ─────────────────────────────────────────────────────────

pub fn router() -> Router {
    Router::new().route("/translate", post(translate))
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        &ENV_LOCK
    }

    fn credentials_snapshot() -> (Option<String>, Option<String>) {
        static ENV_SNAPSHOT: OnceLock<(Option<String>, Option<String>)> = OnceLock::new();
        ENV_SNAPSHOT
            .get_or_init(|| {
                (
                    std::env::var("ALIBABA_CLOUD_ACCESS_KEY_ID").ok(),
                    std::env::var("ALIBABA_CLOUD_ACCESS_KEY_SECRET").ok(),
                )
            })
            .clone()
    }

    // ── Language detection logic (unit tests) ─────────────────

    fn detect_has_chinese(text: &str) -> bool {
        text.chars()
            .any(|c| matches!(c, '\u{4e00}'..='\u{9fff}' | '\u{3400}'..='\u{4dbf}'))
    }

    #[test]
    fn test_detect_chinese_text() {
        assert!(detect_has_chinese("你好世界"));
        assert!(detect_has_chinese("Hello 你好"));
        assert!(detect_has_chinese("测试123"));
    }

    #[test]
    fn test_detect_english_text() {
        assert!(!detect_has_chinese("Hello World"));
        assert!(!detect_has_chinese("12345"));
        assert!(!detect_has_chinese("test@example.com"));
    }

    #[test]
    fn test_detect_empty() {
        assert!(!detect_has_chinese(""));
    }

    // ── Translation direction tests ───────────────────────────

    #[test]
    fn test_lang_pair_auto_to_zh() {
        let direction = resolve_translation_direction("auto", "zh", "hello");
        assert_eq!(direction.source, "en");
        assert_eq!(direction.target, "zh");
    }

    #[test]
    fn test_lang_pair_auto_to_en() {
        let direction = resolve_translation_direction("auto", "en", "你好");
        assert_eq!(direction.source, "zh");
        assert_eq!(direction.target, "en");
    }

    #[test]
    fn test_lang_pair_en_to_zh() {
        let direction = resolve_translation_direction("en", "zh", "hello");
        assert_eq!(direction.source, "en");
        assert_eq!(direction.target, "zh");
    }

    #[test]
    fn test_lang_pair_zh_to_en() {
        let direction = resolve_translation_direction("zh", "en", "你好");
        assert_eq!(direction.source, "zh");
        assert_eq!(direction.target, "en");
    }

    #[test]
    fn test_lang_pair_same_language() {
        match resolve_translation_outcome("zh", "zh", "你好") {
            TranslationOutcome::Passthrough { from, to } => {
                assert_eq!(from, "zh");
                assert_eq!(to, "zh");
            }
            TranslationOutcome::Translate(..) => panic!("expected zh passthrough"),
        }

        match resolve_translation_outcome("en", "en", "hello") {
            TranslationOutcome::Passthrough { from, to } => {
                assert_eq!(from, "en");
                assert_eq!(to, "en");
            }
            TranslationOutcome::Translate(..) => panic!("expected en passthrough"),
        }
    }

    #[test]
    fn test_lang_pair_fallback_chinese_input() {
        let direction = resolve_translation_direction("unknown", "unknown", "你好世界");
        assert_eq!(direction.source, "zh");
        assert_eq!(direction.target, "en");
    }

    #[test]
    fn test_lang_pair_fallback_english_input() {
        let direction = resolve_translation_direction("unknown", "unknown", "hello world");
        assert_eq!(direction.source, "en");
        assert_eq!(direction.target, "zh");
    }

    // ── Auto-detect target language tests ──────────────────────

    #[test]
    fn test_lang_pair_auto_target_chinese_input() {
        let auto_direction = resolve_translation_direction("auto", "auto", "你好世界");
        assert_eq!(auto_direction.source, "zh");
        assert_eq!(auto_direction.target, "en");

        let explicit_direction = resolve_translation_direction("zh", "auto", "测试");
        assert_eq!(explicit_direction.source, "zh");
        assert_eq!(explicit_direction.target, "en");
    }

    #[test]
    fn test_lang_pair_auto_target_english_input() {
        let auto_direction = resolve_translation_direction("auto", "auto", "hello world");
        assert_eq!(auto_direction.source, "en");
        assert_eq!(auto_direction.target, "zh");

        let explicit_direction = resolve_translation_direction("en", "auto", "test");
        assert_eq!(explicit_direction.source, "en");
        assert_eq!(explicit_direction.target, "zh");
    }

    // ── Handler: same-language passthrough (no network) ──────

    #[tokio::test]
    async fn test_handler_translate_same_lang_zh() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let app = router();
        let req = Request::builder()
            .method("POST")
            .uri("/translate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "text": "你好",
                    "from": "zh",
                    "to": "zh"
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["result"], "你好");
        assert_eq!(json["from"], "zh");
        assert_eq!(json["to"], "zh");
    }

    #[tokio::test]
    async fn test_handler_translate_missing_alibaba_credentials_returns_backend_error() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let _guard = env_lock().lock().unwrap();
        let (default_access_key_id, default_access_key_secret) = credentials_snapshot();

        unsafe {
            std::env::remove_var("ALIBABA_CLOUD_ACCESS_KEY_ID");
            std::env::remove_var("ALIBABA_CLOUD_ACCESS_KEY_SECRET");
        }

        let app = router();
        let req = Request::builder()
            .method("POST")
            .uri("/translate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "text": "hello",
                    "from": "en",
                    "to": "zh"
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        unsafe {
            if let Some(value) = default_access_key_id {
                std::env::set_var("ALIBABA_CLOUD_ACCESS_KEY_ID", value);
            } else {
                std::env::remove_var("ALIBABA_CLOUD_ACCESS_KEY_ID");
            }

            if let Some(value) = default_access_key_secret {
                std::env::set_var("ALIBABA_CLOUD_ACCESS_KEY_SECRET", value);
            } else {
                std::env::remove_var("ALIBABA_CLOUD_ACCESS_KEY_SECRET");
            }
        }

        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json["error"]
            .as_str()
            .unwrap()
            .contains("Alibaba Cloud credentials are not configured"));
    }

    #[tokio::test]
    async fn test_handler_translate_upstream_failure_returns_non_ok_status() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let _guard = env_lock().lock().unwrap();
        let (default_access_key_id, default_access_key_secret) = credentials_snapshot();
        let previous_https_proxy = std::env::var("HTTPS_PROXY").ok();
        let previous_no_proxy = std::env::var("NO_PROXY").ok();

        unsafe {
            std::env::set_var(
                "ALIBABA_CLOUD_ACCESS_KEY_ID",
                default_access_key_id
                    .clone()
                    .unwrap_or_else(|| "test-access-key".to_string()),
            );
            std::env::set_var(
                "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
                default_access_key_secret
                    .clone()
                    .unwrap_or_else(|| "test-access-secret".to_string()),
            );
            std::env::set_var("HTTPS_PROXY", "http://127.0.0.1:1");
            std::env::remove_var("NO_PROXY");
        }

        let app = router();
        let req = Request::builder()
            .method("POST")
            .uri("/translate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "text": "hello",
                    "from": "en",
                    "to": "zh"
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        unsafe {
            if let Some(value) = default_access_key_id {
                std::env::set_var("ALIBABA_CLOUD_ACCESS_KEY_ID", value);
            } else {
                std::env::remove_var("ALIBABA_CLOUD_ACCESS_KEY_ID");
            }

            if let Some(value) = default_access_key_secret {
                std::env::set_var("ALIBABA_CLOUD_ACCESS_KEY_SECRET", value);
            } else {
                std::env::remove_var("ALIBABA_CLOUD_ACCESS_KEY_SECRET");
            }

            if let Some(value) = previous_https_proxy {
                std::env::set_var("HTTPS_PROXY", value);
            } else {
                std::env::remove_var("HTTPS_PROXY");
            }

            if let Some(value) = previous_no_proxy {
                std::env::set_var("NO_PROXY", value);
            } else {
                std::env::remove_var("NO_PROXY");
            }
        }

        assert_ne!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json["error"].as_str().unwrap().contains("翻译请求失败"));
    }

    // ── Request/Response serialization ────────────────────────

    #[test]
    fn test_translate_request_deserialize() {
        let json = r#"{"text": "hello", "from": "en", "to": "zh"}"#;
        let req: TranslateRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.text, "hello");
        assert_eq!(req.from, Some("en".to_string()));
        assert_eq!(req.to, "zh");
    }

    #[test]
    fn test_translate_request_optional_from() {
        let json = r#"{"text": "hello", "to": "zh"}"#;
        let req: TranslateRequest = serde_json::from_str(json).unwrap();
        assert!(req.from.is_none());
    }

    #[test]
    fn test_translate_response_serialize() {
        let resp = TranslateResponse {
            result: "你好".to_string(),
            from: "en".to_string(),
            to: "zh".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["result"], "你好");
    }

    #[test]
    fn test_resolve_translation_direction_en_to_zh() {
        let direction = resolve_translation_direction("en", "zh", "hello");
        assert_eq!(direction.source, "en");
        assert_eq!(direction.target, "zh");
    }

    #[test]
    fn test_resolve_translation_direction_zh_to_en() {
        let direction = resolve_translation_direction("zh", "en", "你好");
        assert_eq!(direction.source, "zh");
        assert_eq!(direction.target, "en");
    }

    #[test]
    fn test_resolve_translation_direction_auto_target_from_chinese() {
        let direction = resolve_translation_direction("auto", "auto", "你好世界");
        assert_eq!(direction.source, "zh");
        assert_eq!(direction.target, "en");
    }

    #[test]
    fn test_resolve_translation_direction_auto_target_from_english() {
        let direction = resolve_translation_direction("auto", "auto", "hello world");
        assert_eq!(direction.source, "en");
        assert_eq!(direction.target, "zh");
    }

    #[test]
    fn test_resolve_translation_direction_same_language_zh() {
        let outcome = resolve_translation_outcome("zh", "zh", "你好");
        match outcome {
            TranslationOutcome::Passthrough { from, to } => {
                assert_eq!(from, "zh");
                assert_eq!(to, "zh");
            }
            TranslationOutcome::Translate(..) => panic!("expected passthrough"),
        }
    }

    #[test]
    fn test_resolve_translation_direction_same_language_en() {
        let outcome = resolve_translation_outcome("en", "en", "hello");
        match outcome {
            TranslationOutcome::Passthrough { from, to } => {
                assert_eq!(from, "en");
                assert_eq!(to, "en");
            }
            TranslationOutcome::Translate(..) => panic!("expected passthrough"),
        }
    }

    #[test]
    fn test_build_alibaba_query_contains_required_fields() {
        let query = build_alibaba_query(
            "test-access-key",
            "hello world",
            "en",
            "zh",
            "2026-05-07T10:00:00Z",
            "nonce-123",
        );

        assert_eq!(query.get("Action").map(String::as_str), Some("TranslateGeneral"));
        assert_eq!(query.get("Version").map(String::as_str), Some("2018-10-12"));
        assert_eq!(query.get("Format").map(String::as_str), Some("JSON"));
        assert_eq!(query.get("FormatType").map(String::as_str), Some("text"));
        assert_eq!(query.get("Scene").map(String::as_str), Some("general"));
        assert_eq!(query.get("SourceLanguage").map(String::as_str), Some("en"));
        assert_eq!(query.get("TargetLanguage").map(String::as_str), Some("zh"));
        assert_eq!(query.get("SourceText").map(String::as_str), Some("hello world"));
        assert_eq!(query.get("AccessKeyId").map(String::as_str), Some("test-access-key"));
        assert_eq!(query.get("SignatureMethod").map(String::as_str), Some("HMAC-SHA1"));
        assert_eq!(query.get("SignatureVersion").map(String::as_str), Some("1.0"));
        assert_eq!(query.get("SignatureNonce").map(String::as_str), Some("nonce-123"));
        assert_eq!(query.get("Timestamp").map(String::as_str), Some("2026-05-07T10:00:00Z"));
    }

    #[test]
    fn test_parse_alibaba_success_response() {
        let json = r#"{
            "Code": 200,
            "Data": {
                "Translated": "你好世界",
                "WordCount": "2"
            },
            "RequestId": "req-123"
        }"#;

        let body: AlibabaTranslateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(body.code.as_deref(), Some("200"));
        assert_eq!(extract_translated_text(&body).unwrap(), "你好世界");
    }

    #[test]
    fn test_parse_alibaba_success_response_with_string_code() {
        let json = r#"{
            "Code": "200",
            "Data": {
                "Translated": "你好世界"
            }
        }"#;

        let body: AlibabaTranslateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(body.code.as_deref(), Some("200"));
        assert_eq!(extract_translated_text(&body).unwrap(), "你好世界");
    }

    #[test]
    fn test_parse_alibaba_non_success_response() {
        let json = r#"{
            "Code": 503,
            "Message": "backend busy",
            "RequestId": "req-123"
        }"#;

        let body: AlibabaTranslateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(body.code.as_deref(), Some("503"));
        assert!(extract_translated_text(&body).is_err());
    }

    #[test]
    fn test_parse_alibaba_non_success_response_with_string_code() {
        let json = r#"{
            "Code": "ServiceUnavailable",
            "Message": "backend busy",
            "RequestId": "req-123"
        }"#;

        let body: AlibabaTranslateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(body.code.as_deref(), Some("ServiceUnavailable"));
        assert!(extract_translated_text(&body).is_err());
    }

    #[test]
    fn test_load_alibaba_credentials_from_env_requires_both_values() {
        let result = load_alibaba_credentials_from_reader(|name| match name {
            "ALIBABA_CLOUD_ACCESS_KEY_ID" => None,
            "ALIBABA_CLOUD_ACCESS_KEY_SECRET" => None,
            _ => panic!("unexpected credential name"),
        });

        match result {
            Err(message) => assert_eq!(
                message,
                "Alibaba Cloud credentials are not configured: ALIBABA_CLOUD_ACCESS_KEY_ID / ALIBABA_CLOUD_ACCESS_KEY_SECRET"
            ),
            Ok(_) => panic!("expected missing Alibaba Cloud credentials error"),
        }
    }

    #[test]
    fn test_load_alibaba_credentials_from_env_rejects_whitespace_only_values() {
        let result = load_alibaba_credentials_from_reader(|name| match name {
            "ALIBABA_CLOUD_ACCESS_KEY_ID" => Some("   ".to_string()),
            "ALIBABA_CLOUD_ACCESS_KEY_SECRET" => Some("\t\n".to_string()),
            _ => panic!("unexpected credential name"),
        });

        match result {
            Err(message) => assert_eq!(
                message,
                "Alibaba Cloud credentials are not configured: ALIBABA_CLOUD_ACCESS_KEY_ID / ALIBABA_CLOUD_ACCESS_KEY_SECRET"
            ),
            Ok(_) => panic!("expected whitespace-only Alibaba Cloud credentials to be rejected"),
        }
    }

    #[test]
    fn test_build_signed_alibaba_request_url_is_deterministic() {
        let credentials = AlibabaCredentials {
            access_key_id: "test-access-key".to_string(),
            access_key_secret: "test-access-secret".to_string(),
        };
        let query = build_alibaba_query(
            &credentials.access_key_id,
            "hello world/+~",
            "en",
            "zh",
            "2026-05-08T12:34:56Z",
            "nonce-123",
        );

        let canonical = canonical_query_string(&query);
        assert_eq!(
            canonical,
            "AccessKeyId=test-access-key&Action=TranslateGeneral&Format=JSON&FormatType=text&Scene=general&SignatureMethod=HMAC-SHA1&SignatureNonce=nonce-123&SignatureVersion=1.0&SourceLanguage=en&SourceText=hello%20world%2F%2B~&TargetLanguage=zh&Timestamp=2026-05-08T12%3A34%3A56Z&Version=2018-10-12"
        );

        let signature = build_alibaba_signature(&canonical, &credentials.access_key_secret);
        assert_eq!(signature, "miSaTYgm8ntsAj+Re+P+aPnsEq8=");

        let url = build_signed_alibaba_request_url(&query, &credentials);
        assert_eq!(
            url,
            "https://mt.cn-hangzhou.aliyuncs.com/?Signature=miSaTYgm8ntsAj%2BRe%2BP%2BaPnsEq8%3D&AccessKeyId=test-access-key&Action=TranslateGeneral&Format=JSON&FormatType=text&Scene=general&SignatureMethod=HMAC-SHA1&SignatureNonce=nonce-123&SignatureVersion=1.0&SourceLanguage=en&SourceText=hello%20world%2F%2B~&TargetLanguage=zh&Timestamp=2026-05-08T12%3A34%3A56Z&Version=2018-10-12"
        );
    }
}

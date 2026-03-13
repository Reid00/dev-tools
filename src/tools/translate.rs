use axum::{Json, Router, routing::post};
use serde::{Deserialize, Serialize};

// ── Request / Response types ───────────────────────────────────────

#[derive(Deserialize)]
pub struct TranslateRequest {
    pub text: String,
    pub from: Option<String>, // "zh" | "en" | "auto"
    pub to: String,           // "zh" | "en"
}

#[derive(Serialize)]
pub struct TranslateResponse {
    pub result: String,
    pub from: String,
    pub to: String,
}

#[derive(Deserialize)]
struct MyMemoryResponse {
    #[serde(rename = "responseData")]
    response_data: MyMemoryData,
    #[serde(rename = "responseStatus")]
    response_status: u32,
}

#[derive(Deserialize)]
struct MyMemoryData {
    #[serde(rename = "translatedText")]
    translated_text: String,
}

// ── Handlers ───────────────────────────────────────────────────────

async fn translate(
    Json(req): Json<TranslateRequest>,
) -> Result<Json<TranslateResponse>, Json<serde_json::Value>> {
    let from_lang = req.from.as_deref().unwrap_or("auto");

    // Map short codes to MyMemory language pairs
    let lang_pair = match (from_lang, req.to.as_str()) {
        ("auto", "zh") | ("en", "zh") => "en|zh-CN",
        ("auto", "en") | ("zh", "en") => "zh-CN|en",
        ("zh", "zh") => {
            return Ok(Json(TranslateResponse {
                result: req.text.clone(),
                from: "zh".to_string(),
                to: "zh".to_string(),
            }));
        }
        ("en", "en") => {
            return Ok(Json(TranslateResponse {
                result: req.text.clone(),
                from: "en".to_string(),
                to: "en".to_string(),
            }));
        }
        _ => {
            // Auto-detect: if contains Chinese chars, translate to English; otherwise to Chinese
            let has_chinese = req.text.chars().any(|c| {
                matches!(c, '\u{4e00}'..='\u{9fff}' | '\u{3400}'..='\u{4dbf}')
            });
            if has_chinese {
                "zh-CN|en"
            } else {
                "en|zh-CN"
            }
        }
    };

    let client = reqwest::Client::new();
    let url = format!(
        "https://api.mymemory.translated.net/get?q={}&langpair={}",
        urlencoding::encode(&req.text),
        lang_pair
    );

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| Json(serde_json::json!({"error": format!("翻译请求失败: {}", e)})))?;

    let body: MyMemoryResponse = resp
        .json()
        .await
        .map_err(|e| Json(serde_json::json!({"error": format!("解析翻译结果失败: {}", e)})))?;

    if body.response_status != 200 {
        return Err(Json(serde_json::json!({"error": "翻译服务返回错误"})));
    }

    let (from, to) = if lang_pair.starts_with("zh") {
        ("zh".to_string(), "en".to_string())
    } else {
        ("en".to_string(), "zh".to_string())
    };

    Ok(Json(TranslateResponse {
        result: body.response_data.translated_text,
        from,
        to,
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

    // ── Language pair mapping (unit tests) ────────────────────

    fn resolve_lang_pair(from: &str, to: &str, text: &str) -> &'static str {
        match (from, to) {
            ("auto", "zh") | ("en", "zh") => "en|zh-CN",
            ("auto", "en") | ("zh", "en") => "zh-CN|en",
            ("zh", "zh") | ("en", "en") => "same",
            _ => {
                if detect_has_chinese(text) {
                    "zh-CN|en"
                } else {
                    "en|zh-CN"
                }
            }
        }
    }

    #[test]
    fn test_lang_pair_auto_to_zh() {
        assert_eq!(resolve_lang_pair("auto", "zh", "hello"), "en|zh-CN");
    }

    #[test]
    fn test_lang_pair_auto_to_en() {
        assert_eq!(resolve_lang_pair("auto", "en", "你好"), "zh-CN|en");
    }

    #[test]
    fn test_lang_pair_en_to_zh() {
        assert_eq!(resolve_lang_pair("en", "zh", "hello"), "en|zh-CN");
    }

    #[test]
    fn test_lang_pair_zh_to_en() {
        assert_eq!(resolve_lang_pair("zh", "en", "你好"), "zh-CN|en");
    }

    #[test]
    fn test_lang_pair_same_language() {
        assert_eq!(resolve_lang_pair("zh", "zh", "你好"), "same");
        assert_eq!(resolve_lang_pair("en", "en", "hello"), "same");
    }

    #[test]
    fn test_lang_pair_fallback_chinese_input() {
        assert_eq!(resolve_lang_pair("unknown", "unknown", "你好世界"), "zh-CN|en");
    }

    #[test]
    fn test_lang_pair_fallback_english_input() {
        assert_eq!(
            resolve_lang_pair("unknown", "unknown", "hello world"),
            "en|zh-CN"
        );
    }

    // ── MyMemoryResponse deserialization ──────────────────────

    #[test]
    fn test_mymemory_response_deserialize() {
        let json = r#"{
            "responseData": {
                "translatedText": "你好世界"
            },
            "responseStatus": 200
        }"#;
        let resp: MyMemoryResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.response_status, 200);
        assert_eq!(resp.response_data.translated_text, "你好世界");
    }

    #[test]
    fn test_mymemory_response_error_status() {
        let json = r#"{
            "responseData": {
                "translatedText": ""
            },
            "responseStatus": 403
        }"#;
        let resp: MyMemoryResponse = serde_json::from_str(json).unwrap();
        assert_ne!(resp.response_status, 200);
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
    async fn test_handler_translate_same_lang_en() {
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
                    "text": "hello world",
                    "from": "en",
                    "to": "en"
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["result"], "hello world");
        assert_eq!(json["from"], "en");
        assert_eq!(json["to"], "en");
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
}

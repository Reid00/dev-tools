use axum::{Json, Router, routing::post};
use serde::{Deserialize, Serialize};

// ── Request / Response types ───────────────────────────────────────

#[derive(Deserialize)]
pub struct Base64Request {
    pub input: String,
}

#[derive(Serialize)]
pub struct Base64Response {
    pub result: String,
    pub success: bool,
    pub error: Option<String>,
}

// ── Handlers ───────────────────────────────────────────────────────

async fn base64_encode(Json(req): Json<Base64Request>) -> Json<Base64Response> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let encoded = STANDARD.encode(req.input.as_bytes());
    Json(Base64Response {
        result: encoded,
        success: true,
        error: None,
    })
}

async fn base64_decode(Json(req): Json<Base64Request>) -> Json<Base64Response> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    match STANDARD.decode(&req.input) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => Json(Base64Response {
                result: s,
                success: true,
                error: None,
            }),
            Err(e) => Json(Base64Response {
                result: String::new(),
                success: false,
                error: Some(format!("UTF-8 解码失败: {}", e)),
            }),
        },
        Err(e) => Json(Base64Response {
            result: String::new(),
            success: false,
            error: Some(format!("Base64 解码失败: {}", e)),
        }),
    }
}

// ── Router ─────────────────────────────────────────────────────────

pub fn router() -> Router {
    Router::new()
        .route("/base64/encode", post(base64_encode))
        .route("/base64/decode", post(base64_decode))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn post_json(uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let app = router();
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, json)
    }

    #[tokio::test]
    async fn test_base64_encode() {
        let (status, json) = post_json("/base64/encode", serde_json::json!({"input": "hello"})).await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(json["result"], "aGVsbG8=");
    }

    #[tokio::test]
    async fn test_base64_decode() {
        let (status, json) = post_json("/base64/decode", serde_json::json!({"input": "aGVsbG8="})).await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(json["result"], "hello");
    }

    #[tokio::test]
    async fn test_base64_decode_invalid() {
        let (_, json) = post_json("/base64/decode", serde_json::json!({"input": "invalid!!"})).await;
        assert!(!json["success"].as_bool().unwrap());
        assert!(json["error"].is_string());
    }
}
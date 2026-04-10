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

#[derive(Deserialize)]
pub struct UrlRequest {
    pub input: String,
    pub encode_all: Option<bool>, // true: 编码所有字符, false: 仅编码特殊字符
}

#[derive(Serialize)]
pub struct UrlResponse {
    pub result: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct HtmlRequest {
    pub input: String,
}

#[derive(Serialize)]
pub struct HtmlResponse {
    pub result: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct JwtRequest {
    pub token: String,
}

#[derive(Serialize, Default)]
pub struct JwtResponse {
    pub header: String,
    pub payload: String,
    pub signature: String,
    pub header_json: Option<serde_json::Value>,
    pub payload_json: Option<serde_json::Value>,
    pub valid: bool,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct UnicodeRequest {
    pub input: String,
}

#[derive(Serialize)]
pub struct UnicodeResponse {
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

// ── URL Encode/Decode ───────────────────────────────────────────────

async fn url_encode(Json(req): Json<UrlRequest>) -> Json<UrlResponse> {
    let encoded = if req.encode_all.unwrap_or(false) {
        // 编码所有非字母数字字符
        req.input.chars().map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        }).collect::<String>()
    } else {
        // 仅编码 URL 特殊字符
        urlencoding::encode(&req.input).into_owned()
    };
    Json(UrlResponse {
        result: encoded,
        success: true,
        error: None,
    })
}

async fn url_decode(Json(req): Json<UrlRequest>) -> Json<UrlResponse> {
    match urlencoding::decode(&req.input) {
        Ok(decoded) => Json(UrlResponse {
            result: decoded.into_owned(),
            success: true,
            error: None,
        }),
        Err(e) => Json(UrlResponse {
            result: String::new(),
            success: false,
            error: Some(format!("URL 解码失败: {}", e)),
        }),
    }
}

// ── HTML Entity Encode/Decode ───────────────────────────────────────

fn encode_html_entities(s: &str) -> String {
    s.chars().map(|c| match c {
        '<' => "&lt;".to_string(),
        '>' => "&gt;".to_string(),
        '&' => "&amp;".to_string(),
        '"' => "&quot;".to_string(),
        '\'' => "&apos;".to_string(),
        c if c.is_control() || !c.is_ascii() => format!("&#{};", c as u32),
        c => c.to_string(),
    }).collect()
}

fn decode_html_entities(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '&' {
            let mut end = i + 1;
            while end < chars.len() && chars[end] != ';' && chars[end] != '&' {
                end += 1;
            }
            if end < chars.len() && chars[end] == ';' {
                let entity: String = chars[i+1..end].iter().collect();
                let decoded: Option<u32> = match entity.as_str() {
                    "lt" => Some('<' as u32),
                    "gt" => Some('>' as u32),
                    "amp" => Some('&' as u32),
                    "quot" => Some('"' as u32),
                    "apos" => Some('\'' as u32),
                    "nbsp" => Some(' ' as u32),
                    s if s.starts_with('#') && s.len() > 1 => {
                        let num_str = &s[1..];
                        if num_str.starts_with('x') || num_str.starts_with('X') {
                            u32::from_str_radix(&num_str[1..], 16).ok()
                        } else {
                            num_str.parse::<u32>().ok()
                        }
                    },
                    _ => None,
                };
                if let Some(code) = decoded {
                    if let Some(c) = char::from_u32(code) {
                        result.push(c);
                        i = end + 1;
                        continue;
                    }
                }
            }
        }
        result.push(chars[i]);
        i += 1;
    }
    result
}

async fn html_encode(Json(req): Json<HtmlRequest>) -> Json<HtmlResponse> {
    Json(HtmlResponse {
        result: encode_html_entities(&req.input),
        success: true,
        error: None,
    })
}

async fn html_decode(Json(req): Json<HtmlRequest>) -> Json<HtmlResponse> {
    Json(HtmlResponse {
        result: decode_html_entities(&req.input),
        success: true,
        error: None,
    })
}

// ── JWT Decode ─────────────────────────────────────────────────────

async fn jwt_decode(Json(req): Json<JwtRequest>) -> Json<JwtResponse> {
    let parts: Vec<&str> = req.token.split('.').collect();
    if parts.len() != 3 {
        return Json(JwtResponse {
            valid: false,
            error: Some("JWT 格式无效，应为三段式 (header.payload.signature)".to_string()),
            ..Default::default()
        });
    }

    use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};

    let header = match STANDARD_NO_PAD.decode(parts[0]) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return Json(JwtResponse { valid: false, error: Some("Header UTF-8 解码失败".to_string()), ..Default::default() }),
        },
        Err(_) => {
            match base64::engine::general_purpose::STANDARD.decode(parts[0]) {
                Ok(bytes) => String::from_utf8(bytes).unwrap_or_default(),
                Err(_) => return Json(JwtResponse { valid: false, error: Some("Header Base64 解码失败".to_string()), ..Default::default() }),
            }
        }
    };

    let payload = match STANDARD_NO_PAD.decode(parts[1]) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return Json(JwtResponse { valid: false, error: Some("Payload UTF-8 解码失败".to_string()), ..Default::default() }),
        },
        Err(_) => {
            match base64::engine::general_purpose::STANDARD.decode(parts[1]) {
                Ok(bytes) => String::from_utf8(bytes).unwrap_or_default(),
                Err(_) => return Json(JwtResponse { valid: false, error: Some("Payload Base64 解码失败".to_string()), ..Default::default() }),
            }
        }
    };

    let header_json: Option<serde_json::Value> = serde_json::from_str(&header).ok();
    let payload_json: Option<serde_json::Value> = serde_json::from_str(&payload).ok();

    Json(JwtResponse {
        header,
        payload,
        signature: parts[2].to_string(),
        header_json,
        payload_json,
        valid: true,
        error: None,
    })
}

// ── Unicode Encode/Decode ───────────────────────────────────────────

async fn unicode_encode(Json(req): Json<UnicodeRequest>) -> Json<UnicodeResponse> {
    let result = req.input.chars().map(|c| {
        if c.is_ascii() {
            c.to_string()
        } else {
            format!("\\u{:04x}", c as u32)
        }
    }).collect::<String>();
    Json(UnicodeResponse {
        result,
        success: true,
        error: None,
    })
}

async fn unicode_decode(Json(req): Json<UnicodeRequest>) -> Json<UnicodeResponse> {
    let mut result = String::with_capacity(req.input.len());
    let chars: Vec<char> = req.input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() && chars[i + 1] == 'u' {
            if i + 5 < chars.len() {
                let hex: String = chars[i+2..i+6].iter().collect();
                if let Ok(code) = u32::from_str_radix(&hex, 16) {
                    if let Some(c) = char::from_u32(code) {
                        result.push(c);
                        i += 6;
                        continue;
                    }
                }
            }
        }
        result.push(chars[i]);
        i += 1;
    }
    Json(UnicodeResponse {
        result,
        success: true,
        error: None,
    })
}

// ── Router ─────────────────────────────────────────────────────────

pub fn router() -> Router {
    Router::new()
        .route("/base64/encode", post(base64_encode))
        .route("/base64/decode", post(base64_decode))
        .route("/url/encode", post(url_encode))
        .route("/url/decode", post(url_decode))
        .route("/html/encode", post(html_encode))
        .route("/html/decode", post(html_decode))
        .route("/jwt/decode", post(jwt_decode))
        .route("/unicode/encode", post(unicode_encode))
        .route("/unicode/decode", post(unicode_decode))
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

    #[tokio::test]
    async fn test_url_encode() {
        let (status, json) = post_json("/url/encode", serde_json::json!({"input": "hello world"})).await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(json["result"], "hello%20world");
    }

    #[tokio::test]
    async fn test_url_decode() {
        let (status, json) = post_json("/url/decode", serde_json::json!({"input": "hello%20world"})).await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(json["result"], "hello world");
    }

    #[tokio::test]
    async fn test_html_encode() {
        let (_, json) = post_json("/html/encode", serde_json::json!({"input": "<div>test</div>"})).await;
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(json["result"], "&lt;div&gt;test&lt;/div&gt;");
    }

    #[tokio::test]
    async fn test_html_decode() {
        let (_, json) = post_json("/html/decode", serde_json::json!({"input": "&lt;div&gt;"})).await;
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(json["result"], "<div>");
    }

    #[tokio::test]
    async fn test_jwt_decode() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let (_, json) = post_json("/jwt/decode", serde_json::json!({"token": token})).await;
        assert!(json["valid"].as_bool().unwrap());
        assert_eq!(json["header_json"]["alg"], "HS256");
    }

    #[tokio::test]
    async fn test_unicode_encode() {
        let (_, json) = post_json("/unicode/encode", serde_json::json!({"input": "你好"})).await;
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(json["result"], "\\u4f60\\u597d");
    }

    #[tokio::test]
    async fn test_unicode_decode() {
        let (_, json) = post_json("/unicode/decode", serde_json::json!({"input": "\\u4f60\\u597d"})).await;
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(json["result"], "你好");
    }
}
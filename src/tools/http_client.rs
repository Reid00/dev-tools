use axum::{Json, Router, routing::post};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::time::Instant;

// ── Data Structures ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HttpMethod {
    #[default]
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    PATCH,
}

impl HttpMethod {
    fn to_reqwest(self) -> reqwest::Method {
        match self {
            HttpMethod::GET => reqwest::Method::GET,
            HttpMethod::POST => reqwest::Method::POST,
            HttpMethod::PUT => reqwest::Method::PUT,
            HttpMethod::DELETE => reqwest::Method::DELETE,
            HttpMethod::HEAD => reqwest::Method::HEAD,
            HttpMethod::OPTIONS => reqwest::Method::OPTIONS,
            HttpMethod::PATCH => reqwest::Method::PATCH,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BodyType {
    #[default]
    None,
    Json,
    Form,
    Text,
    Raw,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    #[default]
    None,
    Basic,
    Bearer,
    ApiKey,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyValue {
    pub key: String,
    pub value: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

impl Default for KeyValue {
    fn default() -> Self {
        KeyValue {
            key: String::new(),
            value: String::new(),
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AuthConfig {
    #[serde(default)]
    pub auth_type: AuthType,
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
    pub api_key_name: Option<String>,
    pub api_key_value: Option<String>,
    #[serde(default)]
    pub api_key_in: ApiKeyLocation,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyLocation {
    #[default]
    Header,
    Query,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct HttpRequest {
    pub url: String,
    #[serde(default)]
    pub method: HttpMethod,
    #[serde(default)]
    pub headers: Vec<KeyValue>,
    #[serde(default)]
    pub query_params: Vec<KeyValue>,
    #[serde(default)]
    pub path_params: Vec<KeyValue>,
    #[serde(default)]
    pub body_type: BodyType,
    pub body: Option<String>,
    #[serde(default)]
    pub form_data: Vec<KeyValue>,
    pub auth: Option<AuthConfig>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub retry_count: u32,
    #[serde(default = "default_retry_delay")]
    pub retry_delay_ms: u64,
}

fn default_timeout() -> u64 {
    30000
}

fn default_retry_delay() -> u64 {
    1000
}

#[derive(Debug, Serialize)]
pub struct HttpResponse {
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub body_size: usize,
    pub duration_ms: u64,
    pub is_json: bool,
    pub error: Option<String>,
}

// ── Request/Response for API ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SendRequest {
    #[serde(flatten)]
    pub request: HttpRequest,
}

// ── Helper Functions ────────────────────────────────────────────────────

/// Replace path parameters in URL (e.g., {{id}} -> value)
fn replace_path_params(url: &str, params: &[KeyValue]) -> String {
    let mut result = url.to_string();
    for param in params {
        if param.enabled && !param.key.is_empty() {
            let placeholder = format!("{{{{{}}}}}", param.key);
            result = result.replace(&placeholder, &param.value);
        }
    }
    result
}

/// Build query string from key-value pairs
fn build_query_string(params: &[KeyValue]) -> String {
    let enabled: Vec<_> = params
        .iter()
        .filter(|p| p.enabled && !p.key.is_empty())
        .collect();

    if enabled.is_empty() {
        return String::new();
    }

    let pairs: Vec<String> = enabled
        .iter()
        .map(|p| {
            let key = urlencoding::encode(&p.key);
            let value = urlencoding::encode(&p.value);
            format!("{}={}", key, value)
        })
        .collect();

    format!("?{}", pairs.join("&"))
}

/// Build headers from key-value pairs and auth config
fn build_headers(
    headers: &[KeyValue],
    auth: &Option<AuthConfig>,
    content_type: Option<&str>,
) -> Result<HeaderMap, String> {
    let mut map = HeaderMap::new();

    // Add content-type if specified
    if let Some(ct) = content_type {
        if let Ok(name) = HeaderName::try_from("content-type") {
            if let Ok(value) = HeaderValue::try_from(ct) {
                map.insert(name, value);
            }
        }
    }

    // Add custom headers
    for h in headers {
        if h.enabled && !h.key.is_empty() {
            let name = match HeaderName::try_from(&h.key) {
                Ok(n) => n,
                Err(_) => continue, // Skip invalid header names
            };
            let value = match HeaderValue::try_from(&h.value) {
                Ok(v) => v,
                Err(_) => continue,
            };
            map.insert(name, value);
        }
    }

    // Add auth headers
    if let Some(auth) = auth {
        match auth.auth_type {
            AuthType::Basic => {
                if let (Some(user), Some(pass)) = (&auth.username, &auth.password) {
                    let credentials = base64_encode(&format!("{}:{}", user, pass));
                    if let Ok(name) = HeaderName::try_from("authorization") {
                        if let Ok(value) = HeaderValue::try_from(format!("Basic {}", credentials)) {
                            map.insert(name, value);
                        }
                    }
                }
            }
            AuthType::Bearer => {
                if let Some(token) = &auth.token {
                    if let Ok(name) = HeaderName::try_from("authorization") {
                        if let Ok(value) = HeaderValue::try_from(format!("Bearer {}", token)) {
                            map.insert(name, value);
                        }
                    }
                }
            }
            AuthType::ApiKey => {
                if let (Some(name), Some(value)) = (&auth.api_key_name, &auth.api_key_value) {
                    if auth.api_key_in == ApiKeyLocation::Header {
                        if let Ok(header_name) = HeaderName::try_from(name.as_str()) {
                            if let Ok(header_value) = HeaderValue::try_from(value.as_str()) {
                                map.insert(header_name, header_value);
                            }
                        }
                    }
                }
            }
            AuthType::None => {}
        }
    }

    Ok(map)
}

/// Base64 encode without external crate
fn base64_encode(input: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::new();

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// Build request body based on body type
fn build_body(body_type: &BodyType, body: &Option<String>, form_data: &[KeyValue]) -> Option<String> {
    match body_type {
        BodyType::None => None,
        BodyType::Json | BodyType::Text | BodyType::Raw => body.clone(),
        BodyType::Form => {
            if form_data.is_empty() {
                return None;
            }
            let pairs: Vec<String> = form_data
                .iter()
                .filter(|p| p.enabled && !p.key.is_empty())
                .map(|p| {
                    let key = urlencoding::encode(&p.key);
                    let value = urlencoding::encode(&p.value);
                    format!("{}={}", key, value)
                })
                .collect();
            Some(pairs.join("&"))
        }
    }
}

/// Validate URL format
fn validate_url(url: &str) -> Result<(), String> {
    if url.is_empty() {
        return Err("URL 不能为空".to_string());
    }

    let parsed = Url::parse(url).map_err(|_| "无效的 URL 格式".to_string())?;

    match parsed.scheme() {
        "http" | "https" => Ok(()),
        _ => Err("URL 必须以 http:// 或 https:// 开头".to_string()),
    }
}

/// Check if response body is valid JSON
fn is_json_body(body: &str) -> bool {
    if body.trim().is_empty() {
        return false;
    }
    serde_json::from_str::<serde_json::Value>(body).is_ok()
}

/// Format JSON body for display
fn format_json_if_possible(body: &str) -> String {
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(body) {
        serde_json::to_string_pretty(&val).unwrap_or_else(|_| body.to_string())
    } else {
        body.to_string()
    }
}

// ── Handler ─────────────────────────────────────────────────────────────

async fn send_request(Json(req): Json<SendRequest>) -> Json<HttpResponse> {
    let http_req = req.request;
    let start = Instant::now();

    // Build URL with path params and query string
    let url = replace_path_params(&http_req.url, &http_req.path_params);

    // Validate URL
    if let Err(e) = validate_url(&url) {
        return Json(HttpResponse {
            status: 0,
            status_text: String::new(),
            headers: vec![],
            body: String::new(),
            body_size: 0,
            duration_ms: start.elapsed().as_millis() as u64,
            is_json: false,
            error: Some(e),
        });
    }

    // Build final URL with query params and API key in query
    let final_url = {
        let mut parsed = match Url::parse(&url) {
            Ok(u) => u,
            Err(e) => {
                return Json(HttpResponse {
                    status: 0,
                    status_text: String::new(),
                    headers: vec![],
                    body: String::new(),
                    body_size: 0,
                    duration_ms: start.elapsed().as_millis() as u64,
                    is_json: false,
                    error: Some(format!("URL 解析失败: {}", e)),
                });
            }
        };

        // Add query params
        let query_string = build_query_string(&http_req.query_params);
        if !query_string.is_empty() {
            let existing = parsed.query().unwrap_or("");
            let new_query = if existing.is_empty() {
                query_string.trim_start_matches('?').to_string()
            } else {
                format!("{}&{}", existing, query_string.trim_start_matches('?'))
            };
            parsed.set_query(Some(&new_query));
        }

        // Add API key in query if configured
        if let Some(auth) = &http_req.auth {
            if auth.auth_type == AuthType::ApiKey && auth.api_key_in == ApiKeyLocation::Query {
                if let (Some(name), Some(value)) = (&auth.api_key_name, &auth.api_key_value) {
                    let existing_query = parsed.query().unwrap_or("");
                    let mut pairs: Vec<String> = existing_query
                        .split('&')
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .collect();
                    pairs.push(format!("{}={}", urlencoding::encode(name), urlencoding::encode(value)));
                    parsed.set_query(Some(&pairs.join("&")));
                }
            }
        }

        parsed.to_string()
    };

    // Determine content type
    let content_type = match http_req.body_type {
        BodyType::None => None,
        BodyType::Json => Some("application/json"),
        BodyType::Form => Some("application/x-www-form-urlencoded"),
        BodyType::Text => Some("text/plain"),
        BodyType::Raw => None,
    };

    // Build headers
    let headers = match build_headers(&http_req.headers, &http_req.auth, content_type) {
        Ok(h) => h,
        Err(e) => {
            return Json(HttpResponse {
                status: 0,
                status_text: String::new(),
                headers: vec![],
                body: String::new(),
                body_size: 0,
                duration_ms: start.elapsed().as_millis() as u64,
                is_json: false,
                error: Some(e),
            });
        }
    };

    // Build body
    let body = build_body(&http_req.body_type, &http_req.body, &http_req.form_data);

    // Create HTTP client
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(http_req.timeout_ms))
        .danger_accept_invalid_certs(false)
        .build();

    let client = match client {
        Ok(c) => c,
        Err(e) => {
            return Json(HttpResponse {
                status: 0,
                status_text: String::new(),
                headers: vec![],
                body: String::new(),
                body_size: 0,
                duration_ms: start.elapsed().as_millis() as u64,
                is_json: false,
                error: Some(format!("创建 HTTP 客户端失败: {}", e)),
            });
        }
    };

    // Send request with retry
    let mut last_error = None;
    let max_attempts = http_req.retry_count + 1;

    for attempt in 0..max_attempts {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(http_req.retry_delay_ms)).await;
        }

        // Build request
        let mut request_builder = client.request(http_req.method.to_reqwest(), &final_url).headers(headers.clone());

        if let Some(ref b) = body {
            request_builder = request_builder.body(b.clone());
        }

        // Send request
        match request_builder.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let status_text = response.status().canonical_reason().unwrap_or("").to_string();

                // Extract response headers
                let resp_headers: Vec<(String, String)> = response
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();

                // Get response body
                let resp_body = match response.text().await {
                    Ok(t) => t,
                    Err(e) => {
                        return Json(HttpResponse {
                            status,
                            status_text,
                            headers: resp_headers,
                            body: String::new(),
                            body_size: 0,
                            duration_ms: start.elapsed().as_millis() as u64,
                            is_json: false,
                            error: Some(format!("读取响应体失败: {}", e)),
                        });
                    }
                };

                let body_size = resp_body.len();
                let is_json = is_json_body(&resp_body);
                let formatted_body = if is_json {
                    format_json_if_possible(&resp_body)
                } else {
                    resp_body
                };

                return Json(HttpResponse {
                    status,
                    status_text,
                    headers: resp_headers,
                    body: formatted_body,
                    body_size,
                    duration_ms: start.elapsed().as_millis() as u64,
                    is_json,
                    error: None,
                });
            }
            Err(e) => {
                let error_msg = if e.is_timeout() {
                    "连接超时".to_string()
                } else if e.is_connect() {
                    "无法连接到服务器".to_string()
                } else if e.is_redirect() {
                    format!("重定向错误: {}", e)
                } else if e.to_string().contains("dns") || e.to_string().contains("resolve") {
                    "无法解析域名".to_string()
                } else if e.to_string().contains("certificate") {
                    "SSL 证书验证失败".to_string()
                } else {
                    format!("请求失败: {}", e)
                };
                last_error = Some(error_msg);
            }
        }
    }

    // All retries failed
    Json(HttpResponse {
        status: 0,
        status_text: String::new(),
        headers: vec![],
        body: String::new(),
        body_size: 0,
        duration_ms: start.elapsed().as_millis() as u64,
        is_json: false,
        error: last_error,
    })
}

// ── Router ─────────────────────────────────────────────────────────────

pub fn router() -> Router {
    Router::new().route("/send", post(send_request))
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── URL Processing Tests ───────────────────────────────────────

    #[test]
    fn test_replace_path_params_simple() {
        let url = "https://api.example.com/users/{{id}}";
        let params = vec![KeyValue {
            key: "id".to_string(),
            value: "123".to_string(),
            enabled: true,
        }];
        assert_eq!(replace_path_params(url, &params), "https://api.example.com/users/123");
    }

    #[test]
    fn test_replace_path_params_multiple() {
        let url = "https://api.example.com/{{resource}}/{{id}}";
        let params = vec![
            KeyValue {
                key: "resource".to_string(),
                value: "users".to_string(),
                enabled: true,
            },
            KeyValue {
                key: "id".to_string(),
                value: "456".to_string(),
                enabled: true,
            },
        ];
        assert_eq!(replace_path_params(url, &params), "https://api.example.com/users/456");
    }

    #[test]
    fn test_replace_path_params_disabled() {
        let url = "https://api.example.com/users/{{id}}";
        let params = vec![KeyValue {
            key: "id".to_string(),
            value: "123".to_string(),
            enabled: false,
        }];
        assert_eq!(replace_path_params(url, &params), "https://api.example.com/users/{{id}}");
    }

    #[test]
    fn test_build_query_string_empty() {
        let params: Vec<KeyValue> = vec![];
        assert_eq!(build_query_string(&params), "");
    }

    #[test]
    fn test_build_query_string_single() {
        let params = vec![KeyValue {
            key: "foo".to_string(),
            value: "bar".to_string(),
            enabled: true,
        }];
        assert_eq!(build_query_string(&params), "?foo=bar");
    }

    #[test]
    fn test_build_query_string_multiple() {
        let params = vec![
            KeyValue {
                key: "a".to_string(),
                value: "1".to_string(),
                enabled: true,
            },
            KeyValue {
                key: "b".to_string(),
                value: "2".to_string(),
                enabled: true,
            },
        ];
        assert_eq!(build_query_string(&params), "?a=1&b=2");
    }

    #[test]
    fn test_build_query_string_encoding() {
        let params = vec![KeyValue {
            key: "search".to_string(),
            value: "hello world".to_string(),
            enabled: true,
        }];
        assert_eq!(build_query_string(&params), "?search=hello%20world");
    }

    #[test]
    fn test_build_query_string_disabled() {
        let params = vec![
            KeyValue {
                key: "a".to_string(),
                value: "1".to_string(),
                enabled: true,
            },
            KeyValue {
                key: "b".to_string(),
                value: "2".to_string(),
                enabled: false,
            },
        ];
        assert_eq!(build_query_string(&params), "?a=1");
    }

    // ── Header Tests ───────────────────────────────────────────────

    #[test]
    fn test_build_headers_basic() {
        let headers = vec![KeyValue {
            key: "X-Custom".to_string(),
            value: "test".to_string(),
            enabled: true,
        }];
        let map = build_headers(&headers, &None, None).unwrap();
        assert_eq!(map.get("x-custom").unwrap(), "test");
    }

    #[test]
    fn test_build_headers_with_content_type() {
        let headers = vec![];
        let map = build_headers(&headers, &None, Some("application/json")).unwrap();
        assert_eq!(map.get("content-type").unwrap(), "application/json");
    }

    #[test]
    fn test_build_headers_bearer_auth() {
        let auth = AuthConfig {
            auth_type: AuthType::Bearer,
            token: Some("my-token".to_string()),
            ..Default::default()
        };
        let map = build_headers(&[], &Some(auth), None).unwrap();
        let auth_header = map.get("authorization").unwrap();
        assert_eq!(auth_header, "Bearer my-token");
    }

    #[test]
    fn test_build_headers_basic_auth() {
        let auth = AuthConfig {
            auth_type: AuthType::Basic,
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            ..Default::default()
        };
        let map = build_headers(&[], &Some(auth), None).unwrap();
        let auth_header = map.get("authorization").unwrap();
        // "user:pass" base64 encoded is "dXNlcjpwYXNz"
        assert!(auth_header.to_str().unwrap().starts_with("Basic "));
    }

    #[test]
    fn test_build_headers_api_key_header() {
        let auth = AuthConfig {
            auth_type: AuthType::ApiKey,
            api_key_name: Some("X-API-Key".to_string()),
            api_key_value: Some("secret123".to_string()),
            api_key_in: ApiKeyLocation::Header,
            ..Default::default()
        };
        let map = build_headers(&[], &Some(auth), None).unwrap();
        assert_eq!(map.get("x-api-key").unwrap(), "secret123");
    }

    // ── Body Tests ─────────────────────────────────────────────────

    #[test]
    fn test_build_body_none() {
        assert!(build_body(&BodyType::None, &None, &[]).is_none());
    }

    #[test]
    fn test_build_body_json() {
        let body = Some(r#"{"key":"value"}"#.to_string());
        let result = build_body(&BodyType::Json, &body, &[]);
        assert_eq!(result, Some(r#"{"key":"value"}"#.to_string()));
    }

    #[test]
    fn test_build_body_form() {
        let form_data = vec![
            KeyValue {
                key: "username".to_string(),
                value: "john".to_string(),
                enabled: true,
            },
            KeyValue {
                key: "password".to_string(),
                value: "secret".to_string(),
                enabled: true,
            },
        ];
        let result = build_body(&BodyType::Form, &None, &form_data);
        assert_eq!(result, Some("username=john&password=secret".to_string()));
    }

    // ── Validation Tests ───────────────────────────────────────────

    #[test]
    fn test_validate_url_valid() {
        assert!(validate_url("https://example.com").is_ok());
        assert!(validate_url("http://localhost:3000/api").is_ok());
    }

    #[test]
    fn test_validate_url_empty() {
        assert!(validate_url("").is_err());
    }

    #[test]
    fn test_validate_url_invalid_scheme() {
        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("example.com").is_err());
    }

    // ── JSON Detection Tests ───────────────────────────────────────

    #[test]
    fn test_is_json_body_valid() {
        assert!(is_json_body(r#"{"key":"value"}"#));
        assert!(is_json_body(r#"[1,2,3]"#));
    }

    #[test]
    fn test_is_json_body_invalid() {
        assert!(!is_json_body("plain text"));
        assert!(!is_json_body(""));
        assert!(!is_json_body("{invalid}"));
    }

    // ── Base64 Tests ───────────────────────────────────────────────

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode("user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64_encode("hello"), "aGVsbG8=");
        assert_eq!(base64_encode("a"), "YQ==");
    }

    // ── JSON Formatting Tests ───────────────────────────────────────

    #[test]
    fn test_format_json_if_possible() {
        let input = r#"{"a":1,"b":2}"#;
        let result = format_json_if_possible(input);
        assert!(result.contains('\n'));
        assert!(result.contains("\"a\""));
    }

    #[test]
    fn test_format_json_if_possible_invalid() {
        let input = "not json";
        let result = format_json_if_possible(input);
        assert_eq!(result, "not json");
    }

    // ── Handler Integration Tests ───────────────────────────────────

    #[tokio::test]
    async fn test_handler_send_invalid_url() {
        let req = SendRequest {
            request: HttpRequest {
                url: "invalid-url".to_string(),
                method: HttpMethod::GET,
                ..Default::default()
            },
        };

        let json = send_request(Json(req)).await;
        assert!(json.error.is_some());
        assert!(json.error.as_ref().unwrap().contains("无效的 URL"));
    }

    #[tokio::test]
    async fn test_handler_send_empty_url() {
        let req = SendRequest {
            request: HttpRequest {
                url: "".to_string(),
                method: HttpMethod::GET,
                ..Default::default()
            },
        };

        let json = send_request(Json(req)).await;
        assert!(json.error.is_some());
        assert!(json.error.as_ref().unwrap().contains("URL 不能为空"));
    }
}
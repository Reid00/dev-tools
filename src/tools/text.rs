use axum::{Json, Router, routing::post};
use serde::{Deserialize, Serialize};

// ============================================================================
// Regex Tester
// ============================================================================

#[derive(Deserialize)]
pub struct RegexTestRequest {
    pub pattern: String,
    pub text: String,
    pub global: Option<bool>,
    pub case_insensitive: Option<bool>,
    pub multiline: Option<bool>,
}

#[derive(Serialize)]
pub struct RegexMatch {
    pub matched: String,
    pub start: usize,
    pub end: usize,
    pub groups: Vec<String>,
}

#[derive(Serialize)]
pub struct RegexTestResponse {
    pub matches: Vec<RegexMatch>,
    pub success: bool,
    pub error: Option<String>,
}

async fn regex_test(Json(req): Json<RegexTestRequest>) -> Json<RegexTestResponse> {
    let mut flags = String::new();
    if req.case_insensitive.unwrap_or(false) {
        flags.push('i');
    }
    if req.multiline.unwrap_or(false) {
        flags.push('m');
    }

    let pattern = if flags.is_empty() {
        req.pattern.clone()
    } else {
        format!("(?{}){}", flags, req.pattern)
    };

    match regex::Regex::new(&pattern) {
        Ok(re) => {
            let matches: Vec<RegexMatch> = if req.global.unwrap_or(false) {
                re.find_iter(&req.text)
                    .map(|m| {
                        let groups: Vec<String> = re
                            .captures(&req.text)
                            .map(|cap| {
                                cap.iter()
                                    .skip(1)
                                    .filter_map(|g| g.map(|g| g.as_str().to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();
                        RegexMatch {
                            matched: m.as_str().to_string(),
                            start: m.start(),
                            end: m.end(),
                            groups,
                        }
                    })
                    .collect()
            } else {
                re.find(&req.text)
                    .map(|m| {
                        let groups: Vec<String> = re
                            .captures(&req.text)
                            .map(|cap| {
                                cap.iter()
                                    .skip(1)
                                    .filter_map(|g| g.map(|g| g.as_str().to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();
                        RegexMatch {
                            matched: m.as_str().to_string(),
                            start: m.start(),
                            end: m.end(),
                            groups,
                        }
                    })
                    .map(|m| vec![m])
                    .unwrap_or_default()
            };
            Json(RegexTestResponse {
                matches,
                success: true,
                error: None,
            })
        }
        Err(e) => Json(RegexTestResponse {
            matches: Vec::new(),
            success: false,
            error: Some(format!("正则表达式错误: {}", e)),
        }),
    }
}

// ============================================================================
// Text Diff
// ============================================================================

#[derive(Deserialize)]
pub struct DiffRequest {
    pub text1: String,
    pub text2: String,
}

#[derive(Serialize)]
pub struct DiffLine {
    #[serde(rename = "type")]
    pub line_type: String, // "equal", "added", "removed"
    pub content: String,
    pub line_num1: Option<usize>,
    pub line_num2: Option<usize>,
}

#[derive(Serialize)]
pub struct DiffResponse {
    pub diff: Vec<DiffLine>,
    pub added: usize,
    pub removed: usize,
    pub success: bool,
}

fn compute_diff(text1: &str, text2: &str) -> Vec<DiffLine> {
    let lines1: Vec<&str> = text1.lines().collect();
    let lines2: Vec<&str> = text2.lines().collect();

    let mut result: Vec<DiffLine> = Vec::new();
    let mut i = 0;
    let mut j = 0;

    while i < lines1.len() || j < lines2.len() {
        if i >= lines1.len() {
            result.push(DiffLine {
                line_type: "added".to_string(),
                content: lines2[j].to_string(),
                line_num1: None,
                line_num2: Some(j + 1),
            });
            j += 1;
        } else if j >= lines2.len() {
            result.push(DiffLine {
                line_type: "removed".to_string(),
                content: lines1[i].to_string(),
                line_num1: Some(i + 1),
                line_num2: None,
            });
            i += 1;
        } else if lines1[i] == lines2[j] {
            result.push(DiffLine {
                line_type: "equal".to_string(),
                content: lines1[i].to_string(),
                line_num1: Some(i + 1),
                line_num2: Some(j + 1),
            });
            i += 1;
            j += 1;
        } else {
            result.push(DiffLine {
                line_type: "removed".to_string(),
                content: lines1[i].to_string(),
                line_num1: Some(i + 1),
                line_num2: None,
            });
            result.push(DiffLine {
                line_type: "added".to_string(),
                content: lines2[j].to_string(),
                line_num1: None,
                line_num2: Some(j + 1),
            });
            i += 1;
            j += 1;
        }
    }
    result
}

async fn text_diff(Json(req): Json<DiffRequest>) -> Json<DiffResponse> {
    let diff = compute_diff(&req.text1, &req.text2);
    let added = diff.iter().filter(|d| d.line_type == "added").count();
    let removed = diff.iter().filter(|d| d.line_type == "removed").count();
    Json(DiffResponse {
        diff,
        added,
        removed,
        success: true,
    })
}

// ============================================================================
// Case Conversion
// ============================================================================

#[derive(Deserialize)]
pub struct CaseConvertRequest {
    pub input: String,
}

#[derive(Serialize)]
pub struct CaseConvertResponse {
    pub camel_case: String,
    pub snake_case: String,
    pub kebab_case: String,
    pub pascal_case: String,
    pub upper_snake_case: String,
    pub success: bool,
}

fn to_camel_case(s: &str) -> String {
    let words: Vec<String> = s
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| w.to_lowercase())
        .collect();
    if words.is_empty() {
        return String::new();
    }
    let mut result = words[0].clone();
    for w in words.iter().skip(1) {
        if !w.is_empty() {
            let mut chars = w.chars();
            result.push(chars.next().unwrap().to_uppercase().next().unwrap());
            result.push_str(chars.as_str());
        }
    }
    result
}

fn to_snake_case(s: &str) -> String {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join("_")
}

fn to_kebab_case(s: &str) -> String {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join("-")
}

fn to_pascal_case(s: &str) -> String {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut word = w.to_lowercase();
            if !word.is_empty() {
                word[0..1].make_ascii_uppercase();
            }
            word
        })
        .collect::<Vec<_>>()
        .join("")
}

async fn case_convert(Json(req): Json<CaseConvertRequest>) -> Json<CaseConvertResponse> {
    Json(CaseConvertResponse {
        camel_case: to_camel_case(&req.input),
        snake_case: to_snake_case(&req.input),
        kebab_case: to_kebab_case(&req.input),
        pascal_case: to_pascal_case(&req.input),
        upper_snake_case: to_snake_case(&req.input).to_uppercase(),
        success: true,
    })
}

// ============================================================================
// Text Statistics
// ============================================================================

#[derive(Deserialize)]
pub struct StatsRequest {
    pub input: String,
}

#[derive(Serialize)]
pub struct StatsResponse {
    pub chars: usize,
    pub chars_no_space: usize,
    pub words: usize,
    pub lines: usize,
    pub bytes: usize,
    pub success: bool,
}

async fn text_stats(Json(req): Json<StatsRequest>) -> Json<StatsResponse> {
    let input = &req.input;
    Json(StatsResponse {
        chars: input.chars().count(),
        chars_no_space: input.chars().filter(|c| !c.is_whitespace()).count(),
        words: input.split_whitespace().count(),
        lines: if input.is_empty() {
            0
        } else {
            input.lines().count()
        },
        bytes: input.len(),
        success: true,
    })
}

// ============================================================================
// UUID Generator
// ============================================================================

#[derive(Deserialize)]
pub struct UuidRequest {
    pub count: Option<usize>,
    pub version: Option<String>,
    pub hyphens: Option<bool>,
}

#[derive(Serialize)]
pub struct UuidResponse {
    pub uuids: Vec<String>,
    pub success: bool,
}

async fn uuid_generate(Json(req): Json<UuidRequest>) -> Json<UuidResponse> {
    use uuid::Uuid;

    let count = req.count.unwrap_or(1).min(100);
    let hyphens = req.hyphens.unwrap_or(true);
    let version = req.version.unwrap_or_else(|| "v4".to_string());

    let uuids: Vec<String> = (0..count)
        .map(|_| {
            let uuid = if version == "v7" {
                Uuid::now_v7()
            } else {
                Uuid::new_v4()
            };
            if hyphens {
                uuid.to_string()
            } else {
                uuid.simple().to_string()
            }
        })
        .collect();

    Json(UuidResponse {
        uuids,
        success: true,
    })
}

// ============================================================================
// Password Generator
// ============================================================================

#[derive(Deserialize)]
pub struct PasswordRequest {
    pub length: Option<usize>,
    pub uppercase: Option<bool>,
    pub lowercase: Option<bool>,
    pub numbers: Option<bool>,
    pub symbols: Option<bool>,
    pub count: Option<usize>,
}

#[derive(Serialize)]
pub struct PasswordResponse {
    pub passwords: Vec<String>,
    pub success: bool,
}

async fn password_generate(Json(req): Json<PasswordRequest>) -> Json<PasswordResponse> {
    use rand::Rng;

    let length = req.length.unwrap_or(16).max(4).min(64);
    let uppercase = req.uppercase.unwrap_or(true);
    let lowercase = req.lowercase.unwrap_or(true);
    let numbers = req.numbers.unwrap_or(true);
    let symbols = req.symbols.unwrap_or(false);
    let count = req.count.unwrap_or(1).min(20);

    let mut charset = String::new();
    if uppercase {
        charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if lowercase {
        charset.push_str("abcdefghijklmnopqrstuvwxyz");
    }
    if numbers {
        charset.push_str("0123456789");
    }
    if symbols {
        charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?");
    }

    if charset.is_empty() {
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".to_string();
    }

    let charset_bytes = charset.as_bytes();
    let mut rng = rand::thread_rng();

    let passwords: Vec<String> = (0..count)
        .map(|_| {
            (0..length)
                .map(|_| {
                    let idx = rng.gen_range(0..charset_bytes.len());
                    charset_bytes[idx] as char
                })
                .collect()
        })
        .collect();

    Json(PasswordResponse {
        passwords,
        success: true,
    })
}

// ============================================================================
// Router
// ============================================================================

pub fn router() -> Router {
    Router::new()
        .route("/regex/test", post(regex_test))
        .route("/diff", post(text_diff))
        .route("/case/convert", post(case_convert))
        .route("/stats", post(text_stats))
        .route("/uuid/generate", post(uuid_generate))
        .route("/password/generate", post(password_generate))
}

// ============================================================================
// Tests
// ============================================================================

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
    async fn test_regex_basic() {
        let (_, json) = post_json(
            "/regex/test",
            serde_json::json!({
                "pattern": "\\d+",
                "text": "hello 123 world"
            }),
        )
        .await;
        assert!(json["success"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_diff() {
        let (_, json) = post_json(
            "/diff",
            serde_json::json!({
                "text1": "hello",
                "text2": "world"
            }),
        )
        .await;
        assert!(json["success"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_case_convert() {
        let (_, json) = post_json(
            "/case/convert",
            serde_json::json!({
                "input": "hello world"
            }),
        )
        .await;
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(json["camel_case"], "helloWorld");
        assert_eq!(json["snake_case"], "hello_world");
    }

    #[tokio::test]
    async fn test_stats() {
        let (_, json) = post_json(
            "/stats",
            serde_json::json!({
                "input": "hello world"
            }),
        )
        .await;
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(json["words"], 2);
    }

    #[tokio::test]
    async fn test_uuid() {
        let (_, json) = post_json("/uuid/generate", serde_json::json!({})).await;
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(json["uuids"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_password() {
        let (_, json) = post_json("/password/generate", serde_json::json!({})).await;
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(json["passwords"].as_array().unwrap().len(), 1);
    }
}

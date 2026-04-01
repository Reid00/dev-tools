use axum::{Json, Router, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Request / Response types ───────────────────────────────────────

#[derive(Deserialize)]
pub struct FormatRequest {
    pub input: String,
    pub indent: Option<u32>,     // indent spaces, 0 = compact
    pub sort_keys: Option<bool>, // sort keys alphabetically
    pub max_depth: Option<usize>, // recursion depth limit for nested JSON strings, default 5
}

#[derive(Serialize)]
pub struct FormatResponse {
    pub result: String,
    pub valid: bool,
    pub error: Option<String>,
    pub stats: Option<JsonStats>,
}

#[derive(Serialize)]
pub struct JsonStats {
    pub keys: usize,
    pub depth: usize,
    pub size_bytes: usize,
}

#[derive(Deserialize)]
pub struct ValidateRequest {
    pub input: String,
}

#[derive(Serialize)]
pub struct ValidateResponse {
    pub valid: bool,
    pub error: Option<String>,
    pub error_position: Option<usize>,
}

#[derive(Deserialize)]
pub struct PyDictRequest {
    pub input: String,
}

#[derive(Serialize)]
pub struct PyDictResponse {
    pub result: String,
    pub valid: bool,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct CompareRequest {
    pub json1: String,
    pub json2: String,
}

#[derive(Serialize)]
pub struct CompareResponse {
    pub equal: bool,
    pub differences: Vec<String>,
}

#[derive(Deserialize)]
pub struct MinifyRequest {
    pub input: String,
}

#[derive(Serialize)]
pub struct MinifyResponse {
    pub result: String,
    pub original_size: usize,
    pub minified_size: usize,
}

// ── Helper functions ───────────────────────────────────────────────

fn count_depth(val: &Value) -> usize {
    match val {
        Value::Object(map) => {
            1 + map.values().map(count_depth).max().unwrap_or(0)
        }
        Value::Array(arr) => {
            1 + arr.iter().map(count_depth).max().unwrap_or(0)
        }
        _ => 0,
    }
}

fn count_keys(val: &Value) -> usize {
    match val {
        Value::Object(map) => {
            map.len() + map.values().map(count_keys).sum::<usize>()
        }
        Value::Array(arr) => arr.iter().map(count_keys).sum(),
        _ => 0,
    }
}

fn sort_value(val: &Value) -> Value {
    match val {
        Value::Object(map) => {
            let mut sorted: serde_json::Map<String, Value> = serde_json::Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for k in keys {
                sorted.insert(k.clone(), sort_value(&map[k]));
            }
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sort_value).collect()),
        other => other.clone(),
    }
}

/// Recursively format JSON strings nested within JSON values.
/// When a string field contains valid JSON, parse and replace it with the actual JSON structure.
fn deep_format_value(val: &Value, depth: usize, max_depth: usize) -> Value {
    if depth >= max_depth {
        return val.clone();
    }

    match val {
        Value::Object(map) => {
            let mut result = serde_json::Map::new();
            for (k, v) in map {
                result.insert(k.clone(), deep_format_value(v, depth, max_depth));
            }
            Value::Object(result)
        }
        Value::Array(arr) => {
            Value::Array(arr.iter().map(|v| deep_format_value(v, depth, max_depth)).collect())
        }
        Value::String(s) => {
            // Try to parse as JSON
            if let Ok(nested) = serde_json::from_str::<Value>(s) {
                // Successfully parsed - recursively format
                deep_format_value(&nested, depth + 1, max_depth)
            } else {
                // Not valid JSON - keep original
                val.clone()
            }
        }
        other => other.clone(),
    }
}

/// Convert Python-style dict string to valid JSON
fn python_dict_to_json(input: &str) -> Result<String, String> {
    let mut result = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut in_string = false;
    let mut string_char: char = '"';

    while i < len {
        let c = chars[i];

        if in_string {
            if c == '\\' && i + 1 < len {
                // Handle escape sequences - only allow valid JSON escapes
                let next = chars[i + 1];
                match next {
                    // Valid JSON escape sequences
                    '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't' => {
                        result.push('\\');
                        result.push(next);
                        i += 2;
                        continue;
                    }
                    // Unicode escape \uXXXX
                    'u' => {
                        result.push('\\');
                        result.push('u');
                        i += 2;
                        // Copy the next 4 hex digits if present
                        for _ in 0..4 {
                            if i < len {
                                let h = chars[i];
                                if h.is_ascii_hexdigit() {
                                    result.push(h);
                                    i += 1;
                                } else {
                                    break;
                                }
                            }
                        }
                        continue;
                    }
                    // Invalid escape - just output the backslash escaped
                    _ => {
                        result.push_str("\\\\");
                        result.push(next);
                        i += 2;
                        continue;
                    }
                }
            }
            if c == string_char {
                in_string = false;
                result.push('"');
                i += 1;
                continue;
            }
            // Escape double quotes inside single-quoted strings
            if string_char == '\'' && c == '"' {
                result.push('\\');
                result.push('"');
                i += 1;
                continue;
            }
            // Escape literal newlines and control characters in strings (from print output)
            match c {
                '\n' => result.push_str("\\n"),
                '\r' => result.push_str("\\r"),
                '\t' => result.push_str("\\t"),
                c if c.is_control() => {
                    result.push_str(&format!("\\u{:04x}", c as u32));
                }
                _ => result.push(c),
            }
            i += 1;
            continue;
        }

        match c {
            '\'' => {
                in_string = true;
                string_char = '\'';
                result.push('"');
            }
            '"' => {
                in_string = true;
                string_char = '"';
                result.push('"');
            }
            _ => {
                // Replace Python keywords (using char-based matching for Unicode safety)
                if i + 4 <= len
                    && chars[i] == 'T' && chars[i+1] == 'r' && chars[i+2] == 'u' && chars[i+3] == 'e'
                    && !chars.get(i + 4).is_some_and(|c| c.is_alphanumeric())
                {
                    result.push_str("true");
                    i += 4;
                    continue;
                }
                if i + 5 <= len
                    && chars[i] == 'F' && chars[i+1] == 'a' && chars[i+2] == 'l' && chars[i+3] == 's' && chars[i+4] == 'e'
                    && !chars.get(i + 5).is_some_and(|c| c.is_alphanumeric())
                {
                    result.push_str("false");
                    i += 5;
                    continue;
                }
                if i + 4 <= len
                    && chars[i] == 'N' && chars[i+1] == 'o' && chars[i+2] == 'n' && chars[i+3] == 'e'
                    && !chars.get(i + 4).is_some_and(|c| c.is_alphanumeric())
                {
                    result.push_str("null");
                    i += 4;
                    continue;
                }
                // Handle tuple () -> array []
                if c == '(' {
                    result.push('[');
                } else if c == ')' {
                    result.push(']');
                } else {
                    result.push(c);
                }
            }
        }
        i += 1;
    }

    // Remove trailing commas before } or ]
    let re_result = remove_trailing_commas(&result);

    // Validate the result is valid JSON
    match serde_json::from_str::<Value>(&re_result) {
        Ok(_) => Ok(re_result),
        Err(e) => Err(format!("转换后的 JSON 无效: {}", e)),
    }
}

fn remove_trailing_commas(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut in_str = false;
    let mut str_char = '"';

    while i < len {
        let c = chars[i];

        if in_str {
            if c == '\\' && i + 1 < len {
                result.push(c);
                result.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == str_char {
                in_str = false;
            }
            result.push(c);
            i += 1;
            continue;
        }

        if c == '"' || c == '\'' {
            in_str = true;
            str_char = c;
            result.push(c);
            i += 1;
            continue;
        }

        if c == ',' {
            // Look ahead for closing bracket/brace (skip whitespace)
            let mut j = i + 1;
            while j < len && chars[j].is_whitespace() {
                j += 1;
            }
            if j < len && (chars[j] == '}' || chars[j] == ']') {
                // Skip this trailing comma
                i += 1;
                continue;
            }
        }

        result.push(c);
        i += 1;
    }
    result
}

fn compare_values(v1: &Value, v2: &Value, path: &str, diffs: &mut Vec<String>) {
    match (v1, v2) {
        (Value::Object(m1), Value::Object(m2)) => {
            for key in m1.keys() {
                let p = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", path, key)
                };
                match m2.get(key) {
                    Some(v) => compare_values(&m1[key], v, &p, diffs),
                    None => diffs.push(format!("删除: {}", p)),
                }
            }
            for key in m2.keys() {
                if !m1.contains_key(key) {
                    let p = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };
                    diffs.push(format!("新增: {}", p));
                }
            }
        }
        (Value::Array(a1), Value::Array(a2)) => {
            let max_len = a1.len().max(a2.len());
            for idx in 0..max_len {
                let p = format!("{}[{}]", path, idx);
                match (a1.get(idx), a2.get(idx)) {
                    (Some(v1), Some(v2)) => compare_values(v1, v2, &p, diffs),
                    (Some(_), None) => diffs.push(format!("删除: {}", p)),
                    (None, Some(_)) => diffs.push(format!("新增: {}", p)),
                    (None, None) => {}
                }
            }
        }
        _ => {
            if v1 != v2 {
                diffs.push(format!("修改: {} : {} → {}", path, v1, v2));
            }
        }
    }
}

// ── Handlers ───────────────────────────────────────────────────────

/// Remove # comments from JSON input (lines starting with #)
fn remove_json_comments(input: &str) -> String {
    input
        .lines()
        .filter(|line| !line.trim().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

async fn format_json(Json(req): Json<FormatRequest>) -> Json<FormatResponse> {
    let input = remove_json_comments(req.input.trim());
    match serde_json::from_str::<Value>(&input) {
        Ok(val) => {
            // Apply deep formatting if max_depth is set and > 0
            let val = if let Some(max_depth) = req.max_depth {
                if max_depth > 0 {
                    deep_format_value(&val, 0, max_depth)
                } else {
                    val
                }
            } else {
                // Default: no deep parsing (preserve current behavior)
                val
            };

            // Apply key sorting if requested
            let val = if req.sort_keys.unwrap_or(false) {
                sort_value(&val)
            } else {
                val
            };

            let indent = req.indent.unwrap_or(2);
            let result = if indent == 0 {
                serde_json::to_string(&val).unwrap_or_default()
            } else {
                // Use custom indentation
                let buf = Vec::new();
                let indent_bytes = " ".repeat(indent as usize).into_bytes();
                let formatter = serde_json::ser::PrettyFormatter::with_indent(&indent_bytes);
                let mut ser = serde_json::Serializer::with_formatter(buf, formatter);
                serde::Serialize::serialize(&val, &mut ser).unwrap();
                String::from_utf8(ser.into_inner()).unwrap_or_default()
            };

            let stats = JsonStats {
                keys: count_keys(&val),
                depth: count_depth(&val),
                size_bytes: result.len(),
            };

            Json(FormatResponse {
                result,
                valid: true,
                error: None,
                stats: Some(stats),
            })
        }
        Err(e) => Json(FormatResponse {
            result: input.to_string(),
            valid: false,
            error: Some(format!("JSON 语法错误: {}", e)),
            stats: None,
        }),
    }
}

async fn validate_json(Json(req): Json<ValidateRequest>) -> Json<ValidateResponse> {
    let input = remove_json_comments(&req.input);
    match serde_json::from_str::<Value>(&input) {
        Ok(_) => Json(ValidateResponse {
            valid: true,
            error: None,
            error_position: None,
        }),
        Err(e) => Json(ValidateResponse {
            valid: false,
            error: Some(format!("{}", e)),
            error_position: Some(e.column()),
        }),
    }
}

async fn py_dict_to_json(Json(req): Json<PyDictRequest>) -> Json<PyDictResponse> {
    match python_dict_to_json(&req.input) {
        Ok(json_str) => {
            // Re-format nicely
            match serde_json::from_str::<Value>(&json_str) {
                Ok(val) => Json(PyDictResponse {
                    result: serde_json::to_string_pretty(&val).unwrap_or(json_str),
                    valid: true,
                    error: None,
                }),
                Err(_) => Json(PyDictResponse {
                    result: json_str,
                    valid: true,
                    error: None,
                }),
            }
        }
        Err(e) => Json(PyDictResponse {
            result: String::new(),
            valid: false,
            error: Some(e),
        }),
    }
}

async fn compare_json(Json(req): Json<CompareRequest>) -> Json<CompareResponse> {
    let v1 = match serde_json::from_str::<Value>(&req.json1) {
        Ok(v) => v,
        Err(_) => {
            return Json(CompareResponse {
                equal: false,
                differences: vec!["JSON 1 格式无效".to_string()],
            });
        }
    };
    let v2 = match serde_json::from_str::<Value>(&req.json2) {
        Ok(v) => v,
        Err(_) => {
            return Json(CompareResponse {
                equal: false,
                differences: vec!["JSON 2 格式无效".to_string()],
            });
        }
    };
    let mut diffs = Vec::new();
    compare_values(&v1, &v2, "", &mut diffs);
    Json(CompareResponse {
        equal: diffs.is_empty(),
        differences: diffs,
    })
}

async fn minify_json(Json(req): Json<MinifyRequest>) -> Json<MinifyResponse> {
    let original_size = req.input.len();
    let input = remove_json_comments(&req.input);
    match serde_json::from_str::<Value>(&input) {
        Ok(val) => {
            let result = serde_json::to_string(&val).unwrap_or_default();
            let minified_size = result.len();
            Json(MinifyResponse {
                result,
                original_size,
                minified_size,
            })
        }
        Err(_) => Json(MinifyResponse {
            result: req.input.clone(),
            original_size,
            minified_size: original_size,
        }),
    }
}

// ── Router ─────────────────────────────────────────────────────────

pub fn router() -> Router {
    Router::new()
        .route("/format", post(format_json))
        .route("/validate", post(validate_json))
        .route("/py-dict", post(py_dict_to_json))
        .route("/compare", post(compare_json))
        .route("/minify", post(minify_json))
}

// ── Tests ──────────────────────────────────────────────────────────

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

    // ── count_depth ───────────────────────────────────────────

    #[test]
    fn test_count_depth_primitive() {
        assert_eq!(count_depth(&serde_json::json!(42)), 0);
        assert_eq!(count_depth(&serde_json::json!("hello")), 0);
        assert_eq!(count_depth(&serde_json::json!(null)), 0);
    }

    #[test]
    fn test_count_depth_flat_object() {
        let v = serde_json::json!({"a": 1, "b": 2});
        assert_eq!(count_depth(&v), 1);
    }

    #[test]
    fn test_count_depth_nested() {
        let v = serde_json::json!({"a": {"b": {"c": 1}}});
        assert_eq!(count_depth(&v), 3);
    }

    #[test]
    fn test_count_depth_array() {
        let v = serde_json::json!([1, [2, [3]]]);
        assert_eq!(count_depth(&v), 3);
    }

    #[test]
    fn test_count_depth_mixed() {
        let v = serde_json::json!({"a": [{"b": 1}]});
        assert_eq!(count_depth(&v), 3); // object -> array -> object
    }

    // ── count_keys ────────────────────────────────────────────

    #[test]
    fn test_count_keys_flat() {
        let v = serde_json::json!({"a": 1, "b": 2, "c": 3});
        assert_eq!(count_keys(&v), 3);
    }

    #[test]
    fn test_count_keys_nested() {
        let v = serde_json::json!({"a": {"x": 1, "y": 2}, "b": 3});
        assert_eq!(count_keys(&v), 4); // a, x, y, b
    }

    #[test]
    fn test_count_keys_array_of_objects() {
        let v = serde_json::json!([{"a": 1}, {"b": 2}]);
        assert_eq!(count_keys(&v), 2);
    }

    #[test]
    fn test_count_keys_no_keys() {
        assert_eq!(count_keys(&serde_json::json!(42)), 0);
        assert_eq!(count_keys(&serde_json::json!([1, 2, 3])), 0);
    }

    // ── sort_value ────────────────────────────────────────────

    #[test]
    fn test_sort_value_keys() {
        let v = serde_json::json!({"c": 3, "a": 1, "b": 2});
        let sorted = sort_value(&v);
        let keys: Vec<&String> = sorted.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_sort_value_nested() {
        let v = serde_json::json!({"z": {"b": 1, "a": 2}, "a": 0});
        let sorted = sort_value(&v);
        let outer: Vec<&String> = sorted.as_object().unwrap().keys().collect();
        assert_eq!(outer, vec!["a", "z"]);
        let inner: Vec<&String> = sorted["z"].as_object().unwrap().keys().collect();
        assert_eq!(inner, vec!["a", "b"]);
    }

    #[test]
    fn test_sort_value_primitive_unchanged() {
        assert_eq!(sort_value(&serde_json::json!(42)), serde_json::json!(42));
        assert_eq!(sort_value(&serde_json::json!("hi")), serde_json::json!("hi"));
    }

    // ── python_dict_to_json ───────────────────────────────────

    #[test]
    fn test_pydict_simple() {
        let result = python_dict_to_json("{'name': 'test', 'value': 123}").unwrap();
        let v: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["name"], "test");
        assert_eq!(v["value"], 123);
    }

    #[test]
    fn test_pydict_true_false_none() {
        let result = python_dict_to_json("{'a': True, 'b': False, 'c': None}").unwrap();
        let v: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["a"], true);
        assert_eq!(v["b"], false);
        assert!(v["c"].is_null());
    }

    #[test]
    fn test_pydict_trailing_comma() {
        let result = python_dict_to_json("{'a': 1, 'b': 2,}").unwrap();
        let v: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["a"], 1);
        assert_eq!(v["b"], 2);
    }

    #[test]
    fn test_pydict_tuple_to_array() {
        let result = python_dict_to_json("{'items': (1, 2, 3)}").unwrap();
        let v: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["items"], serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn test_pydict_nested() {
        let result = python_dict_to_json("{'outer': {'inner': True}}").unwrap();
        let v: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["outer"]["inner"], true);
    }

    #[test]
    fn test_pydict_double_quotes_inside_single() {
        let result = python_dict_to_json("{'msg': 'say \"hello\"'}").unwrap();
        let v: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["msg"], "say \"hello\"");
    }

    #[test]
    fn test_pydict_chinese_value() {
        let result = python_dict_to_json("{'name': '张三'}").unwrap();
        let v: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["name"], "张三");
    }

    #[test]
    fn test_pydict_multiline_string() {
        // Test literal newlines in strings (from print output)
        let result = python_dict_to_json("{'msg': 'line1\nline2'}").unwrap();
        let v: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["msg"], "line1\nline2");

        // Test with tabs
        let result = python_dict_to_json("{'msg': 'col1\tcol2'}").unwrap();
        let v: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["msg"], "col1\tcol2");
    }

    #[test]
    fn test_pydict_invalid_escape() {
        // Test invalid escape sequences (like \《 in Chinese text)
        // These should be escaped to produce valid JSON
        let result = python_dict_to_json("{'text': 'test\\《invalid'}").unwrap();
        let v: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["text"], "test\\《invalid");

        // Test backslash before regular character (using raw string to avoid Rust escape processing)
        let result = python_dict_to_json(r"{'text': 'path\xfile'}").unwrap();
        let v: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["text"], r"path\xfile");
    }

    #[test]
    fn test_pydict_invalid() {
        assert!(python_dict_to_json("not a dict at all").is_err());
    }

    // ── remove_trailing_commas ────────────────────────────────

    #[test]
    fn test_remove_trailing_commas_object() {
        let result = remove_trailing_commas(r#"{"a": 1, "b": 2,}"#);
        assert_eq!(result, r#"{"a": 1, "b": 2}"#);
    }

    #[test]
    fn test_remove_trailing_commas_array() {
        let result = remove_trailing_commas("[1, 2, 3,]");
        assert_eq!(result, "[1, 2, 3]");
    }

    #[test]
    fn test_remove_trailing_commas_nested() {
        let result = remove_trailing_commas(r#"{"a": [1,], "b": 2,}"#);
        assert_eq!(result, r#"{"a": [1], "b": 2}"#);
    }

    #[test]
    fn test_remove_trailing_commas_in_string_preserved() {
        let result = remove_trailing_commas(r#"{"a": "hello,}"}"#);
        // The comma inside the string should not be removed
        assert_eq!(result, r#"{"a": "hello,}"}"#);
    }

    // ── compare_values ────────────────────────────────────────

    #[test]
    fn test_compare_equal() {
        let v = serde_json::json!({"a": 1, "b": "hello"});
        let mut diffs = Vec::new();
        compare_values(&v, &v, "", &mut diffs);
        assert!(diffs.is_empty());
    }

    #[test]
    fn test_compare_modified_value() {
        let v1 = serde_json::json!({"a": 1});
        let v2 = serde_json::json!({"a": 2});
        let mut diffs = Vec::new();
        compare_values(&v1, &v2, "", &mut diffs);
        assert_eq!(diffs.len(), 1);
        assert!(diffs[0].contains("修改"));
    }

    #[test]
    fn test_compare_added_key() {
        let v1 = serde_json::json!({"a": 1});
        let v2 = serde_json::json!({"a": 1, "b": 2});
        let mut diffs = Vec::new();
        compare_values(&v1, &v2, "", &mut diffs);
        assert_eq!(diffs.len(), 1);
        assert!(diffs[0].contains("新增"));
    }

    #[test]
    fn test_compare_removed_key() {
        let v1 = serde_json::json!({"a": 1, "b": 2});
        let v2 = serde_json::json!({"a": 1});
        let mut diffs = Vec::new();
        compare_values(&v1, &v2, "", &mut diffs);
        assert_eq!(diffs.len(), 1);
        assert!(diffs[0].contains("删除"));
    }

    #[test]
    fn test_compare_array_length_diff() {
        let v1 = serde_json::json!([1, 2, 3]);
        let v2 = serde_json::json!([1, 2]);
        let mut diffs = Vec::new();
        compare_values(&v1, &v2, "", &mut diffs);
        assert_eq!(diffs.len(), 1);
        assert!(diffs[0].contains("删除"));
    }

    // ── Handler: format_json ──────────────────────────────────

    #[tokio::test]
    async fn test_handler_format_valid_json() {
        let (status, json) = post_json(
            "/format",
            serde_json::json!({"input": r#"{"a":1,"b":2}"#}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["valid"].as_bool().unwrap());
        assert!(json["result"].as_str().unwrap().contains('\n'));
        assert!(json["stats"]["keys"].as_u64().unwrap() == 2);
    }

    #[tokio::test]
    async fn test_handler_format_with_indent_4() {
        let (_, json) = post_json(
            "/format",
            serde_json::json!({"input": r#"{"a":1}"#, "indent": 4}),
        )
        .await;
        assert!(json["result"].as_str().unwrap().contains("    "));
    }

    #[tokio::test]
    async fn test_handler_format_compact() {
        let (_, json) = post_json(
            "/format",
            serde_json::json!({"input": r#"{ "a" : 1 , "b" : 2 }"#, "indent": 0}),
        )
        .await;
        assert_eq!(json["result"], r#"{"a":1,"b":2}"#);
    }

    #[tokio::test]
    async fn test_handler_format_sort_keys() {
        let (_, json) = post_json(
            "/format",
            serde_json::json!({"input": r#"{"c":3,"a":1,"b":2}"#, "sort_keys": true}),
        )
        .await;
        let result = json["result"].as_str().unwrap();
        let a_pos = result.find("\"a\"").unwrap();
        let b_pos = result.find("\"b\"").unwrap();
        let c_pos = result.find("\"c\"").unwrap();
        assert!(a_pos < b_pos && b_pos < c_pos);
    }

    #[tokio::test]
    async fn test_handler_format_invalid_json() {
        let (status, json) = post_json(
            "/format",
            serde_json::json!({"input": "{invalid json}"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!json["valid"].as_bool().unwrap());
        assert!(json["error"].is_string());
    }

    #[tokio::test]
    async fn test_handler_format_stats() {
        let (_, json) = post_json(
            "/format",
            serde_json::json!({"input": r#"{"a":{"b":{"c":1}},"d":[1,2]}"#}),
        )
        .await;
        let stats = &json["stats"];
        assert_eq!(stats["keys"].as_u64().unwrap(), 4); // a, b, c, d
        assert_eq!(stats["depth"].as_u64().unwrap(), 3); // a -> b -> c
    }

    // ── Handler: deep formatting ───────────────────────────────

    #[tokio::test]
    async fn test_handler_format_deep_nested() {
        let input = r#"{"content": "{\"a\": 1, \"b\": 2}"}"#;
        let (status, json) = post_json(
            "/format",
            serde_json::json!({"input": input, "max_depth": 5}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["valid"].as_bool().unwrap());
        // Result should contain formatted nested JSON
        let result = json["result"].as_str().unwrap();
        assert!(result.contains("\"a\": 1"));
        assert!(result.contains("\"b\": 2"));
    }

    #[tokio::test]
    async fn test_handler_format_deep_depth_limit() {
        let input = r#"{"level1": "{\"level2\": \"{\\\"level3\\\": 3}\"}"}"#;
        let (_, json) = post_json(
            "/format",
            serde_json::json!({"input": input, "max_depth": 1}),
        )
        .await;
        assert!(json["valid"].as_bool().unwrap());
        let result = json["result"].as_str().unwrap();
        // level1 should be parsed, level2 should remain as escaped string
        assert!(result.contains("\"level2\":"));
        assert!(result.contains("level3"));
    }

    #[tokio::test]
    async fn test_handler_format_deep_zero() {
        let input = r#"{"content": "{\"a\": 1}"}"#;
        let (_, json) = post_json(
            "/format",
            serde_json::json!({"input": input, "max_depth": 0}),
        )
        .await;
        assert!(json["valid"].as_bool().unwrap());
        let result = json["result"].as_str().unwrap();
        // Should remain as escaped string
        assert!(result.contains("\"content\": \"{\\\"a\\\": 1}\""));
    }

    #[tokio::test]
    async fn test_handler_format_deep_unset() {
        let input = r#"{"content": "{\"a\": 1}"}"#;
        let (_, json) = post_json(
            "/format",
            serde_json::json!({"input": input}), // no max_depth
        )
        .await;
        assert!(json["valid"].as_bool().unwrap());
        let result = json["result"].as_str().unwrap();
        // Should remain as escaped string (default: no deep parsing)
        assert!(result.contains("\"content\": \"{\\\"a\\\": 1}\""));
    }

    // ── Handler: validate_json ────────────────────────────────

    #[tokio::test]
    async fn test_handler_validate_valid() {
        let (_, json) = post_json(
            "/validate",
            serde_json::json!({"input": r#"{"key": "value"}"#}),
        )
        .await;
        assert!(json["valid"].as_bool().unwrap());
        assert!(json["error"].is_null());
    }

    #[tokio::test]
    async fn test_handler_validate_invalid() {
        let (_, json) = post_json(
            "/validate",
            serde_json::json!({"input": r#"{"key": }"#}),
        )
        .await;
        assert!(!json["valid"].as_bool().unwrap());
        assert!(json["error"].is_string());
        assert!(json["error_position"].is_number());
    }

    #[tokio::test]
    async fn test_handler_validate_empty() {
        let (_, json) = post_json(
            "/validate",
            serde_json::json!({"input": ""}),
        )
        .await;
        assert!(!json["valid"].as_bool().unwrap());
    }

    // ── Handler: py_dict_to_json ──────────────────────────────

    #[tokio::test]
    async fn test_handler_pydict_basic() {
        let (status, json) = post_json(
            "/py-dict",
            serde_json::json!({"input": "{'name': 'Alice', 'age': 30}"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["valid"].as_bool().unwrap());
        let result: Value = serde_json::from_str(json["result"].as_str().unwrap()).unwrap();
        assert_eq!(result["name"], "Alice");
        assert_eq!(result["age"], 30);
    }

    #[tokio::test]
    async fn test_handler_pydict_keywords() {
        let (_, json) = post_json(
            "/py-dict",
            serde_json::json!({"input": "{'active': True, 'deleted': False, 'data': None}"}),
        )
        .await;
        assert!(json["valid"].as_bool().unwrap());
        let result: Value = serde_json::from_str(json["result"].as_str().unwrap()).unwrap();
        assert_eq!(result["active"], true);
        assert_eq!(result["deleted"], false);
        assert!(result["data"].is_null());
    }

    #[tokio::test]
    async fn test_handler_pydict_invalid() {
        let (_, json) = post_json(
            "/py-dict",
            serde_json::json!({"input": "completely broken {{{"}),
        )
        .await;
        assert!(!json["valid"].as_bool().unwrap());
        assert!(json["error"].is_string());
    }

    // ── Handler: compare_json ─────────────────────────────────

    #[tokio::test]
    async fn test_handler_compare_equal() {
        let (_, json) = post_json(
            "/compare",
            serde_json::json!({
                "json1": r#"{"a":1,"b":2}"#,
                "json2": r#"{"a":1,"b":2}"#
            }),
        )
        .await;
        assert!(json["equal"].as_bool().unwrap());
        assert!(json["differences"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_handler_compare_different() {
        let (_, json) = post_json(
            "/compare",
            serde_json::json!({
                "json1": r#"{"a":1,"b":2}"#,
                "json2": r#"{"a":1,"b":3,"c":4}"#
            }),
        )
        .await;
        assert!(!json["equal"].as_bool().unwrap());
        let diffs = json["differences"].as_array().unwrap();
        assert_eq!(diffs.len(), 2); // b modified + c added
    }

    #[tokio::test]
    async fn test_handler_compare_invalid_json1() {
        let (_, json) = post_json(
            "/compare",
            serde_json::json!({
                "json1": "bad",
                "json2": r#"{"a":1}"#
            }),
        )
        .await;
        assert!(!json["equal"].as_bool().unwrap());
        assert!(json["differences"][0].as_str().unwrap().contains("JSON 1"));
    }

    // ── Handler: minify_json ──────────────────────────────────

    #[tokio::test]
    async fn test_handler_minify() {
        let input = r#"{
  "name": "test",
  "value": 123
}"#;
        let (_, json) = post_json(
            "/minify",
            serde_json::json!({"input": input}),
        )
        .await;
        assert_eq!(json["result"], r#"{"name":"test","value":123}"#);
        assert!(json["minified_size"].as_u64().unwrap() < json["original_size"].as_u64().unwrap());
    }

    #[tokio::test]
    async fn test_handler_minify_already_compact() {
        let (_, json) = post_json(
            "/minify",
            serde_json::json!({"input": r#"{"a":1}"#}),
        )
        .await;
        assert_eq!(json["result"], r#"{"a":1}"#);
    }

    // ── Handler: comment removal ───────────────────────────────

    #[tokio::test]
    async fn test_handler_format_with_comments() {
        let input = r#"{
    # This is a comment
    "name": "test",
    # Another comment
    "value": 123
}"#;
        let (status, json) = post_json(
            "/format",
            serde_json::json!({"input": input}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["valid"].as_bool().unwrap());
        assert!(json["result"].as_str().unwrap().contains("\"name\": \"test\""));
        assert!(!json["result"].as_str().unwrap().contains("# This is a comment"));
    }

    #[tokio::test]
    async fn test_handler_validate_with_comments() {
        let input = r#"{
    # Config file
    "debug": true
}"#;
        let (_, json) = post_json(
            "/validate",
            serde_json::json!({"input": input}),
        )
        .await;
        assert!(json["valid"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_handler_minify_with_comments() {
        let input = r#"{
    # Comment to remove
    "a": 1,
    "b": 2
}"#;
        let (_, json) = post_json(
            "/minify",
            serde_json::json!({"input": input}),
        )
        .await;
        assert_eq!(json["result"], r#"{"a":1,"b":2}"#);
    }

    // ── deep_format_value ──────────────────────────────────────

    #[test]
    fn test_deep_format_simple_nested() {
        let input = serde_json::json!({"content": "{\"a\": 1, \"b\": 2}"});
        let result = deep_format_value(&input, 0, 5);
        assert_eq!(result["content"]["a"], 1);
        assert_eq!(result["content"]["b"], 2);
    }

    #[test]
    fn test_deep_format_multi_level() {
        // content contains JSON string, which itself has a nested JSON string
        let input = serde_json::json!({
            "outer": "{\"inner\": \"{\\\"deep\\\": 3}\"}"
        });
        let result = deep_format_value(&input, 0, 5);
        assert_eq!(result["outer"]["inner"]["deep"], 3);
    }

    #[test]
    fn test_deep_format_depth_limit() {
        let input = serde_json::json!({
            "level1": "{\"level2\": \"{\\\"level3\\\": 3}\"}"
        });
        // max_depth=1: only parse first level
        let result = deep_format_value(&input, 0, 1);
        // level1 should be parsed, but level2 should remain as string
        assert!(result["level1"]["level2"].is_string());
        assert!(result["level1"]["level2"].as_str().unwrap().contains("level3"));
    }

    #[test]
    fn test_deep_format_invalid_json_preserved() {
        let input = serde_json::json!({
            "valid": "{\"a\": 1}",
            "invalid": "not json at all"
        });
        let result = deep_format_value(&input, 0, 5);
        assert_eq!(result["valid"]["a"], 1);
        assert_eq!(result["invalid"], "not json at all");
    }

    #[test]
    fn test_deep_format_json_primitive() {
        let input = serde_json::json!({
            "num_str": "42",
            "bool_str": "true",
            "null_str": "null"
        });
        let result = deep_format_value(&input, 0, 5);
        assert_eq!(result["num_str"], 42);
        assert_eq!(result["bool_str"], true);
        assert!(result["null_str"].is_null());
    }

    #[test]
    fn test_deep_format_array_elements() {
        let input = serde_json::json!({
            "items": ["{\"a\": 1}", "regular string", "{\"b\": 2}"]
        });
        let result = deep_format_value(&input, 0, 5);
        assert_eq!(result["items"][0]["a"], 1);
        assert_eq!(result["items"][1], "regular string");
        assert_eq!(result["items"][2]["b"], 2);
    }

    #[test]
    fn test_deep_format_zero_depth() {
        let input = serde_json::json!({"content": "{\"a\": 1}"});
        let result = deep_format_value(&input, 0, 0);
        // Should remain as string when max_depth=0
        assert!(result["content"].is_string());
        assert_eq!(result["content"], "{\"a\": 1}");
    }
}

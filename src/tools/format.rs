use axum::{Json, Router, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Request / Response types ───────────────────────────────────────

#[derive(Deserialize)]
pub struct YamlToJsonRequest {
    pub input: String,
}

#[derive(Serialize)]
pub struct YamlToJsonResponse {
    pub result: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct JsonToYamlRequest {
    pub input: String,
}

#[derive(Serialize)]
pub struct JsonToYamlResponse {
    pub result: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct XmlRequest {
    pub input: String,
}

#[derive(Serialize)]
pub struct XmlResponse {
    pub result: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct CsvToJsonRequest {
    pub input: String,
    pub delimiter: Option<String>,
}

#[derive(Serialize)]
pub struct CsvToJsonResponse {
    pub result: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct JsonToCsvRequest {
    pub input: String,
}

#[derive(Serialize)]
pub struct JsonToCsvResponse {
    pub result: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct SqlRequest {
    pub input: String,
}

#[derive(Serialize)]
pub struct SqlResponse {
    pub result: String,
    pub success: bool,
    pub error: Option<String>,
}

// ── Handlers: YAML ↔ JSON ───────────────────────────────────────────

async fn yaml_to_json(Json(req): Json<YamlToJsonRequest>) -> Json<YamlToJsonResponse> {
    match serde_yaml::from_str::<Value>(&req.input) {
        Ok(val) => Json(YamlToJsonResponse {
            result: serde_json::to_string_pretty(&val).unwrap_or_default(),
            success: true,
            error: None,
        }),
        Err(e) => Json(YamlToJsonResponse {
            result: String::new(),
            success: false,
            error: Some(format!("YAML 解析错误: {}", e)),
        }),
    }
}

async fn json_to_yaml(Json(req): Json<JsonToYamlRequest>) -> Json<JsonToYamlResponse> {
    match serde_json::from_str::<Value>(&req.input) {
        Ok(val) => match serde_yaml::to_string(&val) {
            Ok(yaml) => Json(JsonToYamlResponse {
                result: yaml,
                success: true,
                error: None,
            }),
            Err(e) => Json(JsonToYamlResponse {
                result: String::new(),
                success: false,
                error: Some(format!("YAML 转换错误: {}", e)),
            }),
        },
        Err(e) => Json(JsonToYamlResponse {
            result: String::new(),
            success: false,
            error: Some(format!("JSON 解析错误: {}", e)),
        }),
    }
}

// ── Handlers: XML Format/Minify ─────────────────────────────────────

async fn xml_format(Json(req): Json<XmlRequest>) -> Json<XmlResponse> {
    use quick_xml::Reader;
    use quick_xml::Writer;
    use quick_xml::events::Event;
    use std::io::Cursor;

    let mut reader = Reader::from_str(&req.input);
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(e) => {
                if let Err(_) = writer.write_event(e) {
                    return Json(XmlResponse {
                        result: String::new(),
                        success: false,
                        error: Some("XML 写入失败".to_string()),
                    });
                }
            }
            Err(e) => {
                return Json(XmlResponse {
                    result: String::new(),
                    success: false,
                    error: Some(format!("XML 解析错误: {:?}", e)),
                });
            }
        }
        buf.clear();
    }

    let result = String::from_utf8(writer.into_inner().into_inner()).unwrap_or_default();
    Json(XmlResponse {
        result,
        success: true,
        error: None,
    })
}

async fn xml_minify(Json(req): Json<XmlRequest>) -> Json<XmlResponse> {
    let result = req.input.split_whitespace().collect::<Vec<_>>().join("");
    Json(XmlResponse {
        result,
        success: true,
        error: None,
    })
}

// ── Handlers: CSV ↔ JSON ───────────────────────────────────────────

async fn csv_to_json(Json(req): Json<CsvToJsonRequest>) -> Json<CsvToJsonResponse> {
    let delimiter = req
        .delimiter
        .unwrap_or_else(|| ",".to_string())
        .chars()
        .next()
        .unwrap_or(',');
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter as u8)
        .from_reader(req.input.as_bytes());

    let headers: Vec<String> = reader
        .headers()
        .map(|h| h.iter().map(|s| s.to_string()).collect())
        .unwrap_or_default();
    let mut result: Vec<serde_json::Map<String, Value>> = Vec::new();

    for record in reader.records() {
        match record {
            Ok(r) => {
                let mut obj = serde_json::Map::new();
                for (i, h) in headers.iter().enumerate() {
                    let val = r.get(i).unwrap_or("").to_string();
                    obj.insert(h.clone(), Value::String(val));
                }
                result.push(obj);
            }
            Err(e) => {
                return Json(CsvToJsonResponse {
                    result: String::new(),
                    success: false,
                    error: Some(format!("CSV 解析错误: {}", e)),
                });
            }
        }
    }

    Json(CsvToJsonResponse {
        result: serde_json::to_string_pretty(&result).unwrap_or_default(),
        success: true,
        error: None,
    })
}

async fn json_to_csv(Json(req): Json<JsonToCsvRequest>) -> Json<JsonToCsvResponse> {
    let value: Value = match serde_json::from_str(&req.input) {
        Ok(v) => v,
        Err(e) => {
            return Json(JsonToCsvResponse {
                result: String::new(),
                success: false,
                error: Some(format!("JSON 解析错误: {}", e)),
            });
        }
    };

    let arr = match value.as_array() {
        Some(a) => a,
        None => {
            return Json(JsonToCsvResponse {
                result: String::new(),
                success: false,
                error: Some("JSON 必须是数组格式".to_string()),
            });
        }
    };

    if arr.is_empty() {
        return Json(JsonToCsvResponse {
            result: String::new(),
            success: true,
            error: None,
        });
    }

    let headers: Vec<&str> = match arr[0].as_object() {
        Some(obj) => obj.keys().map(|s| s.as_str()).collect(),
        None => {
            return Json(JsonToCsvResponse {
                result: String::new(),
                success: false,
                error: Some("数组元素必须是对象".to_string()),
            });
        }
    };

    let mut wtr = csv::Writer::from_writer(Vec::new());
    wtr.write_record(&headers).unwrap();

    for item in arr {
        if let Some(obj) = item.as_object() {
            let record: Vec<String> = headers
                .iter()
                .map(|h| {
                    obj.get(*h)
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string()
                })
                .collect();
            wtr.write_record(&record).unwrap();
        }
    }

    let result = String::from_utf8(wtr.into_inner().unwrap()).unwrap_or_default();
    Json(JsonToCsvResponse {
        result,
        success: true,
        error: None,
    })
}

// ── Handlers: SQL Format ───────────────────────────────────────────

fn format_sql(sql: &str) -> String {
    let keywords = [
        "SELECT", "FROM", "WHERE", "JOIN", "ON", "AND", "OR", "ORDER", "BY", "GROUP", "HAVING",
        "INSERT", "INTO", "VALUES", "UPDATE", "SET", "DELETE", "CREATE", "TABLE", "ALTER", "DROP",
        "INDEX", "INNER", "LEFT", "RIGHT", "OUTER", "FULL", "UNION", "DISTINCT", "LIMIT", "OFFSET",
        "AS", "IN", "NOT", "NULL", "IS", "LIKE", "BETWEEN", "CASE", "WHEN", "THEN", "ELSE", "END",
    ];

    let mut result = sql.to_uppercase();

    for kw in &keywords {
        let pattern = format!(" {}", kw);
        if result.contains(&pattern) {
            result = result.replace(&pattern, &format!("\n{}", kw));
        }
    }

    let lines: Vec<&str> = result.lines().collect();
    let mut formatted = Vec::new();
    let mut indent = 0;
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with("FROM")
            || trimmed.starts_with("WHERE")
            || trimmed.starts_with("ORDER")
            || trimmed.starts_with("GROUP")
            || trimmed.starts_with("HAVING")
            || trimmed.starts_with("LIMIT")
        {
            indent = 0;
        }

        formatted.push(format!("{}{}", "  ".repeat(indent), trimmed));

        if trimmed.starts_with("SELECT") {
            indent = 1;
        }
    }

    formatted.join("\n")
}

async fn sql_format(Json(req): Json<SqlRequest>) -> Json<SqlResponse> {
    Json(SqlResponse {
        result: format_sql(&req.input),
        success: true,
        error: None,
    })
}

// ── Router ─────────────────────────────────────────────────────────

pub fn router() -> Router {
    Router::new()
        .route("/yaml-to-json", post(yaml_to_json))
        .route("/json-to-yaml", post(json_to_yaml))
        .route("/xml/format", post(xml_format))
        .route("/xml/minify", post(xml_minify))
        .route("/csv-to-json", post(csv_to_json))
        .route("/json-to-csv", post(json_to_csv))
        .route("/sql/format", post(sql_format))
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
    async fn test_yaml_to_json() {
        let yaml = "name: test\nvalue: 123";
        let (_, json) = post_json("/yaml-to-json", serde_json::json!({"input": yaml})).await;
        assert!(json["success"].as_bool().unwrap());
        let result: Value = serde_json::from_str(json["result"].as_str().unwrap()).unwrap();
        assert_eq!(result["name"], "test");
        assert_eq!(result["value"], 123);
    }

    #[tokio::test]
    async fn test_json_to_yaml() {
        let json_input = r#"{"name":"test","value":123}"#;
        let (_, json) = post_json("/json-to-yaml", serde_json::json!({"input": json_input})).await;
        assert!(json["success"].as_bool().unwrap());
        assert!(json["result"].as_str().unwrap().contains("name: test"));
    }

    #[tokio::test]
    async fn test_xml_format() {
        let xml = "<root><item>text</item></root>";
        let (_, json) = post_json("/xml/format", serde_json::json!({"input": xml})).await;
        assert!(json["success"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_xml_minify() {
        let xml = "<root>  <item>  text  </item>  </root>";
        let (_, json) = post_json("/xml/minify", serde_json::json!({"input": xml})).await;
        assert!(json["success"].as_bool().unwrap());
        assert!(
            json["result"]
                .as_str()
                .unwrap()
                .contains("<root><item>text</item></root>")
        );
    }

    #[tokio::test]
    async fn test_csv_to_json() {
        let csv = "name,value\ntest,123";
        let (_, json) = post_json("/csv-to-json", serde_json::json!({"input": csv})).await;
        assert!(json["success"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_json_to_csv() {
        let json_input = r#"[{"name":"test","value":"123"}]"#;
        let (_, json) = post_json("/json-to-csv", serde_json::json!({"input": json_input})).await;
        assert!(json["success"].as_bool().unwrap());
        assert!(json["result"].as_str().unwrap().contains("name,value"));
    }

    #[tokio::test]
    async fn test_sql_format() {
        let sql = "select name from users where id = 1";
        let (_, json) = post_json("/sql/format", serde_json::json!({"input": sql})).await;
        assert!(json["success"].as_bool().unwrap());
        assert!(json["result"].as_str().unwrap().contains("SELECT"));
    }

    #[tokio::test]
    async fn test_sql_format_with_order() {
        let sql = "select name from users where id = 1 order by name";
        let (_, json) = post_json("/sql/format", serde_json::json!({"input": sql})).await;
        assert!(json["success"].as_bool().unwrap());
        let result = json["result"].as_str().unwrap();
        assert!(result.contains("SELECT"));
        assert!(result.contains("FROM"));
        assert!(result.contains("WHERE"));
        assert!(result.contains("ORDER"));
    }
}

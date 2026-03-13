use axum::{Json, Router, routing::post};
use chrono::{DateTime, Datelike, Local, NaiveDateTime, TimeZone, Utc, Weekday};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};

// ── Request / Response types ───────────────────────────────────────

#[derive(Deserialize)]
pub struct TimestampToDatetime {
    pub timestamp: i64,
    pub timezone: Option<String>, // e.g. "Asia/Shanghai", "UTC"
}

#[derive(Serialize)]
pub struct DatetimeResult {
    pub local: String,
    pub utc: String,
    pub custom_tz: Option<String>,
    pub weekday: String,
    pub relative: String,
    pub iso8601: String,
    pub unix_sec: i64,
    pub unix_ms: i64,
}

#[derive(Deserialize)]
pub struct DatetimeToTimestamp {
    pub datetime: String, // "YYYY-MM-DD HH:MM:SS" or variants
    pub from_timezone: Option<String>,
}

#[derive(Serialize)]
pub struct TimestampResult {
    pub unix_sec: i64,
    pub unix_ms: i64,
    pub utc: String,
    pub local: String,
    pub iso8601: String,
}

#[derive(Deserialize)]
pub struct TimezoneConvert {
    pub datetime: String,
    pub from_tz: String,
    pub to_tz: String,
}

#[derive(Serialize)]
pub struct TimezoneResult {
    pub from: String,
    pub to: String,
    pub from_tz: String,
    pub to_tz: String,
}

#[derive(Deserialize)]
pub struct FormatConvert {
    pub datetime: String,
    pub target_format: String,
}

#[derive(Serialize)]
pub struct FormatResult {
    pub result: String,
}

#[derive(Deserialize)]
pub struct NowRequest {}

#[derive(Serialize)]
pub struct NowResult {
    pub unix_sec: i64,
    pub unix_ms: i64,
    pub local: String,
    pub utc: String,
    pub iso8601: String,
    pub weekday: String,
}

#[derive(Deserialize)]
pub struct BatchTimestampRequest {
    pub timestamps: Vec<i64>,
    pub timezone: Option<String>,
}

#[derive(Serialize)]
pub struct BatchTimestampResult {
    pub results: Vec<DatetimeResult>,
}

// ── Helper functions ───────────────────────────────────────────────

fn normalize_timestamp(ts: i64) -> (i64, i64) {
    if ts > 1_000_000_000_000 {
        // milliseconds
        (ts / 1000, ts)
    } else {
        // seconds
        (ts, ts * 1000)
    }
}

fn weekday_cn(w: Weekday) -> &'static str {
    match w {
        Weekday::Mon => "星期一",
        Weekday::Tue => "星期二",
        Weekday::Wed => "星期三",
        Weekday::Thu => "星期四",
        Weekday::Fri => "星期五",
        Weekday::Sat => "星期六",
        Weekday::Sun => "星期日",
    }
}

fn relative_time(dt_utc: DateTime<Utc>) -> String {
    let now = Utc::now();
    let diff = now.signed_duration_since(dt_utc);
    let secs = diff.num_seconds();
    if secs < 0 {
        let abs = -secs;
        if abs < 60 {
            format!("{}秒后", abs)
        } else if abs < 3600 {
            format!("{}分钟后", abs / 60)
        } else if abs < 86400 {
            format!("{}小时后", abs / 3600)
        } else {
            format!("{}天后", abs / 86400)
        }
    } else if secs < 60 {
        format!("{}秒前", secs)
    } else if secs < 3600 {
        format!("{}分钟前", secs / 60)
    } else if secs < 86400 {
        format!("{}小时前", secs / 3600)
    } else {
        format!("{}天前", secs / 86400)
    }
}

fn parse_naive_datetime(s: &str) -> Option<NaiveDateTime> {
    let s = s.trim();
    // Try multiple common formats
    let formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y.%m.%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y/%m/%d %H:%M",
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%Y%m%d%H%M%S",
        "%Y%m%d",
    ];
    for fmt in &formats {
        if let Ok(dt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(dt);
        }
    }
    // Try parsing date-only formats and add midnight
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return d.and_hms_opt(0, 0, 0);
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y/%m/%d") {
        return d.and_hms_opt(0, 0, 0);
    }
    None
}

fn parse_tz(s: &str) -> Option<Tz> {
    s.parse::<Tz>().ok()
}

// ── Handlers ───────────────────────────────────────────────────────

async fn timestamp_to_datetime(
    Json(req): Json<TimestampToDatetime>,
) -> Result<Json<DatetimeResult>, Json<serde_json::Value>> {
    let (sec, ms) = normalize_timestamp(req.timestamp);
    let dt_utc = DateTime::from_timestamp(sec, 0).ok_or_else(|| {
        Json(serde_json::json!({"error": "无效的时间戳"}))
    })?;
    let dt_local = dt_utc.with_timezone(&Local);

    let custom_tz = req
        .timezone
        .as_deref()
        .and_then(parse_tz)
        .map(|tz| dt_utc.with_timezone(&tz).format("%Y-%m-%d %H:%M:%S").to_string());

    Ok(Json(DatetimeResult {
        local: dt_local.format("%Y-%m-%d %H:%M:%S").to_string(),
        utc: dt_utc.format("%Y-%m-%d %H:%M:%S").to_string(),
        custom_tz,
        weekday: weekday_cn(dt_utc.weekday()).to_string(),
        relative: relative_time(dt_utc),
        iso8601: dt_utc.to_rfc3339(),
        unix_sec: sec,
        unix_ms: ms,
    }))
}

async fn datetime_to_timestamp(
    Json(req): Json<DatetimeToTimestamp>,
) -> Result<Json<TimestampResult>, Json<serde_json::Value>> {
    let naive = parse_naive_datetime(&req.datetime).ok_or_else(|| {
        Json(serde_json::json!({"error": "无法解析日期时间，支持格式: YYYY-MM-DD HH:MM:SS, YYYY/MM/DD HH:MM:SS 等"}))
    })?;

    let dt_utc = if let Some(tz_str) = &req.from_timezone {
        if let Some(tz) = parse_tz(tz_str) {
            tz.from_local_datetime(&naive)
                .single()
                .ok_or_else(|| Json(serde_json::json!({"error": "无法确定唯一的时间"})))?
                .with_timezone(&Utc)
        } else {
            return Err(Json(serde_json::json!({"error": format!("未知时区: {}", tz_str)})));
        }
    } else {
        // Assume local timezone
        Local
            .from_local_datetime(&naive)
            .single()
            .ok_or_else(|| Json(serde_json::json!({"error": "无法确定唯一的本地时间"})))?
            .with_timezone(&Utc)
    };

    let sec = dt_utc.timestamp();
    let dt_local = dt_utc.with_timezone(&Local);

    Ok(Json(TimestampResult {
        unix_sec: sec,
        unix_ms: sec * 1000,
        utc: dt_utc.format("%Y-%m-%d %H:%M:%S").to_string(),
        local: dt_local.format("%Y-%m-%d %H:%M:%S").to_string(),
        iso8601: dt_utc.to_rfc3339(),
    }))
}

async fn timezone_convert(
    Json(req): Json<TimezoneConvert>,
) -> Result<Json<TimezoneResult>, Json<serde_json::Value>> {
    let naive = parse_naive_datetime(&req.datetime).ok_or_else(|| {
        Json(serde_json::json!({"error": "无法解析日期时间"}))
    })?;
    let from_tz = parse_tz(&req.from_tz).ok_or_else(|| {
        Json(serde_json::json!({"error": format!("未知来源时区: {}", req.from_tz)}))
    })?;
    let to_tz = parse_tz(&req.to_tz).ok_or_else(|| {
        Json(serde_json::json!({"error": format!("未知目标时区: {}", req.to_tz)}))
    })?;

    let dt = from_tz
        .from_local_datetime(&naive)
        .single()
        .ok_or_else(|| Json(serde_json::json!({"error": "无法确定来源时区时间"})))?;

    let converted = dt.with_timezone(&to_tz);

    Ok(Json(TimezoneResult {
        from: dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        to: converted.format("%Y-%m-%d %H:%M:%S").to_string(),
        from_tz: req.from_tz,
        to_tz: req.to_tz,
    }))
}

async fn format_convert(
    Json(req): Json<FormatConvert>,
) -> Result<Json<FormatResult>, Json<serde_json::Value>> {
    let naive = parse_naive_datetime(&req.datetime).ok_or_else(|| {
        Json(serde_json::json!({"error": "无法解析日期时间"}))
    })?;

    let result = match req.target_format.as_str() {
        "YYYY-MM-DD HH:MM:SS" | "standard" => naive.format("%Y-%m-%d %H:%M:%S").to_string(),
        "YYYY/MM/DD HH:MM:SS" | "slash" => naive.format("%Y/%m/%d %H:%M:%S").to_string(),
        "YYYY.MM.DD HH:MM:SS" | "dot" => naive.format("%Y.%m.%d %H:%M:%S").to_string(),
        "YYYYMMDDHHMMSS" | "compact" => naive.format("%Y%m%d%H%M%S").to_string(),
        "YYYY-MM-DD" | "date" => naive.format("%Y-%m-%d").to_string(),
        "HH:MM:SS" | "time" => naive.format("%H:%M:%S").to_string(),
        "chinese" => {
            naive.format("%Y年%m月%d日 %H时%M分%S秒").to_string()
        }
        "iso8601" => {
            naive.format("%Y-%m-%dT%H:%M:%S").to_string() + "+00:00"
        }
        "rfc2822" => {
            let dt_utc = Utc.from_utc_datetime(&naive);
            dt_utc.to_rfc2822()
        }
        other => {
            // Try to use it as a strftime format
            naive.format(other).to_string()
        }
    };

    Ok(Json(FormatResult { result }))
}

async fn now(_: Json<NowRequest>) -> Json<NowResult> {
    let now_utc = Utc::now();
    let now_local = Local::now();
    Json(NowResult {
        unix_sec: now_utc.timestamp(),
        unix_ms: now_utc.timestamp_millis(),
        local: now_local.format("%Y-%m-%d %H:%M:%S").to_string(),
        utc: now_utc.format("%Y-%m-%d %H:%M:%S").to_string(),
        iso8601: now_utc.to_rfc3339(),
        weekday: weekday_cn(now_utc.weekday()).to_string(),
    })
}

async fn batch_timestamp(
    Json(req): Json<BatchTimestampRequest>,
) -> Result<Json<BatchTimestampResult>, Json<serde_json::Value>> {
    let mut results = Vec::with_capacity(req.timestamps.len());
    for ts in &req.timestamps {
        let (sec, ms) = normalize_timestamp(*ts);
        let dt_utc = DateTime::from_timestamp(sec, 0).ok_or_else(|| {
            Json(serde_json::json!({"error": format!("无效的时间戳: {}", ts)}))
        })?;
        let dt_local = dt_utc.with_timezone(&Local);
        let custom_tz = req
            .timezone
            .as_deref()
            .and_then(parse_tz)
            .map(|tz| dt_utc.with_timezone(&tz).format("%Y-%m-%d %H:%M:%S").to_string());

        results.push(DatetimeResult {
            local: dt_local.format("%Y-%m-%d %H:%M:%S").to_string(),
            utc: dt_utc.format("%Y-%m-%d %H:%M:%S").to_string(),
            custom_tz,
            weekday: weekday_cn(dt_utc.weekday()).to_string(),
            relative: relative_time(dt_utc),
            iso8601: dt_utc.to_rfc3339(),
            unix_sec: sec,
            unix_ms: ms,
        });
    }
    Ok(Json(BatchTimestampResult { results }))
}

// ── Router ─────────────────────────────────────────────────────────

pub fn router() -> Router {
    Router::new()
        .route("/timestamp-to-datetime", post(timestamp_to_datetime))
        .route("/datetime-to-timestamp", post(datetime_to_timestamp))
        .route("/timezone-convert", post(timezone_convert))
        .route("/format-convert", post(format_convert))
        .route("/now", post(now))
        .route("/batch-timestamp", post(batch_timestamp))
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chrono::Timelike;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// Helper: send a POST JSON request to the router and return (status, body_json).
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

    // ── normalize_timestamp ───────────────────────────────────

    #[test]
    fn test_normalize_seconds() {
        let (sec, ms) = normalize_timestamp(1_700_000_000);
        assert_eq!(sec, 1_700_000_000);
        assert_eq!(ms, 1_700_000_000_000);
    }

    #[test]
    fn test_normalize_milliseconds() {
        let (sec, ms) = normalize_timestamp(1_700_000_000_123);
        assert_eq!(sec, 1_700_000_000);
        assert_eq!(ms, 1_700_000_000_123);
    }

    #[test]
    fn test_normalize_zero() {
        let (sec, ms) = normalize_timestamp(0);
        assert_eq!(sec, 0);
        assert_eq!(ms, 0);
    }

    // ── weekday_cn ────────────────────────────────────────────

    #[test]
    fn test_weekday_cn_all() {
        assert_eq!(weekday_cn(Weekday::Mon), "星期一");
        assert_eq!(weekday_cn(Weekday::Tue), "星期二");
        assert_eq!(weekday_cn(Weekday::Wed), "星期三");
        assert_eq!(weekday_cn(Weekday::Thu), "星期四");
        assert_eq!(weekday_cn(Weekday::Fri), "星期五");
        assert_eq!(weekday_cn(Weekday::Sat), "星期六");
        assert_eq!(weekday_cn(Weekday::Sun), "星期日");
    }

    // ── relative_time ─────────────────────────────────────────

    #[test]
    fn test_relative_time_seconds_ago() {
        let dt = Utc::now() - chrono::Duration::seconds(30);
        let r = relative_time(dt);
        assert!(r.contains("秒前"), "expected '秒前', got: {}", r);
    }

    #[test]
    fn test_relative_time_minutes_ago() {
        let dt = Utc::now() - chrono::Duration::minutes(5);
        let r = relative_time(dt);
        assert!(r.contains("分钟前"), "expected '分钟前', got: {}", r);
    }

    #[test]
    fn test_relative_time_hours_ago() {
        let dt = Utc::now() - chrono::Duration::hours(3);
        let r = relative_time(dt);
        assert!(r.contains("小时前"), "expected '小时前', got: {}", r);
    }

    #[test]
    fn test_relative_time_days_ago() {
        let dt = Utc::now() - chrono::Duration::days(10);
        let r = relative_time(dt);
        assert!(r.contains("天前"), "expected '天前', got: {}", r);
    }

    #[test]
    fn test_relative_time_future() {
        let dt = Utc::now() + chrono::Duration::hours(2);
        let r = relative_time(dt);
        assert!(r.contains("后"), "expected '后', got: {}", r);
    }

    // ── parse_naive_datetime ──────────────────────────────────

    #[test]
    fn test_parse_standard_format() {
        let dt = parse_naive_datetime("2024-01-15 13:45:30").unwrap();
        assert_eq!(dt.year(), 2024);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 15);
        assert_eq!(dt.hour(), 13);
        assert_eq!(dt.minute(), 45);
        assert_eq!(dt.second(), 30);
    }

    #[test]
    fn test_parse_slash_format() {
        let dt = parse_naive_datetime("2024/06/20 08:30:00").unwrap();
        assert_eq!(dt.year(), 2024);
        assert_eq!(dt.month(), 6);
    }

    #[test]
    fn test_parse_dot_format() {
        let dt = parse_naive_datetime("2024.12.25 00:00:00").unwrap();
        assert_eq!(dt.month(), 12);
        assert_eq!(dt.day(), 25);
    }

    #[test]
    fn test_parse_iso_t_format() {
        let dt = parse_naive_datetime("2024-03-01T10:20:30").unwrap();
        assert_eq!(dt.hour(), 10);
    }

    #[test]
    fn test_parse_compact_format() {
        let dt = parse_naive_datetime("20240315120000").unwrap();
        assert_eq!(dt.year(), 2024);
        assert_eq!(dt.month(), 3);
        assert_eq!(dt.hour(), 12);
    }

    #[test]
    fn test_parse_date_only() {
        let dt = parse_naive_datetime("2024-07-04").unwrap();
        assert_eq!(dt.month(), 7);
        assert_eq!(dt.hour(), 0);
    }

    #[test]
    fn test_parse_with_whitespace() {
        let dt = parse_naive_datetime("  2024-01-01 00:00:00  ").unwrap();
        assert_eq!(dt.year(), 2024);
    }

    #[test]
    fn test_parse_invalid() {
        assert!(parse_naive_datetime("not-a-date").is_none());
        assert!(parse_naive_datetime("").is_none());
    }

    // ── parse_tz ──────────────────────────────────────────────

    #[test]
    fn test_parse_tz_valid() {
        assert!(parse_tz("Asia/Shanghai").is_some());
        assert!(parse_tz("America/New_York").is_some());
        assert!(parse_tz("UTC").is_some());
        assert!(parse_tz("Europe/London").is_some());
    }

    #[test]
    fn test_parse_tz_invalid() {
        assert!(parse_tz("Invalid/Zone").is_none());
        assert!(parse_tz("").is_none());
    }

    // ── Handler: timestamp_to_datetime ────────────────────────

    #[tokio::test]
    async fn test_handler_timestamp_to_datetime_seconds() {
        // 1700000000 = 2023-11-14 22:13:20 UTC
        let (status, json) = post_json(
            "/timestamp-to-datetime",
            serde_json::json!({"timestamp": 1700000000}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["utc"], "2023-11-14 22:13:20");
        assert_eq!(json["unix_sec"], 1700000000);
        assert_eq!(json["unix_ms"], 1700000000000_i64);
        assert_eq!(json["weekday"], "星期二");
    }

    #[tokio::test]
    async fn test_handler_timestamp_to_datetime_milliseconds() {
        let (status, json) = post_json(
            "/timestamp-to-datetime",
            serde_json::json!({"timestamp": 1700000000123_i64}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["unix_sec"], 1700000000);
        assert_eq!(json["unix_ms"], 1700000000123_i64);
    }

    #[tokio::test]
    async fn test_handler_timestamp_with_timezone() {
        let (status, json) = post_json(
            "/timestamp-to-datetime",
            serde_json::json!({"timestamp": 1700000000, "timezone": "Asia/Shanghai"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["custom_tz"], "2023-11-15 06:13:20");
    }

    #[tokio::test]
    async fn test_handler_timestamp_epoch_zero() {
        let (status, json) = post_json(
            "/timestamp-to-datetime",
            serde_json::json!({"timestamp": 0}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["utc"], "1970-01-01 00:00:00");
    }

    // ── Handler: datetime_to_timestamp ────────────────────────

    #[tokio::test]
    async fn test_handler_datetime_to_timestamp_utc() {
        let (status, json) = post_json(
            "/datetime-to-timestamp",
            serde_json::json!({
                "datetime": "2023-11-14 22:13:20",
                "from_timezone": "UTC"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["unix_sec"], 1700000000);
        assert_eq!(json["unix_ms"], 1700000000000_i64);
    }

    #[tokio::test]
    async fn test_handler_datetime_to_timestamp_shanghai() {
        let (status, json) = post_json(
            "/datetime-to-timestamp",
            serde_json::json!({
                "datetime": "2023-11-15 06:13:20",
                "from_timezone": "Asia/Shanghai"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["unix_sec"], 1700000000);
    }

    #[tokio::test]
    async fn test_handler_datetime_invalid_format() {
        let (status, json) = post_json(
            "/datetime-to-timestamp",
            serde_json::json!({"datetime": "not-valid"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK); // error returned in body
        assert!(json["error"].is_string());
    }

    #[tokio::test]
    async fn test_handler_datetime_invalid_timezone() {
        let (status, json) = post_json(
            "/datetime-to-timestamp",
            serde_json::json!({
                "datetime": "2024-01-01 00:00:00",
                "from_timezone": "Invalid/TZ"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["error"].as_str().unwrap().contains("未知时区"));
    }

    // ── Handler: timezone_convert ─────────────────────────────

    #[tokio::test]
    async fn test_handler_timezone_convert_shanghai_to_newyork() {
        let (status, json) = post_json(
            "/timezone-convert",
            serde_json::json!({
                "datetime": "2024-01-15 12:00:00",
                "from_tz": "Asia/Shanghai",
                "to_tz": "America/New_York"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["from"], "2024-01-15 12:00:00");
        // Shanghai UTC+8 -> New York EST UTC-5 = -13h
        assert_eq!(json["to"], "2024-01-14 23:00:00");
    }

    #[tokio::test]
    async fn test_handler_timezone_convert_utc_to_tokyo() {
        let (status, json) = post_json(
            "/timezone-convert",
            serde_json::json!({
                "datetime": "2024-06-01 00:00:00",
                "from_tz": "UTC",
                "to_tz": "Asia/Tokyo"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["to"], "2024-06-01 09:00:00");
    }

    #[tokio::test]
    async fn test_handler_timezone_convert_invalid_tz() {
        let (status, json) = post_json(
            "/timezone-convert",
            serde_json::json!({
                "datetime": "2024-01-01 00:00:00",
                "from_tz": "BadTZ",
                "to_tz": "UTC"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["error"].is_string());
    }

    // ── Handler: format_convert ───────────────────────────────

    #[tokio::test]
    async fn test_handler_format_standard() {
        let (status, json) = post_json(
            "/format-convert",
            serde_json::json!({
                "datetime": "2024/01/15 13:45:30",
                "target_format": "standard"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["result"], "2024-01-15 13:45:30");
    }

    #[tokio::test]
    async fn test_handler_format_slash() {
        let (_, json) = post_json(
            "/format-convert",
            serde_json::json!({
                "datetime": "2024-01-15 13:45:30",
                "target_format": "slash"
            }),
        )
        .await;
        assert_eq!(json["result"], "2024/01/15 13:45:30");
    }

    #[tokio::test]
    async fn test_handler_format_dot() {
        let (_, json) = post_json(
            "/format-convert",
            serde_json::json!({
                "datetime": "2024-01-15 13:45:30",
                "target_format": "dot"
            }),
        )
        .await;
        assert_eq!(json["result"], "2024.01.15 13:45:30");
    }

    #[tokio::test]
    async fn test_handler_format_compact() {
        let (_, json) = post_json(
            "/format-convert",
            serde_json::json!({
                "datetime": "2024-01-15 13:45:30",
                "target_format": "compact"
            }),
        )
        .await;
        assert_eq!(json["result"], "20240115134530");
    }

    #[tokio::test]
    async fn test_handler_format_chinese() {
        let (_, json) = post_json(
            "/format-convert",
            serde_json::json!({
                "datetime": "2024-01-15 13:45:30",
                "target_format": "chinese"
            }),
        )
        .await;
        assert_eq!(json["result"], "2024年01月15日 13时45分30秒");
    }

    #[tokio::test]
    async fn test_handler_format_date_only() {
        let (_, json) = post_json(
            "/format-convert",
            serde_json::json!({
                "datetime": "2024-01-15 13:45:30",
                "target_format": "date"
            }),
        )
        .await;
        assert_eq!(json["result"], "2024-01-15");
    }

    #[tokio::test]
    async fn test_handler_format_time_only() {
        let (_, json) = post_json(
            "/format-convert",
            serde_json::json!({
                "datetime": "2024-01-15 13:45:30",
                "target_format": "time"
            }),
        )
        .await;
        assert_eq!(json["result"], "13:45:30");
    }

    #[tokio::test]
    async fn test_handler_format_iso8601() {
        let (_, json) = post_json(
            "/format-convert",
            serde_json::json!({
                "datetime": "2024-01-15 13:45:30",
                "target_format": "iso8601"
            }),
        )
        .await;
        assert_eq!(json["result"], "2024-01-15T13:45:30+00:00");
    }

    // ── Handler: now ──────────────────────────────────────────

    #[tokio::test]
    async fn test_handler_now() {
        let (status, json) = post_json("/now", serde_json::json!({})).await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["unix_sec"].is_i64());
        assert!(json["unix_ms"].is_i64());
        assert!(json["local"].is_string());
        assert!(json["utc"].is_string());
        assert!(json["iso8601"].is_string());
        assert!(json["weekday"].is_string());
        // Sanity: timestamp should be recent
        let ts = json["unix_sec"].as_i64().unwrap();
        assert!(ts > 1_700_000_000);
    }

    // ── Handler: batch_timestamp ──────────────────────────────

    #[tokio::test]
    async fn test_handler_batch_timestamp() {
        let (status, json) = post_json(
            "/batch-timestamp",
            serde_json::json!({
                "timestamps": [1700000000, 0, 1_700_000_000_123_i64]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let results = json["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0]["utc"], "2023-11-14 22:13:20");
        assert_eq!(results[1]["utc"], "1970-01-01 00:00:00");
        assert_eq!(results[2]["unix_sec"], 1700000000);
    }

    #[tokio::test]
    async fn test_handler_batch_timestamp_with_timezone() {
        let (status, json) = post_json(
            "/batch-timestamp",
            serde_json::json!({
                "timestamps": [1700000000],
                "timezone": "Asia/Tokyo"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let results = json["results"].as_array().unwrap();
        // Tokyo is UTC+9
        assert_eq!(results[0]["custom_tz"], "2023-11-15 07:13:20");
    }

    #[tokio::test]
    async fn test_handler_batch_timestamp_empty() {
        let (status, json) = post_json(
            "/batch-timestamp",
            serde_json::json!({"timestamps": []}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["results"].as_array().unwrap().len(), 0);
    }
}

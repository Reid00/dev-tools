use axum::{Json, Router, routing::post};
use comrak::{markdown_to_html, Options};
use serde::{Deserialize, Serialize};

// ── Request / Response types ───────────────────────────────────────

#[derive(Deserialize)]
pub struct RenderRequest {
    pub markdown: String,
    pub unsafe_html: Option<bool>, // allow raw HTML in markdown
}

#[derive(Serialize)]
pub struct RenderResponse {
    pub html: String,
}

// ── Handlers ───────────────────────────────────────────────────────

async fn render(Json(req): Json<RenderRequest>) -> Json<RenderResponse> {
    let mut options = Options::default();

    // Enable GFM extensions
    options.extension.strikethrough = true;
    options.extension.table = true;
    options.extension.autolink = true;
    options.extension.tasklist = true;
    options.extension.footnotes = true;
    options.extension.description_lists = true;
    options.extension.superscript = true;

    // Rendering options
    options.render.unsafe_ = req.unsafe_html.unwrap_or(false);
    options.render.github_pre_lang = true;

    let html = markdown_to_html(&req.markdown, &options);

    Json(RenderResponse { html })
}

// ── Router ─────────────────────────────────────────────────────────

pub fn router() -> Router {
    Router::new().route("/render", post(render))
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn post_render(body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let app = router();
        let req = Request::builder()
            .method("POST")
            .uri("/render")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, json)
    }

    // ── Headings ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_render_h1() {
        let (status, json) = post_render(serde_json::json!({"markdown": "# Hello"})).await;
        assert_eq!(status, StatusCode::OK);
        let html = json["html"].as_str().unwrap();
        assert!(html.contains("<h1>"), "expected <h1>, got: {}", html);
        assert!(html.contains("Hello"));
    }

    #[tokio::test]
    async fn test_render_h2_to_h6() {
        for level in 2..=6 {
            let md = format!("{} Heading {}", "#".repeat(level), level);
            let (_, json) = post_render(serde_json::json!({"markdown": md})).await;
            let html = json["html"].as_str().unwrap();
            let tag = format!("<h{}>", level);
            assert!(html.contains(&tag), "expected {} in: {}", tag, html);
        }
    }

    // ── Paragraphs & text styles ──────────────────────────────

    #[tokio::test]
    async fn test_render_paragraph() {
        let (_, json) = post_render(serde_json::json!({"markdown": "Hello world"})).await;
        let html = json["html"].as_str().unwrap();
        assert!(html.contains("<p>Hello world</p>"));
    }

    #[tokio::test]
    async fn test_render_bold() {
        let (_, json) = post_render(serde_json::json!({"markdown": "**bold text**"})).await;
        let html = json["html"].as_str().unwrap();
        assert!(html.contains("<strong>bold text</strong>"));
    }

    #[tokio::test]
    async fn test_render_italic() {
        let (_, json) = post_render(serde_json::json!({"markdown": "*italic text*"})).await;
        let html = json["html"].as_str().unwrap();
        assert!(html.contains("<em>italic text</em>"));
    }

    #[tokio::test]
    async fn test_render_strikethrough() {
        let (_, json) =
            post_render(serde_json::json!({"markdown": "~~deleted~~"})).await;
        let html = json["html"].as_str().unwrap();
        assert!(html.contains("<del>deleted</del>"));
    }

    // ── Lists ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_render_unordered_list() {
        let md = "- item 1\n- item 2\n- item 3";
        let (_, json) = post_render(serde_json::json!({"markdown": md})).await;
        let html = json["html"].as_str().unwrap();
        assert!(html.contains("<ul>"));
        assert!(html.contains("<li>"));
        assert!(html.contains("item 1"));
    }

    #[tokio::test]
    async fn test_render_ordered_list() {
        let md = "1. first\n2. second\n3. third";
        let (_, json) = post_render(serde_json::json!({"markdown": md})).await;
        let html = json["html"].as_str().unwrap();
        assert!(html.contains("<ol>"));
        assert!(html.contains("first"));
    }

    #[tokio::test]
    async fn test_render_task_list() {
        let md = "- [x] done\n- [ ] todo";
        let (_, json) = post_render(serde_json::json!({"markdown": md})).await;
        let html = json["html"].as_str().unwrap();
        assert!(html.contains("checked"), "expected checkbox in: {}", html);
    }

    // ── Code ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_render_inline_code() {
        let (_, json) =
            post_render(serde_json::json!({"markdown": "use `println!` macro"})).await;
        let html = json["html"].as_str().unwrap();
        assert!(html.contains("<code>println!</code>"));
    }

    #[tokio::test]
    async fn test_render_code_block() {
        let md = "```rust\nfn main() {}\n```";
        let (_, json) = post_render(serde_json::json!({"markdown": md})).await;
        let html = json["html"].as_str().unwrap();
        assert!(html.contains("<code"), "expected <code in: {}", html);
        assert!(html.contains("fn main()"));
    }

    #[tokio::test]
    async fn test_render_code_block_with_lang_attr() {
        let md = "```python\nprint('hi')\n```";
        let (_, json) = post_render(serde_json::json!({"markdown": md})).await;
        let html = json["html"].as_str().unwrap();
        // github_pre_lang = true means lang on <pre>
        assert!(
            html.contains("python"),
            "expected python language tag in: {}",
            html
        );
    }

    // ── Links & images ────────────────────────────────────────

    #[tokio::test]
    async fn test_render_link() {
        let md = "[Rust](https://www.rust-lang.org)";
        let (_, json) = post_render(serde_json::json!({"markdown": md})).await;
        let html = json["html"].as_str().unwrap();
        assert!(html.contains("<a href=\"https://www.rust-lang.org\">Rust</a>"));
    }

    #[tokio::test]
    async fn test_render_image() {
        let md = "![alt](https://example.com/img.png)";
        let (_, json) = post_render(serde_json::json!({"markdown": md})).await;
        let html = json["html"].as_str().unwrap();
        assert!(html.contains("<img"));
        assert!(html.contains("src=\"https://example.com/img.png\""));
        assert!(html.contains("alt=\"alt\""));
    }

    // ── Tables ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_render_table() {
        let md = "| A | B |\n|---|---|\n| 1 | 2 |";
        let (_, json) = post_render(serde_json::json!({"markdown": md})).await;
        let html = json["html"].as_str().unwrap();
        assert!(html.contains("<table>"));
        assert!(html.contains("<th>"));
        assert!(html.contains("<td>"));
    }

    // ── Blockquote ────────────────────────────────────────────

    #[tokio::test]
    async fn test_render_blockquote() {
        let md = "> This is a quote";
        let (_, json) = post_render(serde_json::json!({"markdown": md})).await;
        let html = json["html"].as_str().unwrap();
        assert!(html.contains("<blockquote>"));
        assert!(html.contains("This is a quote"));
    }

    // ── Horizontal rule ───────────────────────────────────────

    #[tokio::test]
    async fn test_render_hr() {
        let md = "above\n\n---\n\nbelow";
        let (_, json) = post_render(serde_json::json!({"markdown": md})).await;
        let html = json["html"].as_str().unwrap();
        assert!(html.contains("<hr"));
    }

    // ── Footnotes ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_render_footnote() {
        let md = "Text[^1]\n\n[^1]: Footnote content";
        let (_, json) = post_render(serde_json::json!({"markdown": md})).await;
        let html = json["html"].as_str().unwrap();
        assert!(
            html.contains("footnote"),
            "expected footnote in: {}",
            html
        );
    }

    // ── Superscript ───────────────────────────────────────────

    #[tokio::test]
    async fn test_render_superscript() {
        let md = "x^2^";
        let (_, json) = post_render(serde_json::json!({"markdown": md})).await;
        let html = json["html"].as_str().unwrap();
        assert!(html.contains("<sup>2</sup>"));
    }

    // ── Autolink ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_render_autolink() {
        let md = "Visit https://example.com for more";
        let (_, json) = post_render(serde_json::json!({"markdown": md})).await;
        let html = json["html"].as_str().unwrap();
        assert!(html.contains("<a href=\"https://example.com\">"));
    }

    // ── Unsafe HTML control ───────────────────────────────────

    #[tokio::test]
    async fn test_render_unsafe_html_disabled() {
        let md = "<script>alert('xss')</script>";
        let (_, json) = post_render(serde_json::json!({"markdown": md})).await;
        let html = json["html"].as_str().unwrap();
        // When unsafe is disabled, raw HTML should be stripped
        assert!(
            !html.contains("<script>"),
            "script tag should be stripped: {}",
            html
        );
    }

    #[tokio::test]
    async fn test_render_unsafe_html_enabled() {
        let md = "<div class=\"custom\">content</div>";
        let (_, json) =
            post_render(serde_json::json!({"markdown": md, "unsafe_html": true})).await;
        let html = json["html"].as_str().unwrap();
        assert!(
            html.contains("<div class=\"custom\">"),
            "expected raw HTML when unsafe is enabled: {}",
            html
        );
    }

    // ── Empty input ───────────────────────────────────────────

    #[tokio::test]
    async fn test_render_empty() {
        let (status, json) = post_render(serde_json::json!({"markdown": ""})).await;
        assert_eq!(status, StatusCode::OK);
        let html = json["html"].as_str().unwrap();
        assert!(html.is_empty() || html.trim().is_empty());
    }

    // ── Chinese content ───────────────────────────────────────

    #[tokio::test]
    async fn test_render_chinese_content() {
        let md = "# 你好世界\n\n这是一段**中文**内容。";
        let (_, json) = post_render(serde_json::json!({"markdown": md})).await;
        let html = json["html"].as_str().unwrap();
        assert!(html.contains("你好世界"));
        assert!(html.contains("<strong>中文</strong>"));
    }

    // ── Complex document ──────────────────────────────────────

    #[tokio::test]
    async fn test_render_complex_document() {
        let md = r#"# Title

Some **bold** and *italic* text.

- Item 1
- Item 2

```rust
fn main() {}
```

| Col1 | Col2 |
|------|------|
| A    | B    |

> Quote here

---

[Link](https://example.com)
"#;
        let (status, json) = post_render(serde_json::json!({"markdown": md})).await;
        assert_eq!(status, StatusCode::OK);
        let html = json["html"].as_str().unwrap();
        assert!(html.contains("<h1>"));
        assert!(html.contains("<strong>"));
        assert!(html.contains("<em>"));
        assert!(html.contains("<ul>"));
        assert!(html.contains("<code"), "expected <code in: {}", html);
        assert!(html.contains("<table>"));
        assert!(html.contains("<blockquote>"));
        assert!(html.contains("<hr"));
        assert!(html.contains("<a href"));
    }
}

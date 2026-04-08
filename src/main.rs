mod tools;

use axum::Router;
use axum::response::Html;
use axum::routing::get;
use tower_http::cors::{Any, CorsLayer};

const INDEX_HTML: &str = include_str!("../static/index.html");

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(index))
        .nest("/api/time", tools::time_convert::router())
        .nest("/api/json", tools::json_tools::router())
        .nest("/api/translate", tools::translate::router())
        .nest("/api/markdown", tools::markdown::router())
        .nest("/api/http", tools::http_client::router())
        .nest("/api/sub", tools::sub_convert::router())
        .layer(cors);

    let addr = "0.0.0.0:3000";
    tracing::info!("Server running at http://localhost:3000");
    println!("🚀 Dev Tools 已启动: http://localhost:3000");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

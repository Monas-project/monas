use axum::{routing::get, Router};

async fn health() -> &'static str {
    "ok"
}

pub fn create_router() -> Router {
    Router::new().route("/health", get(health))
}

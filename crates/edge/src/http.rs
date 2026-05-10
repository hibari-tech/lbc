//! Edge HTTP API.
//!
//! Phase 0: liveness + version probes. Real CRUD endpoints land in §0.6.

use axum::routing::get;
use axum::Json;
use axum::Router;
use serde_json::{json, Value};

pub fn router() -> Router {
    let api_v1 = Router::new()
        .route("/healthz", get(healthz))
        .route("/version", get(version));
    Router::new()
        .route("/healthz", get(healthz))
        .nest("/api/v1", api_v1)
}

async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn version() -> Json<Value> {
    Json(json!({
        "name": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

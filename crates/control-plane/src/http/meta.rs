//! Stateless meta endpoints + OpenAPI.

use axum::Json;
use serde_json::{json, Value};
use utoipa::OpenApi as _;

use super::openapi::ApiDoc;

pub async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

pub async fn version() -> Json<Value> {
    Json(json!({
        "name": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

pub async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

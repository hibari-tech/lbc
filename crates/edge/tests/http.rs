//! Integration tests for the edge HTTP layer.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt as _;

#[tokio::test]
async fn healthz_returns_ok() {
    let response = edge::http::router()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("router service");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&body).expect("parse json");
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn api_v1_version_reports_crate_metadata() {
    let response = edge::http::router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/version")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("router service");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&body).expect("parse json");
    assert_eq!(json["name"], "edge");
    assert!(json["version"].is_string());
}

#[tokio::test]
async fn unknown_route_is_404() {
    let response = edge::http::router()
        .oneshot(
            Request::builder()
                .uri("/nope")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("router service");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

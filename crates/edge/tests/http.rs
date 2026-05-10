//! Integration tests for the edge HTTP layer.

mod common;

use axum::body::{to_bytes, Body};
use axum::http::header::AUTHORIZATION;
use axum::http::{Request, StatusCode};
use edge::auth::token;
use edge::auth::Role;
use serde_json::Value;
use sqlx::Row;
use tower::ServiceExt as _;

use common::{test_app, TEST_TTL_SECS};

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("parse json")
}

#[tokio::test]
async fn healthz_returns_ok() {
    let app = test_app().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn api_v1_version_reports_crate_metadata() {
    let app = test_app().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/version")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["name"], "edge");
    assert!(json["version"].is_string());
}

#[tokio::test]
async fn unknown_route_is_404() {
    let app = test_app().await;
    let resp = app
        .router
        .clone()
        .oneshot(Request::builder().uri("/nope").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn default_branch_exists_after_open() {
    let app = test_app().await;
    let row = sqlx::query("SELECT id, name, status FROM branch WHERE id = 1")
        .fetch_one(app.db.pool())
        .await
        .expect("default branch row");
    let id: i64 = row.try_get("id").unwrap();
    let name: String = row.try_get("name").unwrap();
    let status: String = row.try_get("status").unwrap();
    assert_eq!(id, 1);
    assert_eq!(name, "default");
    assert_eq!(status, "active");
}

#[tokio::test]
async fn openapi_json_lists_auth_paths() {
    let app = test_app().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let paths = json["paths"].as_object().expect("paths object");
    assert!(paths.contains_key("/api/v1/auth/login"));
    assert!(paths.contains_key("/api/v1/auth/me"));
}

#[tokio::test]
async fn login_returns_token_for_valid_credentials() {
    let app = test_app().await;
    edge::admin::seed_user(&app.db, "alice@example.com", "pw1234", Role::Admin)
        .await
        .expect("seed");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"email":"alice@example.com","password":"pw1234"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json["token"].is_string());
    assert_eq!(json["user"]["email"], "alice@example.com");
    assert_eq!(json["user"]["role"], "admin");
    let claims = token::verify(
        &app.jwt_secret,
        json["token"].as_str().expect("token string"),
    )
    .expect("verify");
    assert_eq!(claims.role, Role::Admin);
    assert!(claims.exp > claims.iat);
}

#[tokio::test]
async fn login_rejects_wrong_password_with_unauthorized() {
    let app = test_app().await;
    edge::admin::seed_user(&app.db, "alice@example.com", "correct", Role::Admin)
        .await
        .expect("seed");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"email":"alice@example.com","password":"wrong"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_rejects_unknown_email_with_unauthorized() {
    let app = test_app().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"email":"ghost@example.com","password":"x"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn me_returns_current_user_when_token_present() {
    let app = test_app().await;
    let id = edge::admin::seed_user(&app.db, "bob@example.com", "pw", Role::Manager)
        .await
        .expect("seed");
    let token = token::issue(
        &app.jwt_secret,
        id,
        Role::Manager,
        i64::try_from(TEST_TTL_SECS).unwrap(),
    )
    .expect("issue");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["id"], id);
    assert_eq!(json["email"], "bob@example.com");
    assert_eq!(json["role"], "manager");
}

#[tokio::test]
async fn me_rejects_missing_authorization_header() {
    let app = test_app().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn me_rejects_expired_token() {
    let app = test_app().await;
    let id = edge::admin::seed_user(&app.db, "eve@example.com", "pw", Role::Viewer)
        .await
        .expect("seed");
    let expired = token::issue(&app.jwt_secret, id, Role::Viewer, -3600).expect("issue");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header(AUTHORIZATION, format!("Bearer {expired}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

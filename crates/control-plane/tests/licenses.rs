//! End-to-end Control Plane license tests.

mod common;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use shared::license::SignedLicense;
use sqlx::Row;
use tower::ServiceExt as _;

use common::{seed_account_and_key, test_app};

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("parse json")
}

fn post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn activate_issues_signed_license_that_verifies() {
    let app = test_app().await;
    let key = seed_account_and_key(&app.db, "acme", "pro", 2).await;

    let resp = app
        .router
        .clone()
        .oneshot(post(
            "/api/v1/licenses/activate",
            json!({
                "license_key": key,
                "branch_name": "store-1",
                "hardware_fingerprint": "FP-AAA-001",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let issued_id = body["issued_license_id"].as_i64().expect("id");
    assert!(issued_id > 0);
    assert_eq!(body["branch_id"], 1);

    let signed: SignedLicense =
        serde_json::from_value(body["license"].clone()).expect("decode signed license");
    assert_eq!(signed.payload.tier, shared::license::Tier::Pro);
    assert_eq!(signed.payload.branch_count, 2);
    assert_eq!(signed.payload.hardware_fingerprint, "FP-AAA-001");
    assert_eq!(signed.payload.grace_period_days, 30);

    let pubkey = app.signer.public_key_bytes();
    signed.verify(&pubkey).expect("signature verifies");
}

#[tokio::test]
async fn activate_rejects_unknown_key() {
    let app = test_app().await;
    let resp = app
        .router
        .clone()
        .oneshot(post(
            "/api/v1/licenses/activate",
            json!({
                "license_key": "no-such-key",
                "branch_name": "store-1",
                "hardware_fingerprint": "FP",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn activate_enforces_branch_count_cap() {
    let app = test_app().await;
    let key = seed_account_and_key(&app.db, "small", "starter", 1).await;

    let first = app
        .router
        .clone()
        .oneshot(post(
            "/api/v1/licenses/activate",
            json!({
                "license_key": key,
                "branch_name": "store-1",
                "hardware_fingerprint": "FP-1",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let second = app
        .router
        .clone()
        .oneshot(post(
            "/api/v1/licenses/activate",
            json!({
                "license_key": key,
                "branch_name": "store-2",
                "hardware_fingerprint": "FP-2",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn activate_is_idempotent_per_branch() {
    let app = test_app().await;
    let key = seed_account_and_key(&app.db, "loop", "starter", 1).await;
    for _ in 0..3 {
        let resp = app
            .router
            .clone()
            .oneshot(post(
                "/api/v1/licenses/activate",
                json!({
                    "license_key": key,
                    "branch_name": "store-1",
                    "hardware_fingerprint": "FP",
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let issued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM issued_license")
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(
        issued, 3,
        "every activation creates a row even when re-activating the same branch"
    );
}

#[tokio::test]
async fn revoke_marks_issued_license_revoked() {
    let app = test_app().await;
    let key = seed_account_and_key(&app.db, "revoke-co", "pro", 1).await;
    let activate = app
        .router
        .clone()
        .oneshot(post(
            "/api/v1/licenses/activate",
            json!({
                "license_key": key,
                "branch_name": "store-1",
                "hardware_fingerprint": "FP",
            }),
        ))
        .await
        .unwrap();
    let body = body_json(activate).await;
    let issued_id = body["issued_license_id"].as_i64().unwrap();

    let revoke = app
        .router
        .clone()
        .oneshot(post(
            &format!("/api/v1/licenses/{issued_id}/revoke"),
            Value::Null,
        ))
        .await
        .unwrap();
    assert_eq!(revoke.status(), StatusCode::NO_CONTENT);

    let row = sqlx::query("SELECT revoked_at FROM issued_license WHERE id = ?")
        .bind(issued_id)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    let revoked_at: Option<i64> = row.try_get("revoked_at").unwrap();
    assert!(revoked_at.is_some());
}

#[tokio::test]
async fn revoke_unknown_id_returns_404() {
    let app = test_app().await;
    let resp = app
        .router
        .clone()
        .oneshot(post("/api/v1/licenses/9999/revoke", Value::Null))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn signed_license_rejects_wrong_public_key() {
    let app = test_app().await;
    let key = seed_account_and_key(&app.db, "wrongkey", "pro", 1).await;
    let resp = app
        .router
        .clone()
        .oneshot(post(
            "/api/v1/licenses/activate",
            json!({
                "license_key": key,
                "branch_name": "s",
                "hardware_fingerprint": "F",
            }),
        ))
        .await
        .unwrap();
    let body = body_json(resp).await;
    let signed: SignedLicense = serde_json::from_value(body["license"].clone()).unwrap();
    let other = control_plane::signing::LicenseSigner::ephemeral();
    assert!(signed.verify(&other.public_key_bytes()).is_err());
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
    assert_eq!(body_json(resp).await["status"], "ok");
}

#[tokio::test]
async fn openapi_lists_license_paths() {
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
    let json = body_json(resp).await;
    let paths = json["paths"].as_object().unwrap();
    assert!(paths.contains_key("/api/v1/licenses/activate"));
    assert!(paths.contains_key("/api/v1/licenses/{id}/revoke"));
}

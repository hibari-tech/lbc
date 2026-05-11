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

fn post_with_bearer(uri: &str, body: Value, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
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

/// Activate and return `(issued_license_id, heartbeat_token)`. The
/// token is needed by every subsequent heartbeat call.
async fn activate(app: &common::TestApp, key: &str, branch: &str, fp: &str) -> (i64, String) {
    let resp = app
        .router
        .clone()
        .oneshot(post(
            "/api/v1/licenses/activate",
            json!({
                "license_key": key,
                "branch_name": branch,
                "hardware_fingerprint": fp,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let id = body["issued_license_id"].as_i64().unwrap();
    let token = body["heartbeat_token"]
        .as_str()
        .expect("activation response must include heartbeat_token")
        .to_string();
    (id, token)
}

#[tokio::test]
async fn heartbeat_updates_last_seen() {
    let app = test_app().await;
    let key = seed_account_and_key(&app.db, "hb", "pro", 1).await;
    let (id, token) = activate(&app, &key, "store", "FP-001").await;

    let before: Option<i64> =
        sqlx::query_scalar("SELECT last_seen FROM issued_license WHERE id = ?")
            .bind(id)
            .fetch_one(app.db.pool())
            .await
            .unwrap();
    assert!(before.is_none());

    let resp = app
        .router
        .clone()
        .oneshot(post_with_bearer(
            &format!("/api/v1/licenses/{id}/heartbeat"),
            json!({"hardware_fingerprint":"FP-001"}),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert!(body["last_seen"].as_i64().unwrap() > 0);

    let after: i64 = sqlx::query_scalar("SELECT last_seen FROM issued_license WHERE id = ?")
        .bind(id)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(after, body["last_seen"].as_i64().unwrap());
}

#[tokio::test]
async fn heartbeat_rejects_fingerprint_mismatch() {
    let app = test_app().await;
    let key = seed_account_and_key(&app.db, "hb-mis", "pro", 1).await;
    let (id, token) = activate(&app, &key, "store", "ORIG-FP").await;
    let resp = app
        .router
        .clone()
        .oneshot(post_with_bearer(
            &format!("/api/v1/licenses/{id}/heartbeat"),
            json!({"hardware_fingerprint":"OTHER-FP"}),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn heartbeat_after_revoke_returns_410() {
    let app = test_app().await;
    let key = seed_account_and_key(&app.db, "hb-rev", "pro", 1).await;
    let (id, token) = activate(&app, &key, "store", "FP").await;
    let revoke = app
        .router
        .clone()
        .oneshot(post(&format!("/api/v1/licenses/{id}/revoke"), Value::Null))
        .await
        .unwrap();
    assert_eq!(revoke.status(), StatusCode::NO_CONTENT);

    let resp = app
        .router
        .clone()
        .oneshot(post_with_bearer(
            &format!("/api/v1/licenses/{id}/heartbeat"),
            json!({"hardware_fingerprint":"FP"}),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::GONE);
}

#[tokio::test]
async fn heartbeat_unknown_id_returns_401() {
    // Pre-Bearer-gate this was 404; with the gate, we 401 before
    // touching the DB so id enumeration over the heartbeat endpoint
    // is no easier than guessing the secret.
    let app = test_app().await;
    let token = "0".repeat(64); // any well-formed token shape
    let resp = app
        .router
        .clone()
        .oneshot(post_with_bearer(
            "/api/v1/licenses/9999/heartbeat",
            json!({"hardware_fingerprint":"X"}),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn activate_response_includes_heartbeat_token() {
    let app = test_app().await;
    let key = seed_account_and_key(&app.db, "tok", "pro", 1).await;
    let resp = app
        .router
        .clone()
        .oneshot(post(
            "/api/v1/licenses/activate",
            json!({
                "license_key": key,
                "branch_name": "store",
                "hardware_fingerprint": "FP",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let token = body["heartbeat_token"]
        .as_str()
        .expect("heartbeat_token field present");
    // 32 random bytes hex-encoded.
    assert_eq!(token.len(), 64, "expected 64 hex chars, got {token:?}");
    assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
}

#[tokio::test]
async fn heartbeat_without_bearer_returns_401() {
    let app = test_app().await;
    let key = seed_account_and_key(&app.db, "hb-noauth", "pro", 1).await;
    let (id, _token) = activate(&app, &key, "store", "FP").await;
    let resp = app
        .router
        .clone()
        .oneshot(post(
            &format!("/api/v1/licenses/{id}/heartbeat"),
            json!({"hardware_fingerprint":"FP"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn heartbeat_with_wrong_bearer_returns_401() {
    let app = test_app().await;
    let key = seed_account_and_key(&app.db, "hb-wrong", "pro", 1).await;
    let (id, _real_token) = activate(&app, &key, "store", "FP").await;
    // Well-formed hex of the right length but not the real secret.
    let wrong = "ff".repeat(32);
    let resp = app
        .router
        .clone()
        .oneshot(post_with_bearer(
            &format!("/api/v1/licenses/{id}/heartbeat"),
            json!({"hardware_fingerprint":"FP"}),
            &wrong,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn heartbeat_with_malformed_bearer_returns_401() {
    let app = test_app().await;
    let key = seed_account_and_key(&app.db, "hb-malformed", "pro", 1).await;
    let (id, _real_token) = activate(&app, &key, "store", "FP").await;
    let resp = app
        .router
        .clone()
        .oneshot(post_with_bearer(
            &format!("/api/v1/licenses/{id}/heartbeat"),
            json!({"hardware_fingerprint":"FP"}),
            "not-hex!!",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn legacy_row_with_unknown_hash_cannot_heartbeat() {
    // Simulate a row written before the bearer-gate migration: the
    // migration backfills random bytes that have no known preimage,
    // so no client-presented token can match. New activations get a
    // fresh hash whose preimage *is* known to the activator.
    let app = test_app().await;
    let key = seed_account_and_key(&app.db, "hb-legacy", "pro", 1).await;
    let (id, real_token) = activate(&app, &key, "store", "FP").await;
    // Overwrite the row's hash with random bytes — simulates a legacy
    // row that survived the migration.
    sqlx::query("UPDATE issued_license SET heartbeat_secret_hash = randomblob(32) WHERE id = ?")
        .bind(id)
        .execute(app.db.pool())
        .await
        .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(post_with_bearer(
            &format!("/api/v1/licenses/{id}/heartbeat"),
            json!({"hardware_fingerprint":"FP"}),
            &real_token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
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
    assert!(paths.contains_key("/api/v1/licenses/{id}/heartbeat"));
    assert!(paths.contains_key("/api/v1/licenses/{id}/revoke"));
}

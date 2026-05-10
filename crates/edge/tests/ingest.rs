//! Integration tests for the webhook ingest endpoint.

mod common;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use sqlx::Row;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt as _;

use common::test_app;

const TEST_SECRET: &str = "shared-secret-for-testing-only";

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn sign(secret: &str, ts_ms: i64, body: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(ts_ms.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let bytes = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

async fn seed_device_with_secret(db: &edge::storage::Db, secret: Option<&str>) -> i64 {
    let row = sqlx::query(
        "INSERT INTO device (branch_id, kind, status, webhook_secret, created_at) \
         VALUES (1, 'camera', 'online', ?, 0) RETURNING id",
    )
    .bind(secret)
    .fetch_one(db.pool())
    .await
    .expect("insert device");
    row.try_get("id").unwrap()
}

fn ingest_request(device_id: i64, ts_ms: i64, sig: &str, body: &[u8]) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/ingest/webhooks/{device_id}"))
        .header("content-type", "application/json")
        .header("x-lbc-timestamp", ts_ms.to_string())
        .header("x-lbc-signature", sig)
        .body(Body::from(body.to_vec()))
        .unwrap()
}

#[tokio::test]
async fn webhook_happy_path_persists_event() {
    let app = test_app().await;
    let device_id = seed_device_with_secret(&app.db, Some(TEST_SECRET)).await;
    let ts = now_ms();
    let body = br#"{"kind":"motion","zone":"front-door"}"#;
    let sig = sign(TEST_SECRET, ts, body);
    let resp = app
        .router
        .clone()
        .oneshot(ingest_request(device_id, ts, &sig, body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let event_id = json["event_id"].as_i64().expect("event_id");
    assert!(event_id > 0);

    let row = sqlx::query("SELECT kind, ts, payload FROM event WHERE id = ?")
        .bind(event_id)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    let kind: String = row.try_get("kind").unwrap();
    let ts_stored: i64 = row.try_get("ts").unwrap();
    let payload_text: String = row.try_get("payload").unwrap();
    assert_eq!(kind, "motion");
    assert_eq!(ts_stored, ts);
    let payload: Value = serde_json::from_str(&payload_text).unwrap();
    assert_eq!(payload["zone"], "front-door");
}

#[tokio::test]
async fn webhook_wrong_signature_rejected() {
    let app = test_app().await;
    let device_id = seed_device_with_secret(&app.db, Some(TEST_SECRET)).await;
    let ts = now_ms();
    let body = br#"{"kind":"motion"}"#;
    let bad_sig = sign("DIFFERENT-SECRET", ts, body);
    let resp = app
        .router
        .clone()
        .oneshot(ingest_request(device_id, ts, &bad_sig, body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM event")
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0, "no event must be persisted on bad signature");
}

#[tokio::test]
async fn webhook_stale_timestamp_rejected() {
    let app = test_app().await;
    let device_id = seed_device_with_secret(&app.db, Some(TEST_SECRET)).await;
    let ts = now_ms() - 10 * 60 * 1000; // 10 minutes ago
    let body = br#"{"kind":"motion"}"#;
    let sig = sign(TEST_SECRET, ts, body);
    let resp = app
        .router
        .clone()
        .oneshot(ingest_request(device_id, ts, &sig, body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_future_timestamp_rejected() {
    let app = test_app().await;
    let device_id = seed_device_with_secret(&app.db, Some(TEST_SECRET)).await;
    let ts = now_ms() + 10 * 60 * 1000;
    let body = br#"{"kind":"motion"}"#;
    let sig = sign(TEST_SECRET, ts, body);
    let resp = app
        .router
        .clone()
        .oneshot(ingest_request(device_id, ts, &sig, body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_unknown_device_returns_404() {
    let app = test_app().await;
    let ts = now_ms();
    let body = br#"{}"#;
    let sig = sign(TEST_SECRET, ts, body);
    let resp = app
        .router
        .clone()
        .oneshot(ingest_request(9999, ts, &sig, body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn webhook_device_without_secret_rejected() {
    let app = test_app().await;
    let device_id = seed_device_with_secret(&app.db, None).await;
    let ts = now_ms();
    let body = br#"{"kind":"motion"}"#;
    let sig = sign(TEST_SECRET, ts, body);
    let resp = app
        .router
        .clone()
        .oneshot(ingest_request(device_id, ts, &sig, body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_missing_signature_header_rejected() {
    let app = test_app().await;
    let device_id = seed_device_with_secret(&app.db, Some(TEST_SECRET)).await;
    let ts = now_ms();
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/ingest/webhooks/{device_id}"))
        .header("content-type", "application/json")
        .header("x-lbc-timestamp", ts.to_string())
        .body(Body::from(r#"{}"#))
        .unwrap();
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_kind_defaults_to_webhook_when_payload_lacks_it() {
    let app = test_app().await;
    let device_id = seed_device_with_secret(&app.db, Some(TEST_SECRET)).await;
    let ts = now_ms();
    let body = br#"{"foo":"bar"}"#;
    let sig = sign(TEST_SECRET, ts, body);
    let resp = app
        .router
        .clone()
        .oneshot(ingest_request(device_id, ts, &sig, body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let event_id = body_json(resp).await["event_id"].as_i64().unwrap();
    let kind: String = sqlx::query_scalar("SELECT kind FROM event WHERE id = ?")
        .bind(event_id)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(kind, "webhook");
}

#[tokio::test]
async fn webhook_invalid_body_json_returns_400() {
    let app = test_app().await;
    let device_id = seed_device_with_secret(&app.db, Some(TEST_SECRET)).await;
    let ts = now_ms();
    let body = b"not json at all";
    let sig = sign(TEST_SECRET, ts, body);
    let resp = app
        .router
        .clone()
        .oneshot(ingest_request(device_id, ts, &sig, body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

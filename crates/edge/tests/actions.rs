//! End-to-end action-layer tests: rule fires → HTTP action dispatched
//! → response captured → action_log row persisted.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use edge::actions::{dispatch, ActionRequest, ActionResult};
use edge::rules::{evaluate_event, RuleEngine};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::Row;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;
use tower::ServiceExt as _;

use common::test_app;

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

#[derive(Clone, Default)]
struct EchoState {
    received: Arc<Mutex<Vec<Value>>>,
}

async fn echo_handler(State(state): State<EchoState>, Json(body): Json<Value>) -> Json<Value> {
    state.received.lock().unwrap().push(body.clone());
    Json(json!({ "ack": true, "echoed": body }))
}

async fn fail_handler() -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"oops":true})),
    )
}

struct EchoServer {
    addr: SocketAddr,
    state: EchoState,
    _shutdown: oneshot::Sender<()>,
}

async fn spawn_echo() -> EchoServer {
    let state = EchoState::default();
    let app = Router::new()
        .route("/notify", post(echo_handler))
        .route("/boom", post(fail_handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await;
    });
    // Wait for it to come up.
    for _ in 0..20 {
        if reqwest::Client::new()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    EchoServer {
        addr,
        state,
        _shutdown: tx,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn action_dispatch_persists_action_log_row() {
    let app = test_app().await;
    let echo = spawn_echo().await;
    let url = format!("http://{}/notify", echo.addr);

    // Manually create a rule_run so dispatch has a parent FK.
    let rule_id: i64 = sqlx::query_scalar(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'manual', 1, '{}', 1, 0, 0) RETURNING id",
    )
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    let rule_run_id: i64 = sqlx::query_scalar(
        "INSERT INTO rule_run (rule_id, fired_at, input_event_ids, outcomes) \
         VALUES (?, 0, '[]', '{}') RETURNING id",
    )
    .bind(rule_id)
    .fetch_one(app.db.pool())
    .await
    .unwrap();

    let action = ActionRequest {
        kind: "http".into(),
        target: url,
        method: Some("POST".into()),
        headers: Default::default(),
        body: Some(json!({ "alert": "motion" })),
    };
    let ActionResult { ok, status, .. } = dispatch(&app.db, rule_run_id, &action).await.unwrap();
    assert!(ok);
    assert_eq!(status, 200);

    let received = echo.state.received.lock().unwrap().clone();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0]["alert"], "motion");

    let row = sqlx::query("SELECT kind, target, status FROM action_log WHERE rule_run_id = ?")
        .bind(rule_run_id)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    let kind: String = row.try_get("kind").unwrap();
    let status_str: String = row.try_get("status").unwrap();
    assert_eq!(kind, "http");
    assert_eq!(status_str, "ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn action_dispatch_records_failure_for_5xx() {
    let app = test_app().await;
    let echo = spawn_echo().await;
    let url = format!("http://{}/boom", echo.addr);

    let rule_id: i64 = sqlx::query_scalar(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'manual', 1, '{}', 1, 0, 0) RETURNING id",
    )
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    let rule_run_id: i64 = sqlx::query_scalar(
        "INSERT INTO rule_run (rule_id, fired_at, input_event_ids, outcomes) \
         VALUES (?, 0, '[]', '{}') RETURNING id",
    )
    .bind(rule_id)
    .fetch_one(app.db.pool())
    .await
    .unwrap();

    let action = ActionRequest {
        kind: "http".into(),
        target: url,
        method: Some("POST".into()),
        headers: Default::default(),
        body: Some(json!({})),
    };
    let result = dispatch(&app.db, rule_run_id, &action).await.unwrap();
    assert!(!result.ok);
    assert_eq!(result.status, 500);
    let status_str: String =
        sqlx::query_scalar("SELECT status FROM action_log WHERE rule_run_id = ?")
            .bind(rule_run_id)
            .fetch_one(app.db.pool())
            .await
            .unwrap();
    assert_eq!(status_str, "error");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn action_dispatch_records_transport_error() {
    let app = test_app().await;
    // Bind+drop to grab a port nobody listens on.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let rule_id: i64 = sqlx::query_scalar(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'manual', 1, '{}', 1, 0, 0) RETURNING id",
    )
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    let rule_run_id: i64 = sqlx::query_scalar(
        "INSERT INTO rule_run (rule_id, fired_at, input_event_ids, outcomes) \
         VALUES (?, 0, '[]', '{}') RETURNING id",
    )
    .bind(rule_id)
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    let action = ActionRequest {
        kind: "http".into(),
        target: format!("http://{addr}/never"),
        method: Some("POST".into()),
        headers: Default::default(),
        body: None,
    };
    let result = dispatch(&app.db, rule_run_id, &action).await.unwrap();
    assert!(!result.ok);
    assert_eq!(result.status, 0);
    assert!(result.response.contains("transport error"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn action_dispatch_unknown_kind_logs_error_row() {
    let app = test_app().await;
    let rule_id: i64 = sqlx::query_scalar(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'manual', 1, '{}', 1, 0, 0) RETURNING id",
    )
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    let rule_run_id: i64 = sqlx::query_scalar(
        "INSERT INTO rule_run (rule_id, fired_at, input_event_ids, outcomes) \
         VALUES (?, 0, '[]', '{}') RETURNING id",
    )
    .bind(rule_id)
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    let action = ActionRequest {
        kind: "smtp".into(),
        target: "ops@example.com".into(),
        method: None,
        headers: Default::default(),
        body: None,
    };
    let result = dispatch(&app.db, rule_run_id, &action).await.unwrap();
    assert!(!result.ok);
    assert!(result.response.contains("unsupported"));
    let status: String = sqlx::query_scalar("SELECT status FROM action_log WHERE rule_run_id = ?")
        .bind(rule_run_id)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(status, "error");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rule_returning_actions_fires_them_via_dispatcher() {
    let app = test_app().await;
    let echo = spawn_echo().await;
    let url = format!("http://{}/notify", echo.addr);

    let event_id: i64 = sqlx::query_scalar(
        "INSERT INTO event (branch_id, kind, ts, payload, ingest_ts) \
         VALUES (1, 'motion', 100, '{\"zone\":\"front-door\"}', 100) RETURNING id",
    )
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    let script = format!(
        r##"
        if event.kind == "motion" {{
            return #{{
                actions: [
                    #{{
                        kind: "http",
                        target: "{url}",
                        method: "POST",
                        body: #{{ alert: event.payload.zone }}
                    }}
                ]
            }};
        }}
        false
        "##
    );
    let definition = serde_json::to_string(&json!({ "script": script })).unwrap();
    sqlx::query(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'on-motion', 1, ?, 1, 0, 0)",
    )
    .bind(&definition)
    .execute(app.db.pool())
    .await
    .unwrap();

    let engine = RuleEngine::new();
    let report = evaluate_event(&app.db, &engine, 1, event_id).await.unwrap();
    assert_eq!(report.matched_rule_ids.len(), 1);

    let received = echo.state.received.lock().unwrap().clone();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0]["alert"], "front-door");

    let action_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM action_log WHERE status = 'ok' AND kind = 'http'")
            .fetch_one(app.db.pool())
            .await
            .unwrap();
    assert_eq!(action_rows, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_to_end_webhook_to_action_log() {
    let app = test_app().await;
    let echo = spawn_echo().await;
    let url = format!("http://{}/notify", echo.addr);

    let secret = "shared-test-secret-shared-test";
    let device_id: i64 = sqlx::query_scalar(
        "INSERT INTO device (branch_id, kind, status, webhook_secret, created_at) \
         VALUES (1, 'camera', 'online', ?, 0) RETURNING id",
    )
    .bind(secret)
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    let script = format!(
        r##"
        if event.kind == "motion" {{
            return #{{
                actions: [
                    #{{ kind: "http", target: "{url}", body: #{{ device: event.device_id }} }}
                ]
            }};
        }}
        false
        "##
    );
    let definition = serde_json::to_string(&json!({ "script": script })).unwrap();
    sqlx::query(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'on-motion', 1, ?, 1, 0, 0)",
    )
    .bind(&definition)
    .execute(app.db.pool())
    .await
    .unwrap();

    let ts = now_ms();
    let body = br#"{"kind":"motion","zone":"front-door"}"#;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(ts.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let sig_bytes = mac.finalize().into_bytes();
    let mut sig = String::with_capacity(sig_bytes.len() * 2);
    for b in sig_bytes {
        sig.push_str(&format!("{b:02x}"));
    }
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/ingest/webhooks/{device_id}"))
        .header("content-type", "application/json")
        .header("x-lbc-timestamp", ts.to_string())
        .header("x-lbc-signature", sig)
        .body(Body::from(body.to_vec()))
        .unwrap();
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = to_bytes(resp.into_body(), 1024).await.unwrap();

    let received = echo.state.received.lock().unwrap().clone();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0]["device"], device_id);
    let action_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM action_log")
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(action_rows, 1);
}

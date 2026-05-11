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
use edge::actions::{dispatch, ActionRequest, ActionResult, ActionsConfig};
use edge::rules::{evaluate_event, RuleEngine};

fn allow_private() -> ActionsConfig {
    ActionsConfig {
        allow_private_targets: true,
        ..Default::default()
    }
}

fn block_private() -> ActionsConfig {
    ActionsConfig::default()
}
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
        ..Default::default()
    };
    let ActionResult { ok, status, .. } = dispatch(&app.db, &allow_private(), rule_run_id, &action)
        .await
        .unwrap();
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
        ..Default::default()
    };
    let result = dispatch(&app.db, &allow_private(), rule_run_id, &action)
        .await
        .unwrap();
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
        ..Default::default()
    };
    let result = dispatch(&app.db, &allow_private(), rule_run_id, &action)
        .await
        .unwrap();
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
        // http/smtp/mqtt/modbus/ftp are supported; pick something still pending.
        kind: "nx".into(),
        target: "nx://server/event".into(),
        method: None,
        headers: Default::default(),
        body: None,
        ..Default::default()
    };
    let result = dispatch(&app.db, &allow_private(), rule_run_id, &action)
        .await
        .unwrap();
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
async fn action_dispatch_blocks_loopback_when_disallowed() {
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
        kind: "http".into(),
        target: "http://127.0.0.1:9/never".into(),
        method: Some("POST".into()),
        headers: Default::default(),
        body: None,
        ..Default::default()
    };
    let result = dispatch(&app.db, &block_private(), rule_run_id, &action)
        .await
        .unwrap();
    assert!(!result.ok);
    assert_eq!(result.status, 0);
    assert!(
        result.response.contains("blocked"),
        "expected blocked response, got: {}",
        result.response
    );
    let status: String = sqlx::query_scalar("SELECT status FROM action_log WHERE rule_run_id = ?")
        .bind(rule_run_id)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(status, "error");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn action_dispatch_blocks_disallowed_scheme() {
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
        kind: "http".into(),
        target: "file:///etc/passwd".into(),
        method: Some("GET".into()),
        headers: Default::default(),
        body: None,
        ..Default::default()
    };
    let result = dispatch(&app.db, &block_private(), rule_run_id, &action)
        .await
        .unwrap();
    assert!(!result.ok);
    assert!(
        result.response.contains("scheme") || result.response.contains("not allowed"),
        "expected scheme rejection, got: {}",
        result.response
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn action_dispatch_blocks_link_local_metadata_endpoint() {
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
        kind: "http".into(),
        // Cloud-metadata endpoint — covered by is_link_local on 169.254/16.
        target: "http://169.254.169.254/latest/meta-data/".into(),
        method: Some("GET".into()),
        headers: Default::default(),
        body: None,
        ..Default::default()
    };
    let result = dispatch(&app.db, &block_private(), rule_run_id, &action)
        .await
        .unwrap();
    assert!(!result.ok);
    assert!(
        result.response.contains("blocked"),
        "expected blocked response, got: {}",
        result.response
    );
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
    let report = evaluate_event(&app.db, &engine, &allow_private(), 1, event_id)
        .await
        .unwrap();
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

// --- SMTP -----------------------------------------------------------------

use edge::actions::smtp::build_message;
use edge::actions::SmtpConfig;

fn smtp_cfg_with(server: &str, from_default: &str) -> SmtpConfig {
    SmtpConfig {
        server: server.into(),
        port: 587,
        from_default: from_default.into(),
        ..Default::default()
    }
}

#[test]
fn smtp_build_message_uses_action_fields() {
    let cfg = smtp_cfg_with("smtp.example.com", "ops@example.com");
    let action = ActionRequest {
        kind: "smtp".into(),
        to: vec!["alice@example.com".into(), "bob@example.com".into()],
        subject: Some("Hello".into()),
        body: Some(json!("plain text body")),
        ..Default::default()
    };
    let msg = build_message(&action, &cfg).expect("build");
    let bytes = msg.formatted();
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("From: ops@example.com"));
    // Lettre combines multiple recipients into a single `To:` header.
    assert!(text.contains("alice@example.com"));
    assert!(text.contains("bob@example.com"));
    assert!(text.contains("Subject: Hello"));
    assert!(text.contains("plain text body"));
}

#[test]
fn smtp_build_message_uses_action_from_over_default() {
    let cfg = smtp_cfg_with("smtp.example.com", "default@example.com");
    let action = ActionRequest {
        kind: "smtp".into(),
        to: vec!["x@example.com".into()],
        subject: Some("y".into()),
        from: Some("custom@example.com".into()),
        body: Some(json!("z")),
        ..Default::default()
    };
    let msg = build_message(&action, &cfg).expect("build");
    let text = String::from_utf8_lossy(&msg.formatted()).to_string();
    assert!(text.contains("From: custom@example.com"));
    assert!(!text.contains("From: default@example.com"));
}

#[test]
fn smtp_build_message_requires_recipients() {
    let cfg = smtp_cfg_with("smtp.example.com", "ops@example.com");
    let action = ActionRequest {
        kind: "smtp".into(),
        to: vec![],
        subject: Some("y".into()),
        body: Some(json!("z")),
        ..Default::default()
    };
    let err = build_message(&action, &cfg).unwrap_err();
    assert!(err.contains("recipient"), "got: {err}");
}

#[test]
fn smtp_build_message_requires_from_address() {
    let cfg = smtp_cfg_with("smtp.example.com", "");
    let action = ActionRequest {
        kind: "smtp".into(),
        to: vec!["x@example.com".into()],
        subject: Some("y".into()),
        body: Some(json!("z")),
        ..Default::default()
    };
    let err = build_message(&action, &cfg).unwrap_err();
    assert!(err.contains("From"), "got: {err}");
}

#[test]
fn smtp_build_message_jsonifies_non_string_body() {
    let cfg = smtp_cfg_with("smtp.example.com", "ops@example.com");
    let action = ActionRequest {
        kind: "smtp".into(),
        to: vec!["x@example.com".into()],
        subject: Some("y".into()),
        body: Some(json!({ "alert": "motion", "zone": "front-door" })),
        ..Default::default()
    };
    let msg = build_message(&action, &cfg).expect("build");
    let text = String::from_utf8_lossy(&msg.formatted()).to_string();
    assert!(text.contains("alert") && text.contains("motion"));
    assert!(text.contains("front-door"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_dispatch_with_no_server_configured_records_error() {
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
    // test_app() default ActionsConfig has smtp.server empty.
    let action = ActionRequest {
        kind: "smtp".into(),
        to: vec!["x@example.com".into()],
        subject: Some("y".into()),
        body: Some(json!("z")),
        ..Default::default()
    };
    let cfg = ActionsConfig {
        allow_private_targets: true,
        smtp: SmtpConfig::default(), // empty
        ..Default::default()
    };
    let result = dispatch(&app.db, &cfg, rule_run_id, &action).await.unwrap();
    assert!(!result.ok);
    assert!(
        result.response.contains("not configured"),
        "got: {}",
        result.response
    );
    let status: String = sqlx::query_scalar("SELECT status FROM action_log WHERE rule_run_id = ?")
        .bind(rule_run_id)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(status, "error");
}

// --- MQTT -----------------------------------------------------------------

use edge::actions::mqtt::{plan_publish, PublishPlan};
use edge::actions::MqttConfig;

#[test]
fn mqtt_plan_publish_extracts_topic_and_defaults() {
    let action = ActionRequest {
        kind: "mqtt".into(),
        topic: Some("lbc/branch/1/alerts".into()),
        body: Some(json!("payload-as-string")),
        ..Default::default()
    };
    let plan = plan_publish(&action).expect("plan");
    assert_eq!(plan.topic, "lbc/branch/1/alerts");
    assert!(matches!(plan.qos, rumqttc::QoS::AtMostOnce));
    assert!(!plan.retain);
    assert_eq!(plan.payload, b"payload-as-string");
}

#[test]
fn mqtt_plan_publish_honours_qos_and_retain() {
    let action = ActionRequest {
        kind: "mqtt".into(),
        topic: Some("t".into()),
        qos: Some(2),
        retain: Some(true),
        body: Some(json!({ "k": "v" })),
        ..Default::default()
    };
    let plan = plan_publish(&action).expect("plan");
    assert!(matches!(plan.qos, rumqttc::QoS::ExactlyOnce));
    assert!(plan.retain);
    // JSON object body is stringified.
    let s = std::str::from_utf8(&plan.payload).unwrap();
    assert!(s.contains("\"k\""));
    assert!(s.contains("\"v\""));
}

#[test]
fn mqtt_plan_publish_rejects_invalid_qos() {
    let action = ActionRequest {
        kind: "mqtt".into(),
        topic: Some("t".into()),
        qos: Some(3),
        ..Default::default()
    };
    let err = plan_publish(&action).unwrap_err();
    assert!(err.contains("QoS"), "got: {err}");
}

#[test]
fn mqtt_plan_publish_requires_topic() {
    let action = ActionRequest {
        kind: "mqtt".into(),
        ..Default::default()
    };
    let err = plan_publish(&action).unwrap_err();
    assert!(err.contains("topic"), "got: {err}");
}

#[test]
fn mqtt_plan_publish_empty_topic_rejected() {
    let action = ActionRequest {
        kind: "mqtt".into(),
        topic: Some(String::new()),
        ..Default::default()
    };
    assert!(plan_publish(&action).is_err());
}

#[test]
fn mqtt_plan_publish_null_body_empty_payload() {
    let action = ActionRequest {
        kind: "mqtt".into(),
        topic: Some("t".into()),
        ..Default::default()
    };
    let plan: PublishPlan = plan_publish(&action).expect("plan");
    assert!(plan.payload.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mqtt_dispatch_with_no_server_configured_records_error() {
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
        kind: "mqtt".into(),
        topic: Some("alerts".into()),
        body: Some(json!("hi")),
        ..Default::default()
    };
    let cfg = ActionsConfig {
        mqtt: MqttConfig::default(), // empty server
        ..Default::default()
    };
    let result = dispatch(&app.db, &cfg, rule_run_id, &action).await.unwrap();
    assert!(!result.ok);
    assert!(
        result.response.contains("not configured"),
        "got: {}",
        result.response
    );
    let status: String = sqlx::query_scalar("SELECT status FROM action_log WHERE rule_run_id = ?")
        .bind(rule_run_id)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(status, "error");
}

// --- modbus plan_request --------------------------------------------------

#[test]
fn modbus_plan_request_write_coil_with_bool_body() {
    use edge::actions::modbus::{plan_request, ModbusOp};
    let action = ActionRequest {
        kind: "modbus".into(),
        target: "10.0.0.5:502".into(),
        function: Some("write_coil".into()),
        unit_id: Some(2),
        address: Some(42),
        body: Some(json!(true)),
        ..Default::default()
    };
    let plan = plan_request(&action).expect("plan");
    assert_eq!(plan.unit_id, 2);
    assert_eq!(plan.address, 42);
    assert_eq!(plan.op, ModbusOp::WriteCoil(true));
}

#[test]
fn modbus_plan_request_write_register_with_int_body() {
    use edge::actions::modbus::{plan_request, ModbusOp};
    let action = ActionRequest {
        kind: "modbus".into(),
        target: "10.0.0.5:502".into(),
        function: Some("write_register".into()),
        address: Some(100),
        body: Some(json!(1234)),
        ..Default::default()
    };
    let plan = plan_request(&action).expect("plan");
    assert_eq!(plan.unit_id, 1, "unit_id defaults to 1");
    assert_eq!(plan.op, ModbusOp::WriteRegister(1234));
}

#[test]
fn modbus_plan_request_rejects_empty_target() {
    use edge::actions::modbus::plan_request;
    let action = ActionRequest {
        kind: "modbus".into(),
        function: Some("write_coil".into()),
        address: Some(0),
        body: Some(json!(true)),
        ..Default::default()
    };
    let err = plan_request(&action).unwrap_err();
    assert!(err.contains("target"), "expected target error, got: {err}");
}

#[test]
fn modbus_plan_request_rejects_non_socketaddr_target() {
    use edge::actions::modbus::plan_request;
    let action = ActionRequest {
        kind: "modbus".into(),
        target: "plc.example.com:502".into(),
        function: Some("write_coil".into()),
        address: Some(0),
        body: Some(json!(true)),
        ..Default::default()
    };
    let err = plan_request(&action).unwrap_err();
    assert!(
        err.contains("SocketAddr"),
        "expected SocketAddr error, got: {err}"
    );
}

#[test]
fn modbus_plan_request_rejects_missing_function() {
    use edge::actions::modbus::plan_request;
    let action = ActionRequest {
        kind: "modbus".into(),
        target: "10.0.0.5:502".into(),
        address: Some(0),
        body: Some(json!(true)),
        ..Default::default()
    };
    let err = plan_request(&action).unwrap_err();
    assert!(
        err.contains("function"),
        "expected function error, got: {err}"
    );
}

#[test]
fn modbus_plan_request_rejects_unsupported_function() {
    use edge::actions::modbus::plan_request;
    let action = ActionRequest {
        kind: "modbus".into(),
        target: "10.0.0.5:502".into(),
        function: Some("read_coils".into()),
        address: Some(0),
        body: Some(json!(0)),
        ..Default::default()
    };
    let err = plan_request(&action).unwrap_err();
    assert!(
        err.contains("unsupported"),
        "expected unsupported error, got: {err}"
    );
}

#[test]
fn modbus_plan_request_rejects_missing_address() {
    use edge::actions::modbus::plan_request;
    let action = ActionRequest {
        kind: "modbus".into(),
        target: "10.0.0.5:502".into(),
        function: Some("write_register".into()),
        body: Some(json!(1)),
        ..Default::default()
    };
    let err = plan_request(&action).unwrap_err();
    assert!(
        err.contains("address"),
        "expected address error, got: {err}"
    );
}

#[test]
fn modbus_plan_request_rejects_register_out_of_range() {
    use edge::actions::modbus::plan_request;
    let action = ActionRequest {
        kind: "modbus".into(),
        target: "10.0.0.5:502".into(),
        function: Some("write_register".into()),
        address: Some(0),
        body: Some(json!(70_000)),
        ..Default::default()
    };
    let err = plan_request(&action).unwrap_err();
    assert!(err.contains("range"), "expected range error, got: {err}");
}

#[test]
fn modbus_plan_request_rejects_unit_id_above_247() {
    use edge::actions::modbus::plan_request;
    let action = ActionRequest {
        kind: "modbus".into(),
        target: "10.0.0.5:502".into(),
        function: Some("write_coil".into()),
        unit_id: Some(255),
        address: Some(0),
        body: Some(json!(true)),
        ..Default::default()
    };
    let err = plan_request(&action).unwrap_err();
    assert!(
        err.contains("unit_id"),
        "expected unit_id error, got: {err}"
    );
}

#[test]
fn modbus_plan_request_coil_accepts_integer_zero_one() {
    use edge::actions::modbus::{plan_request, ModbusOp};
    let on = ActionRequest {
        kind: "modbus".into(),
        target: "10.0.0.5:502".into(),
        function: Some("write_coil".into()),
        address: Some(0),
        body: Some(json!(1)),
        ..Default::default()
    };
    let off = ActionRequest {
        body: Some(json!(0)),
        ..on.clone()
    };
    assert_eq!(plan_request(&on).unwrap().op, ModbusOp::WriteCoil(true));
    assert_eq!(plan_request(&off).unwrap().op, ModbusOp::WriteCoil(false));
}

// --- FTP plan_request -----------------------------------------------------

#[test]
fn ftp_plan_request_extracts_url_components() {
    use edge::actions::ftp::plan_request;
    let action = ActionRequest {
        kind: "ftp".into(),
        target: "ftp://alice:s3cret@10.0.5.10:2121/incoming/alert.json".into(),
        body: Some(json!("payload")),
        ..Default::default()
    };
    let plan = plan_request(&action).expect("plan");
    assert_eq!(plan.host, "10.0.5.10");
    assert_eq!(plan.port, 2121);
    assert_eq!(plan.username, "alice");
    assert_eq!(plan.password, "s3cret");
    assert_eq!(plan.path, "/incoming/alert.json");
    assert_eq!(plan.payload, b"payload");
}

#[test]
fn ftp_plan_request_uses_default_port_21() {
    use edge::actions::ftp::plan_request;
    let action = ActionRequest {
        kind: "ftp".into(),
        target: "ftp://alice:p@host.example.com/x.txt".into(),
        body: Some(json!("hi")),
        ..Default::default()
    };
    let plan = plan_request(&action).expect("plan");
    assert_eq!(plan.port, 21);
    assert_eq!(plan.host, "host.example.com");
}

#[test]
fn ftp_plan_request_anonymous_when_no_userinfo() {
    use edge::actions::ftp::plan_request;
    let action = ActionRequest {
        kind: "ftp".into(),
        target: "ftp://nas.local/drop/x.json".into(),
        body: Some(json!("hi")),
        ..Default::default()
    };
    let plan = plan_request(&action).expect("plan");
    assert_eq!(plan.username, "anonymous");
    assert_eq!(plan.password, "anonymous@");
}

#[test]
fn ftp_plan_request_rejects_empty_target() {
    use edge::actions::ftp::plan_request;
    let action = ActionRequest {
        kind: "ftp".into(),
        body: Some(json!("hi")),
        ..Default::default()
    };
    let err = plan_request(&action).unwrap_err();
    assert!(err.contains("target"), "got: {err}");
}

#[test]
fn ftp_plan_request_rejects_non_ftp_scheme() {
    use edge::actions::ftp::plan_request;
    let action = ActionRequest {
        kind: "ftp".into(),
        target: "http://10.0.0.1/x".into(),
        body: Some(json!("hi")),
        ..Default::default()
    };
    let err = plan_request(&action).unwrap_err();
    assert!(err.contains("ftp://"), "got: {err}");
}

#[test]
fn ftp_plan_request_rejects_missing_path() {
    use edge::actions::ftp::plan_request;
    let action = ActionRequest {
        kind: "ftp".into(),
        target: "ftp://nas.local/".into(),
        body: Some(json!("hi")),
        ..Default::default()
    };
    let err = plan_request(&action).unwrap_err();
    assert!(err.contains("path"), "got: {err}");
}

#[test]
fn ftp_plan_request_rejects_missing_body() {
    use edge::actions::ftp::plan_request;
    let action = ActionRequest {
        kind: "ftp".into(),
        target: "ftp://nas.local/x.json".into(),
        body: None,
        ..Default::default()
    };
    let err = plan_request(&action).unwrap_err();
    assert!(err.contains("body"), "got: {err}");
}

#[test]
fn ftp_plan_request_string_body_uses_raw_bytes() {
    use edge::actions::ftp::plan_request;
    let action = ActionRequest {
        kind: "ftp".into(),
        target: "ftp://nas.local/x.txt".into(),
        body: Some(json!("hello world")),
        ..Default::default()
    };
    let plan = plan_request(&action).expect("plan");
    assert_eq!(plan.payload, b"hello world");
}

#[test]
fn ftp_plan_request_json_object_body_stringified() {
    use edge::actions::ftp::plan_request;
    let action = ActionRequest {
        kind: "ftp".into(),
        target: "ftp://nas.local/alert.json".into(),
        body: Some(json!({ "alert": "motion", "zone": "front" })),
        ..Default::default()
    };
    let plan = plan_request(&action).expect("plan");
    let s = std::str::from_utf8(&plan.payload).unwrap();
    assert!(s.contains("\"alert\""));
    assert!(s.contains("\"motion\""));
    assert!(s.contains("\"front\""));
}

#[test]
fn ftp_parse_pasv_extracts_addr() {
    use edge::actions::ftp::parse_pasv;
    let addr = parse_pasv("227 Entering Passive Mode (192,168,1,5,200,21)\r\n").unwrap();
    assert_eq!(addr, "192.168.1.5:51221");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ftp_dispatch_records_error_on_unreachable_target() {
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
    // 127.0.0.1:1 — TCP refused, fast failure.
    let action = ActionRequest {
        kind: "ftp".into(),
        target: "ftp://127.0.0.1:1/nope.txt".into(),
        body: Some(json!("hi")),
        ..Default::default()
    };
    let result = dispatch(&app.db, &allow_private(), rule_run_id, &action)
        .await
        .unwrap();
    assert!(!result.ok);
    let status: String = sqlx::query_scalar("SELECT status FROM action_log WHERE rule_run_id = ?")
        .bind(rule_run_id)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(status, "error");
    let kind: String = sqlx::query_scalar("SELECT kind FROM action_log WHERE rule_run_id = ?")
        .bind(rule_run_id)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(kind, "ftp");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modbus_dispatch_records_error_on_unreachable_target() {
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
    // 127.0.0.1:1 — TCP refused, fast failure.
    let action = ActionRequest {
        kind: "modbus".into(),
        target: "127.0.0.1:1".into(),
        function: Some("write_coil".into()),
        unit_id: Some(1),
        address: Some(0),
        body: Some(json!(true)),
        ..Default::default()
    };
    let result = dispatch(&app.db, &allow_private(), rule_run_id, &action)
        .await
        .unwrap();
    assert!(!result.ok);
    let status: String = sqlx::query_scalar("SELECT status FROM action_log WHERE rule_run_id = ?")
        .bind(rule_run_id)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(status, "error");
}

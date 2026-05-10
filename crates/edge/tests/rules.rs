//! Rule engine tests — compile/evaluate primitives plus an end-to-end
//! ingest → rule-fires → rule_run-row chain.

mod common;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use edge::rules::engine::EventForRule;
use edge::rules::{evaluate_event, Outcome, RuleEngine};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::Row;
use std::time::{SystemTime, UNIX_EPOCH};
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

fn fixture_event(kind: &str, payload: Value) -> EventForRule {
    EventForRule {
        id: 1,
        kind: kind.to_string(),
        ts: 0,
        device_id: Some(7),
        payload,
    }
}

#[test]
fn engine_evaluates_simple_match() {
    let engine = RuleEngine::new();
    let script = engine
        .compile(1, r#"event.kind == "motion""#)
        .expect("compile");
    let evt = fixture_event("motion", json!({}));
    let Outcome { matched, .. } = engine.evaluate(&script, &evt).expect("eval");
    assert!(matched);
}

#[test]
fn engine_evaluates_no_match_returns_false() {
    let engine = RuleEngine::new();
    let script = engine
        .compile(2, r#"event.kind == "tamper""#)
        .expect("compile");
    let evt = fixture_event("motion", json!({}));
    let Outcome { matched, .. } = engine.evaluate(&script, &evt).expect("eval");
    assert!(!matched);
}

#[test]
fn engine_can_read_payload_fields() {
    let engine = RuleEngine::new();
    let script = engine
        .compile(
            3,
            r#"event.kind == "motion" && event.payload.zone == "front-door""#,
        )
        .expect("compile");
    let evt = fixture_event("motion", json!({ "zone": "front-door" }));
    assert!(engine.evaluate(&script, &evt).expect("eval").matched);
    let other = fixture_event("motion", json!({ "zone": "back-door" }));
    assert!(!engine.evaluate(&script, &other).expect("eval").matched);
}

#[test]
fn engine_rejects_invalid_syntax_at_compile() {
    let engine = RuleEngine::new();
    let err = engine.compile(4, "this is not rhai @#$ {{{{").unwrap_err();
    assert!(format!("{err:#}").to_lowercase().contains("rule 4"));
}

#[test]
fn engine_runaway_loops_hit_op_limit() {
    let engine = RuleEngine::new();
    let script = engine
        .compile(5, "loop { let x = 1 + 1; }")
        .expect("compile");
    let evt = fixture_event("motion", json!({}));
    let err = engine.evaluate(&script, &evt).unwrap_err();
    let msg = format!("{err:#}").to_lowercase();
    assert!(
        msg.contains("operation") || msg.contains("limit"),
        "expected op-limit error, got: {msg}"
    );
}

#[test]
fn engine_returning_zero_int_is_falsy() {
    let engine = RuleEngine::new();
    let script = engine.compile(6, "0").expect("compile");
    let evt = fixture_event("motion", json!({}));
    assert!(!engine.evaluate(&script, &evt).expect("eval").matched);
}

#[test]
fn engine_returning_nonzero_int_is_truthy() {
    let engine = RuleEngine::new();
    let script = engine.compile(7, "42").expect("compile");
    let evt = fixture_event("motion", json!({}));
    assert!(engine.evaluate(&script, &evt).expect("eval").matched);
}

#[tokio::test]
async fn dispatch_persists_rule_run_for_matching_rule() {
    let app = test_app().await;
    // Seed an event directly.
    let event_id: i64 = sqlx::query_scalar(
        "INSERT INTO event (branch_id, kind, ts, payload, ingest_ts) \
         VALUES (1, 'motion', 100, '{\"zone\":\"front-door\"}', 100) RETURNING id",
    )
    .fetch_one(app.db.pool())
    .await
    .expect("insert event");
    // Seed a matching rule.
    let definition = serde_json::to_string(&json!({
        "script": r#"event.kind == "motion""#
    }))
    .unwrap();
    let rule_id: i64 = sqlx::query_scalar(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'motion-fired', 1, ?, 1, 0, 0) RETURNING id",
    )
    .bind(&definition)
    .fetch_one(app.db.pool())
    .await
    .expect("insert rule");
    // Seed a non-matching rule.
    let other_def = serde_json::to_string(&json!({"script": r#"event.kind == "tamper""#})).unwrap();
    sqlx::query(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'tamper-only', 1, ?, 1, 0, 0)",
    )
    .bind(&other_def)
    .execute(app.db.pool())
    .await
    .unwrap();

    let engine = RuleEngine::new();
    let report = evaluate_event(&app.db, &engine, &Default::default(), 1, event_id)
        .await
        .unwrap();
    assert_eq!(report.matched_rule_ids, vec![rule_id]);

    let rows = sqlx::query("SELECT rule_id FROM rule_run")
        .fetch_all(app.db.pool())
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let got: i64 = rows[0].try_get("rule_id").unwrap();
    assert_eq!(got, rule_id);
}

#[tokio::test]
async fn dispatch_skips_rules_without_a_script_field() {
    let app = test_app().await;
    let event_id: i64 = sqlx::query_scalar(
        "INSERT INTO event (branch_id, kind, ts, payload, ingest_ts) \
         VALUES (1, 'motion', 100, '{}', 100) RETURNING id",
    )
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    let visual_def = serde_json::to_string(&json!({"trigger":"motion","when":"closed"})).unwrap();
    sqlx::query(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'visual-rule', 1, ?, 1, 0, 0)",
    )
    .bind(&visual_def)
    .execute(app.db.pool())
    .await
    .unwrap();
    let engine = RuleEngine::new();
    let report = evaluate_event(&app.db, &engine, &Default::default(), 1, event_id)
        .await
        .unwrap();
    assert!(report.matched_rule_ids.is_empty());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_run")
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn dispatch_ignores_disabled_rules() {
    let app = test_app().await;
    let event_id: i64 = sqlx::query_scalar(
        "INSERT INTO event (branch_id, kind, ts, payload, ingest_ts) \
         VALUES (1, 'motion', 100, '{}', 100) RETURNING id",
    )
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    let definition = serde_json::to_string(&json!({"script": "true"})).unwrap();
    sqlx::query(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'always', 1, ?, 0, 0, 0)",
    )
    .bind(&definition)
    .execute(app.db.pool())
    .await
    .unwrap();
    let engine = RuleEngine::new();
    let report = evaluate_event(&app.db, &engine, &Default::default(), 1, event_id)
        .await
        .unwrap();
    assert!(report.matched_rule_ids.is_empty());
}

#[tokio::test]
async fn end_to_end_webhook_fires_rule_via_router() {
    let app = test_app().await;
    let secret = "shared-test-secret-shared-test";
    // Seed a device with a webhook secret.
    let device_id: i64 = sqlx::query_scalar(
        "INSERT INTO device (branch_id, kind, status, webhook_secret, created_at) \
         VALUES (1, 'camera', 'online', ?, 0) RETURNING id",
    )
    .bind(secret)
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    // Seed a rule that matches motion events.
    let definition = serde_json::to_string(&json!({
        "script": r#"event.kind == "motion""#
    }))
    .unwrap();
    let rule_id: i64 = sqlx::query_scalar(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'on-motion', 1, ?, 1, 0, 0) RETURNING id",
    )
    .bind(&definition)
    .fetch_one(app.db.pool())
    .await
    .unwrap();

    // Sign and POST a webhook.
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

    // The runtime fires the rule synchronously after the event insert,
    // so by the time the response returns, rule_run is durable.
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    let event_id = json["event_id"].as_i64().unwrap();
    let rows = sqlx::query("SELECT rule_id, input_event_ids FROM rule_run")
        .fetch_all(app.db.pool())
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "rule should have fired exactly once");
    let got_rule: i64 = rows[0].try_get("rule_id").unwrap();
    let inputs_text: String = rows[0].try_get("input_event_ids").unwrap();
    let inputs: Vec<i64> = serde_json::from_str(&inputs_text).unwrap();
    assert_eq!(got_rule, rule_id);
    assert_eq!(inputs, vec![event_id]);
}

//! Rule engine tests — compile/evaluate primitives plus an end-to-end
//! ingest → rule-fires → rule_run-row chain.

mod common;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use edge::rules::engine::EventForRule;
use edge::rules::scheduler::{evaluate_scheduled, next_after, parse_schedule};
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

// --- AST cache + throttle ------------------------------------------------

#[test]
fn engine_cache_returns_same_ast_until_version_bumps() {
    let engine = RuleEngine::new();
    let _ = engine
        .compile_or_fetch(1, 1, r#"event.kind == "motion""#)
        .expect("compile v1");
    let after_first = engine.compiles_observed();
    assert_eq!(after_first, 1);

    // Same (rule_id, version, src) — must hit the cache.
    let _ = engine
        .compile_or_fetch(1, 1, r#"event.kind == "motion""#)
        .expect("cache hit");
    assert_eq!(engine.compiles_observed(), after_first);

    // Bump version — must recompile.
    let _ = engine
        .compile_or_fetch(1, 2, r#"event.kind == "tamper""#)
        .expect("compile v2");
    assert_eq!(engine.compiles_observed(), after_first + 1);
}

#[test]
fn engine_cache_separates_by_rule_id() {
    let engine = RuleEngine::new();
    let _ = engine.compile_or_fetch(1, 1, "true").expect("rule 1");
    let _ = engine.compile_or_fetch(2, 1, "false").expect("rule 2");
    assert_eq!(engine.compiles_observed(), 2);
    let _ = engine.compile_or_fetch(1, 1, "true").expect("hit 1");
    let _ = engine.compile_or_fetch(2, 1, "false").expect("hit 2");
    assert_eq!(engine.compiles_observed(), 2);
}

#[test]
fn engine_records_and_reads_last_fired_at() {
    let engine = RuleEngine::new();
    let _ = engine.compile_or_fetch(7, 1, "true").unwrap();
    assert_eq!(engine.last_fired_at(7), None);
    engine.record_fire(7, 12345);
    assert_eq!(engine.last_fired_at(7), Some(12345));
    engine.record_fire(7, 99_999);
    assert_eq!(engine.last_fired_at(7), Some(99_999));
}

async fn seed_event(db: &edge::storage::Db, ts: i64) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO event (branch_id, kind, ts, payload, ingest_ts) \
         VALUES (1, 'motion', ?, '{}', ?) RETURNING id",
    )
    .bind(ts)
    .bind(ts)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

#[tokio::test]
async fn dispatch_cache_avoids_recompiling_across_invocations() {
    let app = test_app().await;
    let definition = serde_json::to_string(&json!({
        "script": r#"event.kind == "motion""#
    }))
    .unwrap();
    sqlx::query(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'cached', 1, ?, 1, 0, 0)",
    )
    .bind(&definition)
    .execute(app.db.pool())
    .await
    .unwrap();
    let engine = RuleEngine::new();
    for _ in 0..5 {
        let event_id = seed_event(&app.db, 100).await;
        let _ = evaluate_event(&app.db, &engine, &Default::default(), 1, event_id)
            .await
            .unwrap();
    }
    assert_eq!(
        engine.compiles_observed(),
        1,
        "5 evaluations of an unchanged rule should compile exactly once"
    );
}

#[tokio::test]
async fn dispatch_cache_invalidates_on_version_bump() {
    let app = test_app().await;
    let v1 = serde_json::to_string(&json!({"script": "true"})).unwrap();
    let rule_id: i64 = sqlx::query_scalar(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'bump', 1, ?, 1, 0, 0) RETURNING id",
    )
    .bind(&v1)
    .fetch_one(app.db.pool())
    .await
    .unwrap();

    let engine = RuleEngine::new();
    let event_id = seed_event(&app.db, 100).await;
    let _ = evaluate_event(&app.db, &engine, &Default::default(), 1, event_id)
        .await
        .unwrap();
    assert_eq!(engine.compiles_observed(), 1);

    // Bump version + change script.
    let v2 = serde_json::to_string(&json!({"script": "false"})).unwrap();
    sqlx::query("UPDATE rule SET version = 2, definition = ? WHERE id = ?")
        .bind(&v2)
        .bind(rule_id)
        .execute(app.db.pool())
        .await
        .unwrap();
    let event_id = seed_event(&app.db, 200).await;
    let _ = evaluate_event(&app.db, &engine, &Default::default(), 1, event_id)
        .await
        .unwrap();
    assert_eq!(
        engine.compiles_observed(),
        2,
        "version bump must trigger a recompile"
    );
}

#[tokio::test]
async fn dispatch_throttle_suppresses_repeat_fires() {
    let app = test_app().await;
    let definition = serde_json::to_string(&json!({
        "script": "true",
        "throttle_secs": 3600,
    }))
    .unwrap();
    sqlx::query(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'noisy', 1, ?, 1, 0, 0)",
    )
    .bind(&definition)
    .execute(app.db.pool())
    .await
    .unwrap();
    let engine = RuleEngine::new();
    for ts in [100, 200, 300, 400] {
        let event_id = seed_event(&app.db, ts).await;
        let _ = evaluate_event(&app.db, &engine, &Default::default(), 1, event_id)
            .await
            .unwrap();
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_run")
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(
        count, 1,
        "throttle should let the first event fire and suppress the rest"
    );
}

#[tokio::test]
async fn dispatch_without_throttle_fires_every_event() {
    let app = test_app().await;
    let definition = serde_json::to_string(&json!({"script": "true"})).unwrap();
    sqlx::query(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'unthrottled', 1, ?, 1, 0, 0)",
    )
    .bind(&definition)
    .execute(app.db.pool())
    .await
    .unwrap();
    let engine = RuleEngine::new();
    for ts in [100, 200, 300] {
        let event_id = seed_event(&app.db, ts).await;
        let _ = evaluate_event(&app.db, &engine, &Default::default(), 1, event_id)
            .await
            .unwrap();
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_run")
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 3);
}

#[test]
fn engine_records_and_reads_last_match_at() {
    let engine = RuleEngine::new();
    // Need a cache entry first.
    engine.compile_or_fetch(11, 1, "true").expect("compile");
    assert!(engine.last_match_at(11).is_none());
    engine.record_match(11, 12345);
    assert_eq!(engine.last_match_at(11), Some(12345));
    engine.record_match(11, 67890);
    assert_eq!(engine.last_match_at(11), Some(67890));
}

#[tokio::test]
async fn dispatch_debounce_suppresses_matches_within_burst() {
    let app = test_app().await;
    let definition = serde_json::to_string(&json!({
        "script": r#"event.kind == "motion""#,
        "debounce_secs": 3600,
    }))
    .unwrap();
    let rule_id: i64 = sqlx::query_scalar(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'debounce', 1, ?, 1, 0, 0) RETURNING id",
    )
    .bind(&definition)
    .fetch_one(app.db.pool())
    .await
    .unwrap();

    let engine = RuleEngine::new();
    // Five events in quick succession; only the first should fire.
    for _ in 0..5 {
        let event_id: i64 = sqlx::query_scalar(
            "INSERT INTO event (branch_id, kind, ts, payload, ingest_ts) \
             VALUES (1, 'motion', 0, '{}', 0) RETURNING id",
        )
        .fetch_one(app.db.pool())
        .await
        .unwrap();
        let _ = evaluate_event(&app.db, &engine, &Default::default(), 1, event_id)
            .await
            .unwrap();
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_run WHERE rule_id = ?")
        .bind(rule_id)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 1, "leading-edge debounce fires only on burst start");
}

#[tokio::test]
async fn dispatch_debounce_fires_again_after_quiet_window() {
    let app = test_app().await;
    let definition = serde_json::to_string(&json!({
        "script": r#"event.kind == "motion""#,
        "debounce_secs": 1,
    }))
    .unwrap();
    let rule_id: i64 = sqlx::query_scalar(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'debounce-restart', 1, ?, 1, 0, 0) RETURNING id",
    )
    .bind(&definition)
    .fetch_one(app.db.pool())
    .await
    .unwrap();

    let engine = RuleEngine::new();
    // First match — burst start, fires.
    let e1: i64 = sqlx::query_scalar(
        "INSERT INTO event (branch_id, kind, ts, payload, ingest_ts) \
         VALUES (1, 'motion', 0, '{}', 0) RETURNING id",
    )
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    evaluate_event(&app.db, &engine, &Default::default(), 1, e1)
        .await
        .unwrap();
    // Simulate a quiet window: backdate last_match_at far enough that
    // the next match looks like a new burst.
    engine.record_match(rule_id, 0);
    let e2: i64 = sqlx::query_scalar(
        "INSERT INTO event (branch_id, kind, ts, payload, ingest_ts) \
         VALUES (1, 'motion', 0, '{}', 0) RETURNING id",
    )
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    evaluate_event(&app.db, &engine, &Default::default(), 1, e2)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_run WHERE rule_id = ?")
        .bind(rule_id)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 2, "second burst after quiet window must fire");
}

#[tokio::test]
async fn dispatch_without_debounce_unchanged() {
    let app = test_app().await;
    let definition = serde_json::to_string(&json!({
        "script": r#"event.kind == "motion""#,
    }))
    .unwrap();
    sqlx::query(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'no-debounce', 1, ?, 1, 0, 0)",
    )
    .bind(&definition)
    .execute(app.db.pool())
    .await
    .unwrap();
    let engine = RuleEngine::new();
    for _ in 0..3 {
        let event_id: i64 = sqlx::query_scalar(
            "INSERT INTO event (branch_id, kind, ts, payload, ingest_ts) \
             VALUES (1, 'motion', 0, '{}', 0) RETURNING id",
        )
        .fetch_one(app.db.pool())
        .await
        .unwrap();
        evaluate_event(&app.db, &engine, &Default::default(), 1, event_id)
            .await
            .unwrap();
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_run")
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 3);
}

#[test]
fn engine_records_clears_and_reads_hold_start() {
    let engine = RuleEngine::new();
    engine.compile_or_fetch(101, 1, "true").expect("compile");
    assert!(engine.hold_start_at(101).is_none());
    engine.set_hold_start(101, 1000);
    assert_eq!(engine.hold_start_at(101), Some(1000));
    engine.clear_hold(101);
    assert!(engine.hold_start_at(101).is_none());
}

#[tokio::test]
async fn dispatch_hold_for_first_match_does_not_fire() {
    let app = test_app().await;
    let definition = serde_json::to_string(&json!({
        "script": r#"event.kind == "motion""#,
        "hold_for_secs": 30,
    }))
    .unwrap();
    sqlx::query(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'hold-once', 1, ?, 1, 0, 0)",
    )
    .bind(&definition)
    .execute(app.db.pool())
    .await
    .unwrap();
    let engine = RuleEngine::new();
    let event_id: i64 = sqlx::query_scalar(
        "INSERT INTO event (branch_id, kind, ts, payload, ingest_ts) \
         VALUES (1, 'motion', 0, '{}', 0) RETURNING id",
    )
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    let _ = evaluate_event(&app.db, &engine, &Default::default(), 1, event_id)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_run")
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0, "first match starts the streak; doesn't fire");
}

#[tokio::test]
async fn dispatch_hold_for_within_window_does_not_fire() {
    let app = test_app().await;
    let definition = serde_json::to_string(&json!({
        "script": r#"event.kind == "motion""#,
        "hold_for_secs": 3600,
    }))
    .unwrap();
    sqlx::query(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'hold-burst', 1, ?, 1, 0, 0)",
    )
    .bind(&definition)
    .execute(app.db.pool())
    .await
    .unwrap();
    let engine = RuleEngine::new();
    // Five rapid matches — streak starts at the first, none fire because
    // wall-clock can't possibly advance 3600 s in this loop.
    for _ in 0..5 {
        let event_id: i64 = sqlx::query_scalar(
            "INSERT INTO event (branch_id, kind, ts, payload, ingest_ts) \
             VALUES (1, 'motion', 0, '{}', 0) RETURNING id",
        )
        .fetch_one(app.db.pool())
        .await
        .unwrap();
        evaluate_event(&app.db, &engine, &Default::default(), 1, event_id)
            .await
            .unwrap();
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_run")
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn dispatch_hold_for_fires_after_window() {
    let app = test_app().await;
    let definition = serde_json::to_string(&json!({
        "script": r#"event.kind == "motion""#,
        "hold_for_secs": 30,
    }))
    .unwrap();
    let rule_id: i64 = sqlx::query_scalar(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'hold-fire', 1, ?, 1, 0, 0) RETURNING id",
    )
    .bind(&definition)
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    let engine = RuleEngine::new();
    // First match — starts the streak.
    let e1: i64 = sqlx::query_scalar(
        "INSERT INTO event (branch_id, kind, ts, payload, ingest_ts) \
         VALUES (1, 'motion', 0, '{}', 0) RETURNING id",
    )
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    evaluate_event(&app.db, &engine, &Default::default(), 1, e1)
        .await
        .unwrap();
    // Backdate the streak start so the next match looks N+1 seconds later.
    engine.set_hold_start(rule_id, 0);
    let e2: i64 = sqlx::query_scalar(
        "INSERT INTO event (branch_id, kind, ts, payload, ingest_ts) \
         VALUES (1, 'motion', 0, '{}', 0) RETURNING id",
    )
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    evaluate_event(&app.db, &engine, &Default::default(), 1, e2)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_run WHERE rule_id = ?")
        .bind(rule_id)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 1, "match after hold window must fire");
    assert!(
        engine.hold_start_at(rule_id).is_none(),
        "hold cleared after fire"
    );
}

#[tokio::test]
async fn dispatch_hold_for_non_match_resets_streak() {
    let app = test_app().await;
    let definition = serde_json::to_string(&json!({
        "script": r#"event.kind == "motion""#,
        "hold_for_secs": 30,
    }))
    .unwrap();
    let rule_id: i64 = sqlx::query_scalar(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'hold-reset', 1, ?, 1, 0, 0) RETURNING id",
    )
    .bind(&definition)
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    let engine = RuleEngine::new();
    // First match — streak starts.
    let e1: i64 = sqlx::query_scalar(
        "INSERT INTO event (branch_id, kind, ts, payload, ingest_ts) \
         VALUES (1, 'motion', 0, '{}', 0) RETURNING id",
    )
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    evaluate_event(&app.db, &engine, &Default::default(), 1, e1)
        .await
        .unwrap();
    assert!(engine.hold_start_at(rule_id).is_some());
    // Non-matching event — streak resets.
    let e2: i64 = sqlx::query_scalar(
        "INSERT INTO event (branch_id, kind, ts, payload, ingest_ts) \
         VALUES (1, 'tamper', 0, '{}', 0) RETURNING id",
    )
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    evaluate_event(&app.db, &engine, &Default::default(), 1, e2)
        .await
        .unwrap();
    assert!(
        engine.hold_start_at(rule_id).is_none(),
        "non-match must clear the hold streak"
    );
    // Even after backdating, no fire should happen because the streak is None.
    let e3: i64 = sqlx::query_scalar(
        "INSERT INTO event (branch_id, kind, ts, payload, ingest_ts) \
         VALUES (1, 'motion', 0, '{}', 0) RETURNING id",
    )
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    evaluate_event(&app.db, &engine, &Default::default(), 1, e3)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_run WHERE rule_id = ?")
        .bind(rule_id)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0, "interrupted streak does not fire on resume");
    // The fresh motion event should have started a new streak.
    assert!(engine.hold_start_at(rule_id).is_some());
}

#[tokio::test]
async fn dispatch_without_hold_for_fires_on_first_match() {
    let app = test_app().await;
    let definition = serde_json::to_string(&json!({
        "script": r#"event.kind == "motion""#,
    }))
    .unwrap();
    sqlx::query(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'no-hold', 1, ?, 1, 0, 0)",
    )
    .bind(&definition)
    .execute(app.db.pool())
    .await
    .unwrap();
    let engine = RuleEngine::new();
    let event_id: i64 = sqlx::query_scalar(
        "INSERT INTO event (branch_id, kind, ts, payload, ingest_ts) \
         VALUES (1, 'motion', 0, '{}', 0) RETURNING id",
    )
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    evaluate_event(&app.db, &engine, &Default::default(), 1, event_id)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_run")
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 1, "regression: no hold_for, fire as usual");
}

// --- cron scheduler -------------------------------------------------------

#[test]
fn parse_schedule_accepts_seven_field_expression() {
    // Every 30 seconds — 7-field format (sec min hour DoM Month DoW Year).
    assert!(parse_schedule("*/30 * * * * * *").is_ok());
}

#[test]
fn parse_schedule_rejects_empty_and_garbage() {
    assert!(parse_schedule("").is_err());
    assert!(parse_schedule("   ").is_err());
    assert!(parse_schedule("not a cron").is_err());
}

#[test]
fn next_after_advances_strictly_forward() {
    let s = parse_schedule("0 0 * * * * *").expect("parse");
    // 09:30:00 UTC on some arbitrary day.
    let base_ms = 1_700_000_000_000_i64;
    let n1 = next_after(&s, base_ms).expect("next");
    assert!(n1 > base_ms, "next must be strictly after");
    let n2 = next_after(&s, n1).expect("next2");
    assert!(n2 > n1);
    // Top-of-hour granularity: n2 - n1 == 1h.
    assert_eq!(n2 - n1, 60 * 60 * 1000);
}

async fn seed_scheduled_rule(
    db: &edge::storage::Db,
    name: &str,
    script: &str,
    schedule: &str,
) -> i64 {
    let definition = serde_json::to_string(&json!({ "script": script })).unwrap();
    sqlx::query_scalar(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, schedule, created_at, updated_at) \
         VALUES (1, ?, 1, ?, 1, ?, 0, 0) RETURNING id",
    )
    .bind(name)
    .bind(&definition)
    .bind(schedule)
    .fetch_one(db.pool())
    .await
    .expect("insert scheduled rule")
}

#[tokio::test]
async fn scheduler_first_observation_seeds_without_firing() {
    let app = test_app().await;
    let rule_id = seed_scheduled_rule(&app.db, "every-minute", "true", "0 * * * * * *").await;
    let engine = RuleEngine::new();
    let report = evaluate_scheduled(&app.db, &engine, &Default::default(), 1, now_ms())
        .await
        .unwrap();
    assert!(
        report.fired_rule_ids.is_empty(),
        "first observation must not fire"
    );
    assert!(
        engine.next_fire_at(rule_id).is_some(),
        "next_fire_at should be seeded after first observation"
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_run")
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn scheduler_fires_when_next_fire_at_has_elapsed() {
    let app = test_app().await;
    let rule_id = seed_scheduled_rule(&app.db, "tick", "true", "*/5 * * * * * *").await;
    let engine = RuleEngine::new();
    // Seed via first call.
    evaluate_scheduled(&app.db, &engine, &Default::default(), 1, 1_000_000_000_000)
        .await
        .unwrap();
    let seeded = engine.next_fire_at(rule_id).expect("seeded");
    // Tick at exactly the planned fire time → fires.
    let report = evaluate_scheduled(&app.db, &engine, &Default::default(), 1, seeded)
        .await
        .unwrap();
    assert_eq!(report.fired_rule_ids, vec![rule_id]);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_run")
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 1);
    // next_fire_at advanced past the fire time.
    let after = engine.next_fire_at(rule_id).expect("advanced");
    assert!(after > seeded);
    // rule_run row has an empty input_event_ids array (scheduled, not event-driven).
    let input: String = sqlx::query_scalar("SELECT input_event_ids FROM rule_run")
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(input, "[]");
}

#[tokio::test]
async fn scheduler_does_not_fire_before_next_fire_at() {
    let app = test_app().await;
    let rule_id = seed_scheduled_rule(&app.db, "hourly", "true", "0 0 * * * * *").await;
    let engine = RuleEngine::new();
    evaluate_scheduled(&app.db, &engine, &Default::default(), 1, 1_700_000_000_000)
        .await
        .unwrap();
    let next = engine.next_fire_at(rule_id).expect("seeded");
    // Tick one millisecond before the schedule → no fire.
    let report = evaluate_scheduled(&app.db, &engine, &Default::default(), 1, next - 1)
        .await
        .unwrap();
    assert!(report.fired_rule_ids.is_empty());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_run")
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn scheduler_ignores_event_driven_rules() {
    let app = test_app().await;
    // Rule with NULL schedule — purely event-driven.
    let definition = serde_json::to_string(&json!({ "script": "true" })).unwrap();
    sqlx::query(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, created_at, updated_at) \
         VALUES (1, 'event-only', 1, ?, 1, 0, 0)",
    )
    .bind(&definition)
    .execute(app.db.pool())
    .await
    .unwrap();
    let engine = RuleEngine::new();
    let report = evaluate_scheduled(&app.db, &engine, &Default::default(), 1, now_ms())
        .await
        .unwrap();
    assert!(report.fired_rule_ids.is_empty());
}

#[tokio::test]
async fn scheduler_skips_disabled_scheduled_rules() {
    let app = test_app().await;
    let definition = serde_json::to_string(&json!({ "script": "true" })).unwrap();
    sqlx::query(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, schedule, created_at, updated_at) \
         VALUES (1, 'disabled-cron', 1, ?, 0, '*/1 * * * * * *', 0, 0)",
    )
    .bind(&definition)
    .execute(app.db.pool())
    .await
    .unwrap();
    let engine = RuleEngine::new();
    evaluate_scheduled(&app.db, &engine, &Default::default(), 1, now_ms())
        .await
        .unwrap();
    let report = evaluate_scheduled(&app.db, &engine, &Default::default(), 1, now_ms() + 60_000)
        .await
        .unwrap();
    assert!(report.fired_rule_ids.is_empty());
}

#[tokio::test]
async fn scheduler_skips_invalid_cron_expression() {
    let app = test_app().await;
    let definition = serde_json::to_string(&json!({ "script": "true" })).unwrap();
    sqlx::query(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, schedule, created_at, updated_at) \
         VALUES (1, 'broken', 1, ?, 1, 'not a cron', 0, 0)",
    )
    .bind(&definition)
    .execute(app.db.pool())
    .await
    .unwrap();
    let engine = RuleEngine::new();
    let report = evaluate_scheduled(&app.db, &engine, &Default::default(), 1, now_ms())
        .await
        .unwrap();
    assert!(report.fired_rule_ids.is_empty());
}

#[tokio::test]
async fn scheduler_recovers_after_eval_error_by_advancing_schedule() {
    let app = test_app().await;
    // Script that errors at runtime.
    let definition = serde_json::to_string(&json!({
        "script": "throw \"boom\"",
    }))
    .unwrap();
    let rule_id: i64 = sqlx::query_scalar(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, schedule, created_at, updated_at) \
         VALUES (1, 'broken-script', 1, ?, 1, '*/5 * * * * * *', 0, 0) RETURNING id",
    )
    .bind(&definition)
    .fetch_one(app.db.pool())
    .await
    .unwrap();
    let engine = RuleEngine::new();
    evaluate_scheduled(&app.db, &engine, &Default::default(), 1, 1_000_000_000_000)
        .await
        .unwrap();
    let seeded = engine.next_fire_at(rule_id).expect("seeded");
    // Fire-time tick: script errors → no rule_run row, but schedule advanced.
    let report = evaluate_scheduled(&app.db, &engine, &Default::default(), 1, seeded)
        .await
        .unwrap();
    assert!(report.fired_rule_ids.is_empty());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_run")
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
    let advanced = engine.next_fire_at(rule_id).expect("advanced");
    assert!(
        advanced > seeded,
        "schedule should advance even after eval error"
    );
}

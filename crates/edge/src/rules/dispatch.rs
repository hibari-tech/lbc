//! Run all enabled rules in a branch against a freshly-ingested event,
//! persisting `rule_run` rows for the rules that match.
//!
//! Phase 1 first slice: synchronous, in the same task that handled the
//! incoming webhook. If rules grow expensive, switch this to a Tokio
//! task spawned off an mpsc channel so ingest stays fast.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use serde_json::Value;
use sqlx::Row;

use crate::actions::{self, ActionResult, ActionsConfig};
use crate::storage::Db;

use super::engine::{EventForRule, Outcome, RuleEngine};

#[derive(Debug)]
pub struct EvaluationReport {
    pub event_id: i64,
    pub matched_rule_ids: Vec<i64>,
}

pub async fn evaluate_event(
    db: &Db,
    engine: &RuleEngine,
    actions_cfg: &ActionsConfig,
    branch_id: i64,
    event_id: i64,
) -> anyhow::Result<EvaluationReport> {
    let event = load_event(db, branch_id, event_id)
        .await
        .with_context(|| format!("loading event {event_id}"))?;

    let rules = sqlx::query(
        "SELECT id, version, definition FROM rule \
         WHERE branch_id = ? AND enabled = 1 \
         ORDER BY id ASC",
    )
    .bind(branch_id)
    .fetch_all(db.pool())
    .await
    .context("loading enabled rules")?;

    let now = now_ms();
    let mut matched = Vec::new();
    for r in rules {
        let rule_id: i64 = r.get("id");
        let version: i64 = r.get("version");
        let definition_text: String = r.get("definition");
        let Some(script_src) = extract_script(&definition_text) else {
            // Rule has no script — visual builder rules etc. land later.
            continue;
        };
        let throttle_ms = extract_throttle_ms(&definition_text);
        if let Some(window) = throttle_ms {
            if let Some(last) = engine.last_fired_at(rule_id) {
                if now.saturating_sub(last) < window {
                    tracing::debug!(rule_id, window_ms = window, "throttled; skipping");
                    continue;
                }
            }
        }
        let script = match engine.compile_or_fetch(rule_id, version, &script_src) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(rule_id, error = ?e, "rule compile failed; skipping");
                continue;
            }
        };
        let outcome = match engine.evaluate(&script, &event) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(rule_id, error = ?e, "rule eval failed; skipping");
                continue;
            }
        };
        if outcome.matched {
            let rule_run_id = persist_rule_run(db, rule_id, event_id, &outcome)
                .await
                .with_context(|| format!("persisting rule_run for rule {rule_id}"))?;
            engine.record_fire(rule_id, now);
            matched.push(rule_id);
            for action in &outcome.actions {
                match actions::dispatch(db, actions_cfg, rule_run_id, action).await {
                    Ok(ActionResult {
                        ok: false,
                        response,
                        status,
                        ..
                    }) => {
                        tracing::warn!(
                            rule_id,
                            kind = %action.kind,
                            target = %action.target,
                            status,
                            response = %response,
                            "action dispatch reported failure"
                        );
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!(
                            rule_id,
                            kind = %action.kind,
                            error = ?e,
                            "action dispatch errored"
                        );
                    }
                }
            }
        }
    }

    Ok(EvaluationReport {
        event_id,
        matched_rule_ids: matched,
    })
}

async fn load_event(db: &Db, branch_id: i64, event_id: i64) -> anyhow::Result<EventForRule> {
    let row = sqlx::query(
        "SELECT id, device_id, kind, ts, payload \
         FROM event WHERE id = ? AND branch_id = ?",
    )
    .bind(event_id)
    .bind(branch_id)
    .fetch_one(db.pool())
    .await?;
    let payload_text: String = row.get("payload");
    let payload: Value =
        serde_json::from_str(&payload_text).context("parsing event payload as JSON")?;
    Ok(EventForRule {
        id: row.get("id"),
        device_id: row.get("device_id"),
        kind: row.get("kind"),
        ts: row.get("ts"),
        payload,
    })
}

fn extract_script(definition_json: &str) -> Option<String> {
    let value: Value = serde_json::from_str(definition_json).ok()?;
    value
        .get("script")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Read `definition.throttle_secs` and convert to milliseconds. Returns
/// `None` when the rule isn't throttled (no field, zero, or negative).
fn extract_throttle_ms(definition_json: &str) -> Option<i64> {
    let value: Value = serde_json::from_str(definition_json).ok()?;
    let secs = value.get("throttle_secs")?.as_i64()?;
    if secs <= 0 {
        return None;
    }
    Some(secs.saturating_mul(1000))
}

async fn persist_rule_run(
    db: &Db,
    rule_id: i64,
    event_id: i64,
    outcome: &Outcome,
) -> anyhow::Result<i64> {
    let input_event_ids = serde_json::to_string(&[event_id]).unwrap_or_else(|_| "[]".into());
    let outcomes = serde_json::to_string(outcome).unwrap_or_else(|_| "{}".into());
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO rule_run (rule_id, fired_at, input_event_ids, outcomes) \
         VALUES (?, ?, ?, ?) RETURNING id",
    )
    .bind(rule_id)
    .bind(now_ms())
    .bind(input_event_ids)
    .bind(outcomes)
    .fetch_one(db.pool())
    .await?;
    Ok(id)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

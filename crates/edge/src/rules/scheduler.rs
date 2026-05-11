//! Cron-driven rule firing — `lbcspec.md` §4.2 time primitives, fourth
//! slice after throttle / debounce / hold-for.
//!
//! A scheduled rule is a row in `rule` whose `schedule` column is set to
//! a cron expression. The scheduler driver wakes on a fixed interval
//! (see [`crate::config::RulesConfig::cron_tick_secs`]) and, for each
//! enabled scheduled rule whose next fire time has elapsed, evaluates
//! the rule's Rhai script against a synthetic `tick` event and dispatches
//! whatever actions it returns. `rule_run` is persisted with an empty
//! `input_event_ids` array so the audit trail distinguishes scheduled
//! firings from event-driven ones.
//!
//! Format: cron 0.16 uses seven fields — `sec min hour DoM Month DoW
//! Year`. Examples:
//!
//! * `0 0 * * * * *` — top of every hour
//! * `*/15 * * * * * *` — every 15 seconds
//! * `0 0 9 * * Mon-Fri *` — 09:00 on weekdays
//!
//! Throttle / debounce / hold-for are intentionally **not** applied to
//! scheduled rules — the cron expression already controls frequency.
//!
//! State semantics on first observation: the scheduler does not fire
//! "now" if the rule is freshly seen. It computes the next fire time
//! after the current tick and waits. This avoids surprise fires after
//! an edge restart when the previous run missed a schedule.

use std::str::FromStr;

use anyhow::Context as _;
use chrono::{DateTime, TimeZone, Utc};
use cron::Schedule;
use serde_json::{json, Value};
use sqlx::Row;

use crate::actions::ActionsConfig;
use crate::storage::Db;

use super::dispatch::{dispatch_actions, extract_script, now_ms, persist_rule_run};
use super::engine::{EventForRule, RuleEngine};

#[derive(Debug, Default)]
pub struct ScheduledReport {
    pub fired_rule_ids: Vec<i64>,
}

/// Parse a cron expression. Trims whitespace; rejects empty strings.
pub fn parse_schedule(expr: &str) -> Result<Schedule, String> {
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return Err("empty schedule expression".into());
    }
    Schedule::from_str(trimmed).map_err(|e| format!("invalid cron expression {trimmed:?}: {e}"))
}

/// Next fire time strictly after `after_ms`, encoded back to unix-ms.
/// `None` means the schedule has no more occurrences in the upper bound
/// chrono uses (year 9999) — effectively impossible for any sane
/// expression, but handled defensively.
pub fn next_after(schedule: &Schedule, after_ms: i64) -> Option<i64> {
    let after: DateTime<Utc> = Utc.timestamp_millis_opt(after_ms).single()?;
    let next = schedule.after(&after).next()?;
    Some(next.timestamp_millis())
}

/// One scheduler tick: scan enabled scheduled rules in `branch_id`,
/// fire those whose next-fire time has elapsed, and seed first-time
/// observations.
pub async fn evaluate_scheduled(
    db: &Db,
    engine: &RuleEngine,
    actions_cfg: &ActionsConfig,
    branch_id: i64,
    now: i64,
) -> anyhow::Result<ScheduledReport> {
    let rules = sqlx::query(
        "SELECT id, version, definition, schedule FROM rule \
         WHERE branch_id = ? AND enabled = 1 AND schedule IS NOT NULL \
         ORDER BY id ASC",
    )
    .bind(branch_id)
    .fetch_all(db.pool())
    .await
    .context("loading scheduled rules")?;

    let mut report = ScheduledReport::default();
    for r in rules {
        let rule_id: i64 = r.get("id");
        let version: i64 = r.get("version");
        let definition_text: String = r.get("definition");
        let schedule_text: String = r.get("schedule");
        let schedule = match parse_schedule(&schedule_text) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(rule_id, schedule = %schedule_text, error = %e, "invalid cron expression; skipping");
                continue;
            }
        };
        let Some(script_src) = extract_script(&definition_text) else {
            // Scheduled rule without a script — visual builder land. Skip.
            tracing::debug!(rule_id, "scheduled rule has no script; skipping");
            continue;
        };
        let script = match engine.compile_or_fetch(rule_id, version, &script_src) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(rule_id, error = ?e, "scheduled rule compile failed; skipping");
                continue;
            }
        };
        // First-observation seed: compute next fire from now and skip
        // firing this tick — cron rules should not retroactively fire on
        // edge startup.
        let nfa = engine.next_fire_at(rule_id);
        let Some(next) = nfa else {
            if let Some(seed) = next_after(&schedule, now) {
                engine.set_next_fire_at(rule_id, seed);
                tracing::debug!(rule_id, next_fire_at = seed, "cron rule seeded");
            }
            continue;
        };
        if next > now {
            continue;
        }
        // Fire path.
        let event = EventForRule {
            id: 0,
            kind: "tick".into(),
            ts: now,
            device_id: None,
            payload: json!({}),
        };
        let outcome = match engine.evaluate(&script, &event) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(rule_id, error = ?e, "scheduled rule eval failed; skipping");
                // Still advance the schedule so we don't busy-loop on a broken rule.
                if let Some(advance) = next_after(&schedule, now) {
                    engine.set_next_fire_at(rule_id, advance);
                }
                continue;
            }
        };
        let rule_run_id = persist_rule_run(db, rule_id, &[], &outcome, now)
            .await
            .with_context(|| format!("persisting rule_run for scheduled rule {rule_id}"))?;
        engine.record_fire(rule_id, now);
        report.fired_rule_ids.push(rule_id);
        dispatch_actions(db, actions_cfg, rule_id, rule_run_id, &outcome.actions).await;
        if let Some(advance) = next_after(&schedule, now) {
            engine.set_next_fire_at(rule_id, advance);
            tracing::debug!(rule_id, next_fire_at = advance, "cron rule advanced");
        }
    }
    Ok(report)
}

/// Spawn the periodic scheduler driver. Returns a `JoinHandle` for the
/// background task; the task ticks on `interval_secs` and processes every
/// scheduled rule in `branch_id` against the current time.
pub fn spawn(
    db: Db,
    engine: RuleEngine,
    actions_cfg: ActionsConfig,
    branch_id: i64,
    interval_secs: u64,
) -> tokio::task::JoinHandle<()> {
    let interval = std::time::Duration::from_secs(interval_secs.max(1));
    tokio::spawn(async move {
        // Skip the immediate tick that `tokio::time::interval` fires on
        // first poll — we don't want to advance schedules in the first
        // millisecond after process start.
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let now = now_ms();
            if let Err(e) = evaluate_scheduled(&db, &engine, &actions_cfg, branch_id, now).await {
                tracing::warn!(error = ?e, "scheduler tick failed");
            }
        }
    })
}

/// Read `definition.schedule` if a rule keeps the cron expression inside
/// the definition JSON rather than the dedicated column. Currently
/// unused — kept here so the loader can fall back if a definition has
/// both fields without changing the SQL.
#[allow(dead_code)]
pub(crate) fn extract_schedule_from_definition(definition_json: &str) -> Option<String> {
    let value: Value = serde_json::from_str(definition_json).ok()?;
    value
        .get("schedule")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

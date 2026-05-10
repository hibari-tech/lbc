//! Outbound action dispatch.
//!
//! Phase 1 first slice: HTTP only. SMTP / FTP / MQTT / Modbus / Nx
//! Witness all share the same shape (an [`ActionRequest`] descriptor +
//! a per-kind dispatcher) and land as follow-up modules.
//!
//! All dispatched actions are persisted to the `action_log` table,
//! linked to the originating `rule_run` row.

pub mod http;

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::storage::Db;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    /// Discriminator. Phase 1 only `"http"`.
    pub kind: String,
    /// Destination — for HTTP, the URL.
    pub target: String,
    /// HTTP method. Defaults to `POST` if absent.
    #[serde(default)]
    pub method: Option<String>,
    /// Optional outbound headers.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Optional JSON body. Sent as `application/json`.
    #[serde(default)]
    pub body: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionResult {
    pub ok: bool,
    /// HTTP status when applicable; `0` for transport-level failures.
    pub status: u16,
    /// Response body (or error text), truncated.
    pub response: String,
    pub latency_ms: i64,
}

/// Dispatch a single action and persist an `action_log` row regardless
/// of outcome. Errors at the transport level are recorded as `ok=false`
/// rather than propagated — the rule run that triggered it should not
/// fail just because a downstream HTTP endpoint timed out.
pub async fn dispatch(
    db: &Db,
    rule_run_id: i64,
    action: &ActionRequest,
) -> anyhow::Result<ActionResult> {
    let result = match action.kind.as_str() {
        "http" => http::execute(action).await,
        other => ActionResult {
            ok: false,
            status: 0,
            response: format!("unsupported action kind: {other}"),
            latency_ms: 0,
        },
    };
    persist(db, rule_run_id, action, &result)
        .await
        .context("persisting action_log row")?;
    Ok(result)
}

async fn persist(
    db: &Db,
    rule_run_id: i64,
    action: &ActionRequest,
    result: &ActionResult,
) -> anyhow::Result<()> {
    let request_json = serde_json::to_string(action)?;
    let status = if result.ok { "ok" } else { "error" };
    sqlx::query(
        "INSERT INTO action_log \
            (rule_run_id, kind, target, request, response, status, latency_ms, ts) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(rule_run_id)
    .bind(&action.kind)
    .bind(&action.target)
    .bind(&request_json)
    .bind(&result.response)
    .bind(status)
    .bind(result.latency_ms)
    .bind(now_ms())
    .execute(db.pool())
    .await?;
    Ok(())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

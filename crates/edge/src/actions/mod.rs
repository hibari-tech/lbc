//! Outbound action dispatch.
//!
//! Phase 1 ships `kind = "http"`, `"smtp"`, `"mqtt"`, `"modbus"`,
//! `"ftp"`, and `"nx"` (Nx Witness Generic Event). Each shares the
//! same shape — an [`ActionRequest`] descriptor + a per-kind
//! dispatcher.
//!
//! All dispatched actions are persisted to the `action_log` table,
//! linked to the originating `rule_run` row.
//!
//! ## SSRF guard
//!
//! Rule scripts are admin-authored, but the URL in an HTTP action is
//! still data flowing into network requests against whatever the
//! target name resolves to. Without a guard, a malicious or buggy
//! rule could probe the local network or hit cloud-metadata
//! endpoints (`169.254.169.254`). [`ActionsConfig`] gates that:
//!
//! * `allow_private_targets = false` (default) — http(s) only;
//!   targets resolving to loopback / private / link-local / multicast
//!   / unspecified IPs are refused **before** the request is sent.
//! * `allow_private_targets = true` — escape hatch for dev / tests
//!   that legitimately POST to localhost echo servers. Set via
//!   `LBC_EDGE_ACTIONS__ALLOW_PRIVATE_TARGETS=true` or in the TOML.

pub mod ftp;
pub mod http;
pub mod modbus;
pub mod mqtt;
pub mod nx;
pub mod smtp;

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::storage::Db;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionsConfig {
    #[serde(default)]
    pub allow_private_targets: bool,
    /// SMTP server connection details. Empty `server` disables SMTP
    /// actions — any `kind: "smtp"` dispatch records an error row
    /// explaining how to configure it.
    #[serde(default)]
    pub smtp: SmtpConfig,
    /// MQTT broker connection details. Empty `server` disables MQTT
    /// actions. See [`MqttConfig`].
    #[serde(default)]
    pub mqtt: MqttConfig,
    /// Nx Witness Media Server connection details. Empty `server`
    /// disables Nx actions. See [`NxConfig`].
    #[serde(default)]
    pub nx: NxConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NxConfig {
    /// Nx Media Server base URL (e.g. `https://nx.local:7001`). Empty
    /// disables Nx actions.
    #[serde(default)]
    pub server: String,
    /// Username for HTTP Basic auth. Empty = no auth header.
    #[serde(default)]
    pub username: String,
    /// Password for HTTP Basic auth.
    #[serde(default)]
    pub password: String,
    /// Skip TLS certificate validation. Nx Media Server ships with a
    /// self-signed cert by default; setting this to `true` is the
    /// expected dev / first-install path.
    #[serde(default)]
    pub accept_invalid_certs: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MqttConfig {
    /// Broker hostname. Empty disables MQTT.
    #[serde(default)]
    pub server: String,
    /// Broker port. Default 1883 (plain) when 0; 8883 is conventional
    /// for TLS but TLS support is a follow-up.
    #[serde(default)]
    pub port: u16,
    /// MQTT v3.1.1 client id. Empty = auto-generated per-action.
    #[serde(default)]
    pub client_id: String,
    /// MQTT username. Empty = anonymous.
    #[serde(default)]
    pub username: String,
    /// MQTT password.
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SmtpConfig {
    /// SMTP server hostname. Empty disables SMTP.
    #[serde(default)]
    pub server: String,
    /// SMTP server port. Default 587 (STARTTLS). 465 for implicit TLS.
    #[serde(default)]
    pub port: u16,
    /// Username for SMTP AUTH. Empty = no auth.
    #[serde(default)]
    pub username: String,
    /// Password for SMTP AUTH.
    #[serde(default)]
    pub password: String,
    /// Default `From:` address used when an action omits `from`.
    #[serde(default)]
    pub from_default: String,
    /// If true, use implicit TLS (port 465 style). If false, use
    /// STARTTLS on plain TCP (port 587 style).
    #[serde(default)]
    pub implicit_tls: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionRequest {
    /// Discriminator. `"http"` or `"smtp"`.
    pub kind: String,
    /// For HTTP, the URL. For SMTP, unused (server comes from config).
    #[serde(default)]
    pub target: String,
    /// HTTP method. Defaults to `POST` if absent. Ignored by SMTP.
    #[serde(default)]
    pub method: Option<String>,
    /// HTTP headers (`Content-Type` etc.). Ignored by SMTP.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// HTTP: JSON body. SMTP: plain-text or JSON-stringified body.
    #[serde(default)]
    pub body: Option<Value>,
    /// SMTP recipients. Ignored by HTTP.
    #[serde(default)]
    pub to: Vec<String>,
    /// SMTP `Subject:` header. Ignored by HTTP.
    #[serde(default)]
    pub subject: Option<String>,
    /// SMTP `From:` address. Falls back to `SmtpConfig::from_default`
    /// when absent. Ignored by HTTP.
    #[serde(default)]
    pub from: Option<String>,
    /// MQTT topic. Required for `kind = "mqtt"`. Ignored otherwise.
    #[serde(default)]
    pub topic: Option<String>,
    /// MQTT QoS: 0 (default), 1, or 2.
    #[serde(default)]
    pub qos: Option<u8>,
    /// MQTT retained flag.
    #[serde(default)]
    pub retain: Option<bool>,
    /// Modbus function discriminator. Phase 1 ships `"write_coil"` and
    /// `"write_register"`; reads land in a follow-up. Ignored by other
    /// kinds.
    #[serde(default)]
    pub function: Option<String>,
    /// Modbus slave / unit id (0..=247). Defaults to 1 when absent.
    /// Ignored by other kinds.
    #[serde(default)]
    pub unit_id: Option<u8>,
    /// Modbus register / coil address (0..=65535). Ignored by other
    /// kinds.
    #[serde(default)]
    pub address: Option<u16>,
    /// Nx Witness Generic Event `source` field. Defaults to `"lbc-edge"`
    /// when absent. Ignored by other kinds.
    #[serde(default)]
    pub source: Option<String>,
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
    cfg: &ActionsConfig,
    rule_run_id: i64,
    action: &ActionRequest,
) -> anyhow::Result<ActionResult> {
    let result = match action.kind.as_str() {
        "http" => http::execute(action, cfg).await,
        "smtp" => smtp::execute(action, &cfg.smtp).await,
        "mqtt" => mqtt::execute(action, &cfg.mqtt).await,
        "modbus" => modbus::execute(action).await,
        "ftp" => ftp::execute(action).await,
        "nx" => nx::execute(action, &cfg.nx).await,
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

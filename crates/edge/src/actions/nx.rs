//! Nx Witness Generic Event action — sixth action kind.
//!
//! Nx Witness Media Server exposes a generic-event ingestion endpoint
//! (`POST /api/createEvent`) that surfaces as an event in the operator
//! UI and can be tied to Nx-side rules (bookmarks, push notifications,
//! camera output triggers). LBC fires one when a rule wants to drop a
//! breadcrumb into the VMS timeline.
//!
//! ```rhai
//! return #{
//!     actions: [
//!         #{
//!             kind: "nx",
//!             source: "lbc-edge",
//!             subject: "Motion at front door",
//!             body: `zone=${event.payload.zone}`,
//!         }
//!     ]
//! };
//! ```
//!
//! ## Scope (Phase 1)
//!
//! * Generic events only. Bookmarks, recording-state toggles, and
//!   camera output triggers land later — same `kind: "nx"` shape with
//!   a `function` discriminator (mirrors Modbus).
//! * Server URL + credentials live in [`NxConfig`] so individual rule
//!   scripts can't leak admin auth. Empty `server` disables Nx —
//!   any `kind: "nx"` dispatch records an explicit error row.
//! * Nx Media Server ships with a self-signed cert by default. Set
//!   `actions.nx.accept_invalid_certs = true`
//!   (`LBC_EDGE_ACTIONS__NX__ACCEPT_INVALID_CERTS=true`) to skip TLS
//!   validation. Off by default.
//!
//! ## Network policy
//!
//! Like Modbus and FTP, Nx Witness is an internal-LAN VMS — the SSRF
//! guard that gates outbound HTTP does **not** apply. The server URL
//! is admin-configured, not data flowing from a rule script.

use std::time::{Duration, Instant};

use reqwest::Client;
use serde_json::Value;

use super::{ActionRequest, ActionResult, NxConfig};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone)]
pub struct NxEvent {
    pub source: String,
    pub caption: String,
    pub description: String,
}

pub async fn execute(action: &ActionRequest, cfg: &NxConfig) -> ActionResult {
    let start = Instant::now();

    if cfg.server.is_empty() {
        return error(
            "Nx not configured — set actions.nx.server (LBC_EDGE_ACTIONS__NX__SERVER)",
            start,
        );
    }

    let event = match plan_event(action) {
        Ok(e) => e,
        Err(e) => return error(&e, start),
    };

    let url = match build_url(&cfg.server) {
        Ok(u) => u,
        Err(e) => return error(&e, start),
    };

    let client = match Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .danger_accept_invalid_certs(cfg.accept_invalid_certs)
        .build()
    {
        Ok(c) => c,
        Err(e) => return error(&format!("nx client build: {e}"), start),
    };

    let mut req = client.post(&url).query(&[
        ("source", event.source.as_str()),
        ("caption", event.caption.as_str()),
        ("description", event.description.as_str()),
    ]);
    if !cfg.username.is_empty() {
        req = req.basic_auth(&cfg.username, Some(&cfg.password));
    }

    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let truncated = if body.len() > MAX_RESPONSE_BYTES {
                format!("{}…", &body[..MAX_RESPONSE_BYTES])
            } else {
                body
            };
            ActionResult {
                ok: status.is_success(),
                status: status.as_u16(),
                response: if truncated.is_empty() {
                    format!("nx {status}")
                } else {
                    format!("nx {status}: {truncated}")
                },
                latency_ms: elapsed_ms(start),
            }
        }
        Err(e) => error(&format!("nx send: {e}"), start),
    }
}

/// Validate an action descriptor and project it into an [`NxEvent`].
/// Pure — no IO — so every parse path is testable without an Nx
/// server.
pub fn plan_event(action: &ActionRequest) -> Result<NxEvent, String> {
    let caption = action
        .subject
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Nx action requires `subject` (caption)".to_string())?
        .to_string();
    let source = action
        .source
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("lbc-edge")
        .to_string();
    let description = match &action.body {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    };
    Ok(NxEvent {
        source,
        caption,
        description,
    })
}

fn build_url(server: &str) -> Result<String, String> {
    let trimmed = server.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err("Nx server URL is empty".into());
    }
    Ok(format!("{trimmed}/api/createEvent"))
}

fn error(msg: &str, start: Instant) -> ActionResult {
    ActionResult {
        ok: false,
        status: 0,
        response: msg.to_string(),
        latency_ms: elapsed_ms(start),
    }
}

fn elapsed_ms(start: Instant) -> i64 {
    i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX)
}

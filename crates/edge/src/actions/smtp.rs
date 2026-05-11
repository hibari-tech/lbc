//! SMTP action dispatch via `lettre`.
//!
//! Phase 1: STARTTLS or implicit-TLS connection to a server configured
//! globally on the edge (`actions.smtp.*`). Rule scripts construct the
//! envelope with `to`, `subject`, `body`, and an optional `from`; the
//! server / credentials come from config so individual rules can't
//! leak SMTP auth.
//!
//! ```rhai
//! return #{
//!     actions: [
//!         #{
//!             kind: "smtp",
//!             to: ["ops@example.com"],
//!             subject: "Motion at front door",
//!             body: `Zone: ${event.payload.zone}`,
//!         }
//!     ]
//! };
//! ```

use std::time::Instant;

use lettre::message::{header::ContentType, Mailbox};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::{AsyncTransport, Message, Tokio1Executor};

use super::{ActionRequest, ActionResult, SmtpConfig};

pub async fn execute(action: &ActionRequest, cfg: &SmtpConfig) -> ActionResult {
    let start = Instant::now();

    if cfg.server.is_empty() {
        return error(
            "SMTP not configured — set actions.smtp.server (LBC_EDGE_ACTIONS__SMTP__SERVER)",
            start,
        );
    }

    let message = match build_message(action, cfg) {
        Ok(m) => m,
        Err(e) => return error(&format!("build message: {e}"), start),
    };

    let mut builder = if cfg.implicit_tls {
        match AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.server) {
            Ok(b) => b,
            Err(e) => return error(&format!("relay setup: {e}"), start),
        }
    } else {
        match AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.server) {
            Ok(b) => b,
            Err(e) => return error(&format!("starttls relay setup: {e}"), start),
        }
    };
    if cfg.port != 0 {
        builder = builder.port(cfg.port);
    }
    if !cfg.username.is_empty() {
        builder = builder.credentials(Credentials::new(cfg.username.clone(), cfg.password.clone()));
    }
    let transport = builder.build();

    match transport.send(message).await {
        Ok(resp) => ActionResult {
            ok: true,
            // 0 = transport-level / N/A. SMTP reply codes (e.g. 250) live
            // in the response body for now; surfacing them as a u16 cleanly
            // requires Debug-format parsing on lettre's private enums.
            status: 0,
            response: format!("ok: {}", resp.message().collect::<Vec<_>>().join(" ")),
            latency_ms: elapsed_ms(start),
        },
        Err(e) => error(&format!("smtp send: {e}"), start),
    }
}

pub fn build_message(action: &ActionRequest, cfg: &SmtpConfig) -> Result<Message, String> {
    if action.to.is_empty() {
        return Err("SMTP action requires at least one recipient in `to`".into());
    }
    let from_str = action
        .from
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(&cfg.from_default);
    if from_str.is_empty() {
        return Err(
            "missing From: address — set the action's `from` or actions.smtp.from_default".into(),
        );
    }
    let from: Mailbox = from_str
        .parse()
        .map_err(|e| format!("invalid From `{from_str}`: {e}"))?;

    let mut builder = Message::builder()
        .from(from)
        .subject(action.subject.as_deref().unwrap_or("(no subject)"));
    for addr in &action.to {
        let mb: Mailbox = addr
            .parse()
            .map_err(|e| format!("invalid recipient `{addr}`: {e}"))?;
        builder = builder.to(mb);
    }

    let body_text = match &action.body {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => String::new(),
    };
    builder
        .header(ContentType::TEXT_PLAIN)
        .body(body_text)
        .map_err(|e| format!("message build: {e}"))
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

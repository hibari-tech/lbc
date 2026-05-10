//! Webhook ingest with HMAC-SHA256 verification.
//!
//! `POST /api/v1/ingest/webhooks/{device_id}` accepts an arbitrary JSON
//! body from a configured device and persists it as an `event` row.
//! The device must have a non-null `webhook_secret`; the request must
//! carry:
//!
//! * `X-LBC-Timestamp: <unix_ms>` — within ±5 min of the server clock,
//!   defends against replay of captured requests.
//! * `X-LBC-Signature: <hex>` — `HMAC_SHA256(secret, "<timestamp>.<body>")`,
//!   constant-time-compared.
//!
//! On success, returns `{ event_id }`. The body's `kind` field (if a
//! string) becomes the event kind; otherwise `"webhook"` is used.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header::HeaderName;
use axum::http::HeaderMap;
use axum::Json;
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;
use utoipa::ToSchema;

use super::error::ApiError;
use super::AppState;
use super::DEFAULT_BRANCH_ID;

/// Maximum drift between the request timestamp and the server clock,
/// in milliseconds. ±5 min matches Stripe / Slack webhook conventions
/// and gives slow-clock edge devices some headroom without being a
/// useful replay window for a captured request.
const MAX_TIMESTAMP_SKEW_MS: i64 = 5 * 60 * 1000;

const HEADER_SIGNATURE: HeaderName = HeaderName::from_static("x-lbc-signature");
const HEADER_TIMESTAMP: HeaderName = HeaderName::from_static("x-lbc-timestamp");

#[derive(Debug, Serialize, ToSchema)]
pub struct IngestResponse {
    pub event_id: i64,
}

#[utoipa::path(
    post, path = "/api/v1/ingest/webhooks/{device_id}", tag = "ingest",
    params(("device_id" = i64, Path)),
    responses(
        (status = 200, body = IngestResponse),
        (status = 400, description = "Body not JSON or headers malformed"),
        (status = 401, description = "Missing/invalid signature or stale timestamp"),
        (status = 404, description = "Unknown device"),
    ),
)]
pub async fn webhook(
    State(state): State<AppState>,
    Path(device_id): Path<i64>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<IngestResponse>, ApiError> {
    let timestamp_ms = parse_header(&headers, &HEADER_TIMESTAMP)?
        .parse::<i64>()
        .map_err(|_| ApiError::BadRequest("X-LBC-Timestamp must be unix milliseconds".into()))?;
    let signature_hex = parse_header(&headers, &HEADER_SIGNATURE)?;

    let now = now_ms();
    if (now - timestamp_ms).abs() > MAX_TIMESTAMP_SKEW_MS {
        return Err(ApiError::Unauthorized);
    }

    let row: (String, Option<String>) =
        sqlx::query_as("SELECT kind, webhook_secret FROM device WHERE id = ? AND branch_id = ?")
            .bind(device_id)
            .bind(DEFAULT_BRANCH_ID)
            .fetch_optional(state.db.pool())
            .await?
            .ok_or(ApiError::NotFound)?;
    let (_kind, secret) = row;
    let Some(secret) = secret else {
        return Err(ApiError::Unauthorized);
    };

    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any length");
    mac.update(timestamp_ms.to_string().as_bytes());
    mac.update(b".");
    mac.update(&body);
    let expected = mac.finalize().into_bytes();
    let provided = decode_hex(&signature_hex).ok_or(ApiError::Unauthorized)?;
    if !constant_time_eq(&expected, &provided) {
        return Err(ApiError::Unauthorized);
    }

    let payload: Value =
        serde_json::from_slice(&body).map_err(|e| ApiError::BadRequest(format!("body: {e}")))?;
    let event_kind = payload
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("webhook")
        .to_string();
    let payload_text = serde_json::to_string(&payload)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("re-serialise payload: {e}")))?;
    let event_id: i64 = sqlx::query_scalar(
        "INSERT INTO event (branch_id, device_id, kind, ts, payload, ingest_ts) \
         VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(DEFAULT_BRANCH_ID)
    .bind(device_id)
    .bind(&event_kind)
    .bind(timestamp_ms)
    .bind(&payload_text)
    .bind(now)
    .fetch_one(state.db.pool())
    .await?;

    Ok(Json(IngestResponse { event_id }))
}

fn parse_header(headers: &HeaderMap, name: &HeaderName) -> Result<String, ApiError> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .ok_or(ApiError::Unauthorized)
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

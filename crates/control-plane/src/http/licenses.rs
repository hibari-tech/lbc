//! License issuance + revocation routes.
//!
//! `POST /api/v1/licenses/activate` exchanges a customer-provided
//! license key + branch identity for a signed license.
//! `POST /api/v1/licenses/{id}/revoke` marks an issued license revoked
//! (idempotent — second revoke returns 200 with the same row).
//!
//! Phase 0 simplifications worth flagging:
//!  * Activation creates the `branch` row on the fly when `name` is a new
//!    pair within the account. Real branch lifecycle (rename, retire, etc.)
//!    is §0.8 PR B / Phase 1 work.
//!  * No dealer / installer scope (`lbcspec.md` §7.6) yet.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
use axum::Json;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use shared::license::{LicensePayload, SignedLicense};
use sqlx::Row;
use utoipa::ToSchema;

use super::error::ApiError;
use super::AppState;

const DEFAULT_GRACE_DAYS: u32 = 30;
/// Length in bytes of the per-license heartbeat secret. 32 bytes
/// gives 256-bit entropy and the wire format becomes 64 hex chars.
const HEARTBEAT_SECRET_LEN: usize = 32;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ActivateRequest {
    /// Cleartext license key the customer received at purchase.
    pub license_key: String,
    /// Human-readable branch name unique within the account.
    pub branch_name: String,
    /// Multi-factor hardware fingerprint produced by the edge.
    pub hardware_fingerprint: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ActivateResponse {
    /// Surrogate id for the persisted `issued_license` row — opaque to the edge.
    pub issued_license_id: i64,
    pub branch_id: i64,
    /// Signed license the edge stores and verifies on every start.
    #[schema(value_type = Object)]
    pub license: SignedLicense,
    /// Cleartext heartbeat secret (hex-encoded 32 bytes). Returned
    /// exactly once — the CP stores only its BLAKE3 hash. The edge
    /// must persist this and present it as
    /// `Authorization: Bearer <token>` on every subsequent heartbeat;
    /// losing it forces re-activation.
    pub heartbeat_token: String,
}

#[utoipa::path(
    post, path = "/api/v1/licenses/activate", tag = "licenses",
    request_body = ActivateRequest,
    responses(
        (status = 200, body = ActivateResponse),
        (status = 401, description = "Unknown or revoked license key"),
        (status = 409, description = "Branch count exceeded"),
    ),
)]
pub async fn activate(
    State(state): State<AppState>,
    Json(req): Json<ActivateRequest>,
) -> Result<Json<ActivateResponse>, ApiError> {
    let key_hash = blake3::hash(req.license_key.as_bytes());

    let key_row = sqlx::query(
        "SELECT id, account_id, tier, allowed_branch_count, expires_at, revoked_at \
         FROM license_key WHERE key_hash = ?",
    )
    .bind(key_hash.as_bytes().as_slice())
    .fetch_optional(state.db.pool())
    .await?
    .ok_or_else(|| ApiError::BadRequest("unknown license key".into()))?;

    let key_id: i64 = key_row.get("id");
    let account_id: i64 = key_row.get("account_id");
    let tier_str: String = key_row.get("tier");
    let allowed: i64 = key_row.get("allowed_branch_count");
    let expires_at: i64 = key_row.get("expires_at");
    let revoked_at: Option<i64> = key_row.get("revoked_at");
    if revoked_at.is_some() {
        return Err(ApiError::Gone("license key revoked".into()));
    }
    let tier: shared::license::Tier =
        serde_json::from_value(serde_json::Value::String(tier_str))
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("invalid tier in db: {e}")))?;

    let now = now_secs();
    let now_ms = now * 1000;

    // Find or create the branch within this account.
    let branch_id = upsert_branch(
        &state,
        account_id,
        &req.branch_name,
        &req.hardware_fingerprint,
    )
    .await?;

    // Enforce branch-count cap (count distinct branches with un-revoked licenses).
    let used: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT branch_id) FROM issued_license \
         WHERE license_key_id = ? AND revoked_at IS NULL",
    )
    .bind(key_id)
    .fetch_one(state.db.pool())
    .await?;
    let already_active: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM issued_license \
         WHERE license_key_id = ? AND branch_id = ? AND revoked_at IS NULL",
    )
    .bind(key_id)
    .bind(branch_id)
    .fetch_one(state.db.pool())
    .await?;
    if already_active == 0 && used >= allowed {
        return Err(ApiError::Conflict(format!(
            "license key allows {allowed} branch(es); already activated for {used}"
        )));
    }

    let payload = LicensePayload {
        customer_id: format!("{account_id}"),
        tier,
        feature_flags: vec![],
        branch_count: u32::try_from(allowed).unwrap_or(u32::MAX),
        branch_id,
        hardware_fingerprint: req.hardware_fingerprint,
        issued_at: now,
        expiry: expires_at,
        grace_period_days: DEFAULT_GRACE_DAYS,
    };
    let signed = state
        .signer
        .sign(payload.clone())
        .map_err(ApiError::Internal)?;
    let payload_json = serde_json::to_string(&payload)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("serialising payload: {e}")))?;

    // Mint a fresh heartbeat secret. The cleartext is returned to the
    // edge exactly once; only its BLAKE3 hash is persisted.
    let mut secret = [0u8; HEARTBEAT_SECRET_LEN];
    OsRng.fill_bytes(&mut secret);
    let secret_hash = blake3::hash(&secret);
    let heartbeat_token = hex::encode(secret);

    let issued_id: i64 = sqlx::query_scalar(
        "INSERT INTO issued_license \
            (license_key_id, branch_id, payload, signature, issued_at, expires_at, \
             heartbeat_secret_hash) \
         VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(key_id)
    .bind(branch_id)
    .bind(&payload_json)
    .bind(signed.signature.as_slice())
    .bind(now_ms)
    .bind(expires_at)
    .bind(secret_hash.as_bytes().as_slice())
    .fetch_one(state.db.pool())
    .await?;

    Ok(Json(ActivateResponse {
        issued_license_id: issued_id,
        branch_id,
        license: signed,
        heartbeat_token,
    }))
}

async fn upsert_branch(
    state: &AppState,
    account_id: i64,
    name: &str,
    fingerprint: &str,
) -> Result<i64, ApiError> {
    if let Some(existing) =
        sqlx::query_scalar::<_, i64>("SELECT id FROM branch WHERE account_id = ? AND name = ?")
            .bind(account_id)
            .bind(name)
            .fetch_optional(state.db.pool())
            .await?
    {
        return Ok(existing);
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO branch (account_id, name, hardware_fingerprint, created_at) \
         VALUES (?, ?, ?, ?) RETURNING id",
    )
    .bind(account_id)
    .bind(name)
    .bind(fingerprint)
    .bind(now_secs() * 1000)
    .fetch_one(state.db.pool())
    .await?;
    Ok(id)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatRequest {
    /// The same fingerprint the edge presented at activation time. Mismatch
    /// returns 401 — the license cannot be relayed to a different machine
    /// and still heartbeat.
    pub hardware_fingerprint: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HeartbeatResponse {
    /// Server-recorded `last_seen` in unix epoch milliseconds.
    pub last_seen: i64,
    /// Echoes the issued license's `expires_at` for client convenience.
    pub expires_at: i64,
}

#[utoipa::path(
    post, path = "/api/v1/licenses/{id}/heartbeat", tag = "licenses",
    params(("id" = i64, Path)),
    request_body = HeartbeatRequest,
    responses(
        (status = 200, body = HeartbeatResponse),
        (status = 400, description = "Fingerprint mismatch"),
        (status = 401, description = "Missing or invalid heartbeat token"),
        (status = 404, description = "Unknown id"),
        (status = 410, description = "License revoked"),
    ),
)]
pub async fn heartbeat(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, ApiError> {
    // Decode the Bearer token before touching the DB — malformed
    // headers don't need a row lookup. We keep the same response for
    // every auth-failure shape (missing header, wrong scheme, bad
    // hex, wrong secret) so an attacker can't distinguish "valid id
    // but bad token" from "id doesn't exist" once we 401 in both.
    let presented = extract_bearer_token(&headers).ok_or(ApiError::Unauthorized)?;

    let row = sqlx::query(
        "SELECT payload, expires_at, revoked_at, heartbeat_secret_hash \
         FROM issued_license WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(state.db.pool())
    .await?
    .ok_or(ApiError::Unauthorized)?;
    let revoked_at: Option<i64> = row.get("revoked_at");
    if revoked_at.is_some() {
        return Err(ApiError::Gone("license revoked".into()));
    }
    let stored_hash: Vec<u8> = row.get("heartbeat_secret_hash");
    let presented_hash = blake3::hash(&presented);
    if !constant_time_eq(&stored_hash, presented_hash.as_bytes()) {
        return Err(ApiError::Unauthorized);
    }

    let payload_text: String = row.get("payload");
    let payload: LicensePayload = serde_json::from_str(&payload_text)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("decoding stored payload: {e}")))?;
    if payload.hardware_fingerprint != req.hardware_fingerprint {
        return Err(ApiError::BadRequest("fingerprint mismatch".into()));
    }
    let expires_at: i64 = row.get("expires_at");
    let now_ms = now_secs() * 1000;
    sqlx::query("UPDATE issued_license SET last_seen = ? WHERE id = ?")
        .bind(now_ms)
        .bind(id)
        .execute(state.db.pool())
        .await?;
    Ok(Json(HeartbeatResponse {
        last_seen: now_ms,
        expires_at,
    }))
}

/// Extract the raw bytes of an `Authorization: Bearer <hex>` token.
/// Returns `None` for missing header, wrong scheme, or non-hex
/// payload — every malformed input collapses to the same 401 at the
/// call site.
fn extract_bearer_token(headers: &HeaderMap) -> Option<Vec<u8>> {
    let raw = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let rest = raw.strip_prefix("Bearer ")?;
    let bytes = hex::decode(rest.trim()).ok()?;
    if bytes.len() == HEARTBEAT_SECRET_LEN {
        Some(bytes)
    } else {
        None
    }
}

/// Length-independent constant-time byte compare. `blake3::Hash`
/// already provides this internally for hash-to-hash compare, but
/// we read the stored hash as a generic `Vec<u8>` (since the DB
/// column is opaque), so do it ourselves.
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

#[utoipa::path(
    post, path = "/api/v1/licenses/{id}/revoke", tag = "licenses",
    params(("id" = i64, Path)),
    responses((status = 204), (status = 404)),
)]
pub async fn revoke(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let now_ms = now_secs() * 1000;
    let result =
        sqlx::query("UPDATE issued_license SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?")
            .bind(now_ms)
            .bind(id)
            .execute(state.db.pool())
            .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

//! Authentication routes: `POST /api/v1/auth/login`, `GET /api/v1/auth/me`.
//!
//! Login carries a per-account brute-force gate: after
//! [`LoginRateLimit::max_failed_attempts`](super::LoginRateLimit)
//! consecutive failures the account is locked for
//! `lockout_secs`. Locked accounts return `401 Unauthorized` even
//! with correct credentials — same status as a wrong-password
//! response, so an attacker can't trivially probe lock state. A
//! successful login resets the counter and clears the lock.
//!
//! Unknown emails do **not** increment any counter (you can't lock
//! an account that doesn't exist). Stopping anonymous email
//! enumeration is a separate concern: argon2 verify cost dominates
//! the response timing in either branch, which makes timing
//! enumeration impractical on the order of "guess the user table"
//! attacks.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{password, token, Role};

use super::error::ApiError;
use super::extractors::AuthUser;
use super::AppState;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: i64,
    pub user: UserSummary,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserSummary {
    pub id: i64,
    pub email: String,
    pub role: Role,
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Token issued", body = LoginResponse),
        (status = 401, description = "Invalid credentials")
    )
)]
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let row: Option<(i64, String, String, String, Option<i64>)> = sqlx::query_as(
        "SELECT id, email, password_hash, role, locked_until_ms FROM user WHERE email = ?",
    )
    .bind(&req.email)
    .fetch_optional(state.db.pool())
    .await?;
    let (id, email, password_hash, role_str, locked_until_ms) =
        row.ok_or(ApiError::Unauthorized)?;

    let now = now_ms();
    let gate = state.login_rate_limit;
    let gate_enabled = gate.max_failed_attempts > 0;

    if gate_enabled {
        if let Some(until) = locked_until_ms {
            if until > now {
                return Err(ApiError::Unauthorized);
            }
            // Lock has expired naturally — clear it before the next
            // password check so a successful login below doesn't have
            // to do a second update. Counter stays as-is until the
            // success / failure path below resets or extends it.
            sqlx::query("UPDATE user SET locked_until_ms = NULL WHERE id = ?")
                .bind(id)
                .execute(state.db.pool())
                .await?;
        }
    }

    if !password::verify(&req.password, &password_hash)? {
        if gate_enabled {
            record_failure(&state, id, now, gate).await?;
        }
        return Err(ApiError::Unauthorized);
    }

    if gate_enabled {
        sqlx::query(
            "UPDATE user \
                SET failed_login_count = 0, last_failed_login_ms = NULL, locked_until_ms = NULL \
              WHERE id = ?",
        )
        .bind(id)
        .execute(state.db.pool())
        .await?;
    }

    let role: Role = role_str
        .parse()
        .map_err(|e: anyhow::Error| ApiError::Internal(e.context("decoding role from db")))?;
    let ttl = i64::try_from(state.session_ttl_secs).unwrap_or(i64::MAX);
    let token = token::issue(&state.jwt_secret, id, role, ttl)?;
    let expires_at = now_secs().saturating_add(ttl);
    Ok(Json(LoginResponse {
        token,
        expires_at,
        user: UserSummary { id, email, role },
    }))
}

async fn record_failure(
    state: &AppState,
    user_id: i64,
    now_ms: i64,
    gate: super::LoginRateLimit,
) -> Result<(), ApiError> {
    let new_count: i64 = sqlx::query_scalar(
        "UPDATE user \
            SET failed_login_count = failed_login_count + 1, last_failed_login_ms = ? \
          WHERE id = ? \
          RETURNING failed_login_count",
    )
    .bind(now_ms)
    .bind(user_id)
    .fetch_one(state.db.pool())
    .await?;
    if new_count >= i64::from(gate.max_failed_attempts) {
        let lockout_ms = i64::try_from(gate.lockout_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
        let until = now_ms.saturating_add(lockout_ms);
        sqlx::query("UPDATE user SET locked_until_ms = ? WHERE id = ?")
            .bind(until)
            .bind(user_id)
            .execute(state.db.pool())
            .await?;
    }
    Ok(())
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/me",
    tag = "auth",
    responses(
        (status = 200, description = "Current user", body = UserSummary),
        (status = 401, description = "Missing or invalid token")
    ),
    security(("bearer_auth" = []))
)]
pub async fn me(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<UserSummary>, ApiError> {
    let row: Option<(String, String)> = sqlx::query_as("SELECT email, role FROM user WHERE id = ?")
        .bind(user.user_id)
        .fetch_optional(state.db.pool())
        .await?;
    let (email, role_str) = row.ok_or(ApiError::Unauthorized)?;
    let role: Role = role_str
        .parse()
        .map_err(|e: anyhow::Error| ApiError::Internal(e.context("decoding role from db")))?;
    Ok(Json(UserSummary {
        id: user.user_id,
        email,
        role,
    }))
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

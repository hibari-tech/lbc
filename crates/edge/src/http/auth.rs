//! Authentication routes: `POST /api/v1/auth/login`, `GET /api/v1/auth/me`.

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
    let row: Option<(i64, String, String, String)> =
        sqlx::query_as("SELECT id, email, password_hash, role FROM user WHERE email = ?")
            .bind(&req.email)
            .fetch_optional(state.db.pool())
            .await?;
    let (id, email, password_hash, role_str) = row.ok_or(ApiError::Unauthorized)?;
    if !password::verify(&req.password, &password_hash)? {
        return Err(ApiError::Unauthorized);
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

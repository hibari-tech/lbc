//! Devices CRUD (`/api/v1/devices`).
//!
//! Phase 0: implicitly scoped to [`super::DEFAULT_BRANCH_ID`] until license
//! activation in §0.9 mints real branches.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::ToSchema;

use crate::auth::Role;

use super::error::ApiError;
use super::extractors::AuthUser;
use super::AppState;
use super::DEFAULT_BRANCH_ID;

#[derive(Debug, Serialize, ToSchema)]
pub struct DeviceRead {
    pub id: i64,
    pub kind: String,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub address: Option<String>,
    pub credentials_ref: Option<String>,
    pub status: String,
    pub last_seen: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceCreate {
    pub kind: String,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub address: Option<String>,
    pub credentials_ref: Option<String>,
}

/// Field absent (`None`) = leave unchanged. Nulling an existing value is not
/// supported in Phase 0; revisit in §0.7+ if needed.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DevicePatch {
    pub kind: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub address: Option<String>,
    pub credentials_ref: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[utoipa::path(
    get, path = "/api/v1/devices", tag = "devices",
    params(("limit" = Option<i64>, Query, description = "1..=500, default 50"),
           ("offset" = Option<i64>, Query, description = "default 0")),
    responses((status = 200, body = [DeviceRead])),
    security(("bearer_auth" = []))
)]
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<DeviceRead>>, ApiError> {
    user.require(Role::Viewer)?;
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let offset = q.offset.unwrap_or(0).max(0);
    let rows = sqlx::query(
        "SELECT id, kind, vendor, model, address, credentials_ref, status, last_seen, created_at \
         FROM device WHERE branch_id = ? ORDER BY id ASC LIMIT ? OFFSET ?",
    )
    .bind(DEFAULT_BRANCH_ID)
    .bind(limit)
    .bind(offset)
    .fetch_all(state.db.pool())
    .await?;
    Ok(Json(rows.into_iter().map(row_to_device).collect()))
}

#[utoipa::path(
    post, path = "/api/v1/devices", tag = "devices",
    request_body = DeviceCreate,
    responses((status = 201, body = DeviceRead), (status = 403)),
    security(("bearer_auth" = []))
)]
pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<DeviceCreate>,
) -> Result<(StatusCode, Json<DeviceRead>), ApiError> {
    user.require(Role::Manager)?;
    let now = now_ms();
    let row = sqlx::query(
        "INSERT INTO device (branch_id, kind, vendor, model, address, credentials_ref, status, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, 'unknown', ?) \
         RETURNING id, kind, vendor, model, address, credentials_ref, status, last_seen, created_at",
    )
    .bind(DEFAULT_BRANCH_ID)
    .bind(&req.kind)
    .bind(&req.vendor)
    .bind(&req.model)
    .bind(&req.address)
    .bind(&req.credentials_ref)
    .bind(now)
    .fetch_one(state.db.pool())
    .await?;
    Ok((StatusCode::CREATED, Json(row_to_device(row))))
}

#[utoipa::path(
    get, path = "/api/v1/devices/{id}", tag = "devices",
    params(("id" = i64, Path)),
    responses((status = 200, body = DeviceRead), (status = 404)),
    security(("bearer_auth" = []))
)]
pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<DeviceRead>, ApiError> {
    user.require(Role::Viewer)?;
    let row = sqlx::query(
        "SELECT id, kind, vendor, model, address, credentials_ref, status, last_seen, created_at \
         FROM device WHERE id = ? AND branch_id = ?",
    )
    .bind(id)
    .bind(DEFAULT_BRANCH_ID)
    .fetch_optional(state.db.pool())
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(row_to_device(row)))
}

#[utoipa::path(
    patch, path = "/api/v1/devices/{id}", tag = "devices",
    params(("id" = i64, Path)),
    request_body = DevicePatch,
    responses((status = 200, body = DeviceRead), (status = 404), (status = 403)),
    security(("bearer_auth" = []))
)]
pub async fn patch(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
    Json(p): Json<DevicePatch>,
) -> Result<Json<DeviceRead>, ApiError> {
    user.require(Role::Manager)?;
    let row = sqlx::query(
        "UPDATE device SET \
            kind = COALESCE(?, kind), \
            vendor = COALESCE(?, vendor), \
            model = COALESCE(?, model), \
            address = COALESCE(?, address), \
            credentials_ref = COALESCE(?, credentials_ref), \
            status = COALESCE(?, status) \
         WHERE id = ? AND branch_id = ? \
         RETURNING id, kind, vendor, model, address, credentials_ref, status, last_seen, created_at",
    )
    .bind(&p.kind)
    .bind(&p.vendor)
    .bind(&p.model)
    .bind(&p.address)
    .bind(&p.credentials_ref)
    .bind(&p.status)
    .bind(id)
    .bind(DEFAULT_BRANCH_ID)
    .fetch_optional(state.db.pool())
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(row_to_device(row)))
}

#[utoipa::path(
    delete, path = "/api/v1/devices/{id}", tag = "devices",
    params(("id" = i64, Path)),
    responses((status = 204), (status = 404), (status = 403)),
    security(("bearer_auth" = []))
)]
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    user.require(Role::Manager)?;
    let result = sqlx::query("DELETE FROM device WHERE id = ? AND branch_id = ?")
        .bind(id)
        .bind(DEFAULT_BRANCH_ID)
        .execute(state.db.pool())
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

fn row_to_device(row: sqlx::sqlite::SqliteRow) -> DeviceRead {
    DeviceRead {
        id: row.get("id"),
        kind: row.get("kind"),
        vendor: row.get("vendor"),
        model: row.get("model"),
        address: row.get("address"),
        credentials_ref: row.get("credentials_ref"),
        status: row.get("status"),
        last_seen: row.get("last_seen"),
        created_at: row.get("created_at"),
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

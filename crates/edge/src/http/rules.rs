//! Rules CRUD (`/api/v1/rules`).

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;
use utoipa::ToSchema;

use crate::auth::Role;

use super::devices::ListQuery;
use super::error::ApiError;
use super::extractors::AuthUser;
use super::AppState;
use super::DEFAULT_BRANCH_ID;

#[derive(Debug, Serialize, ToSchema)]
pub struct RuleRead {
    pub id: i64,
    pub name: String,
    pub version: i64,
    /// Rule definition document (visual-builder JSON or compiled state-machine).
    #[schema(value_type = Object)]
    pub definition: Value,
    pub enabled: bool,
    pub schedule: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleCreate {
    pub name: String,
    #[schema(value_type = Object)]
    pub definition: Value,
    pub schedule: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RulePatch {
    pub name: Option<String>,
    #[schema(value_type = Object)]
    pub definition: Option<Value>,
    pub enabled: Option<bool>,
    pub schedule: Option<String>,
}

#[utoipa::path(
    get, path = "/api/v1/rules", tag = "rules",
    params(("limit" = Option<i64>, Query), ("offset" = Option<i64>, Query)),
    responses((status = 200, body = [RuleRead])),
    security(("bearer_auth" = []))
)]
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<RuleRead>>, ApiError> {
    user.require(Role::Viewer)?;
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let offset = q.offset.unwrap_or(0).max(0);
    let rows = sqlx::query(
        "SELECT id, name, version, definition, enabled, schedule, created_at, updated_at \
         FROM rule WHERE branch_id = ? ORDER BY id ASC LIMIT ? OFFSET ?",
    )
    .bind(DEFAULT_BRANCH_ID)
    .bind(limit)
    .bind(offset)
    .fetch_all(state.db.pool())
    .await?;
    rows.into_iter()
        .map(row_to_rule)
        .collect::<Result<_, _>>()
        .map(Json)
}

#[utoipa::path(
    post, path = "/api/v1/rules", tag = "rules",
    request_body = RuleCreate,
    responses((status = 201, body = RuleRead), (status = 403), (status = 409)),
    security(("bearer_auth" = []))
)]
pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<RuleCreate>,
) -> Result<(StatusCode, Json<RuleRead>), ApiError> {
    user.require(Role::Manager)?;
    let now = now_ms();
    let definition = serde_json::to_string(&req.definition)
        .map_err(|e| ApiError::BadRequest(format!("definition not serialisable: {e}")))?;
    let enabled = i64::from(req.enabled.unwrap_or(true));
    let result = sqlx::query(
        "INSERT INTO rule (branch_id, name, version, definition, enabled, schedule, created_at, updated_at) \
         VALUES (?, ?, 1, ?, ?, ?, ?, ?) \
         RETURNING id, name, version, definition, enabled, schedule, created_at, updated_at",
    )
    .bind(DEFAULT_BRANCH_ID)
    .bind(&req.name)
    .bind(&definition)
    .bind(enabled)
    .bind(&req.schedule)
    .bind(now)
    .bind(now)
    .fetch_one(state.db.pool())
    .await;
    match result {
        Ok(row) => Ok((StatusCode::CREATED, Json(row_to_rule(row)?))),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Err(ApiError::Conflict(
            format!("rule name '{}' already exists", req.name),
        )),
        Err(e) => Err(e.into()),
    }
}

#[utoipa::path(
    get, path = "/api/v1/rules/{id}", tag = "rules",
    params(("id" = i64, Path)),
    responses((status = 200, body = RuleRead), (status = 404)),
    security(("bearer_auth" = []))
)]
pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<RuleRead>, ApiError> {
    user.require(Role::Viewer)?;
    let row = sqlx::query(
        "SELECT id, name, version, definition, enabled, schedule, created_at, updated_at \
         FROM rule WHERE id = ? AND branch_id = ?",
    )
    .bind(id)
    .bind(DEFAULT_BRANCH_ID)
    .fetch_optional(state.db.pool())
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(row_to_rule(row)?))
}

#[utoipa::path(
    patch, path = "/api/v1/rules/{id}", tag = "rules",
    params(("id" = i64, Path)),
    request_body = RulePatch,
    responses((status = 200, body = RuleRead), (status = 404), (status = 403)),
    security(("bearer_auth" = []))
)]
pub async fn patch(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
    Json(p): Json<RulePatch>,
) -> Result<Json<RuleRead>, ApiError> {
    user.require(Role::Manager)?;
    let definition_str = match &p.definition {
        Some(v) => Some(
            serde_json::to_string(v)
                .map_err(|e| ApiError::BadRequest(format!("definition not serialisable: {e}")))?,
        ),
        None => None,
    };
    let enabled = p.enabled.map(i64::from);
    let now = now_ms();
    let row = sqlx::query(
        "UPDATE rule SET \
            name = COALESCE(?, name), \
            definition = COALESCE(?, definition), \
            enabled = COALESCE(?, enabled), \
            schedule = COALESCE(?, schedule), \
            updated_at = ? \
         WHERE id = ? AND branch_id = ? \
         RETURNING id, name, version, definition, enabled, schedule, created_at, updated_at",
    )
    .bind(&p.name)
    .bind(&definition_str)
    .bind(enabled)
    .bind(&p.schedule)
    .bind(now)
    .bind(id)
    .bind(DEFAULT_BRANCH_ID)
    .fetch_optional(state.db.pool())
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(row_to_rule(row)?))
}

#[utoipa::path(
    delete, path = "/api/v1/rules/{id}", tag = "rules",
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
    let result = sqlx::query("DELETE FROM rule WHERE id = ? AND branch_id = ?")
        .bind(id)
        .bind(DEFAULT_BRANCH_ID)
        .execute(state.db.pool())
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

fn row_to_rule(row: sqlx::sqlite::SqliteRow) -> Result<RuleRead, ApiError> {
    let definition_text: String = row.get("definition");
    let definition: Value = serde_json::from_str(&definition_text)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("rule definition not valid json: {e}")))?;
    let enabled_int: i64 = row.get("enabled");
    Ok(RuleRead {
        id: row.get("id"),
        name: row.get("name"),
        version: row.get("version"),
        definition,
        enabled: enabled_int != 0,
        schedule: row.get("schedule"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

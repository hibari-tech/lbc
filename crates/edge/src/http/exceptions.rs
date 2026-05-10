//! Exceptions read-only API (`/api/v1/exceptions`).

use axum::extract::{Path, Query, State};
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
pub struct ExceptionRead {
    pub id: i64,
    pub kind: String,
    pub severity: String,
    pub ts: i64,
    pub status: String,
    pub assignee: Option<i64>,
    pub resolution: Option<String>,
    pub evidence_ref: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct ExceptionQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub status: Option<String>,
}

#[utoipa::path(
    get, path = "/api/v1/exceptions", tag = "exceptions",
    params(
        ("limit" = Option<i64>, Query),
        ("offset" = Option<i64>, Query),
        ("status" = Option<String>, Query, description = "open|investigating|confirmed|dismissed"),
    ),
    responses((status = 200, body = [ExceptionRead])),
    security(("bearer_auth" = []))
)]
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Query(q): Query<ExceptionQuery>,
) -> Result<Json<Vec<ExceptionRead>>, ApiError> {
    user.require(Role::Viewer)?;
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let offset = q.offset.unwrap_or(0).max(0);
    let rows = sqlx::query(
        "SELECT id, kind, severity, ts, status, assignee, resolution, evidence_ref, \
                created_at, updated_at \
         FROM exception WHERE branch_id = ? \
           AND (? IS NULL OR status = ?) \
         ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
    )
    .bind(DEFAULT_BRANCH_ID)
    .bind(q.status.as_deref())
    .bind(q.status.as_deref())
    .bind(limit)
    .bind(offset)
    .fetch_all(state.db.pool())
    .await?;
    Ok(Json(rows.into_iter().map(row_to_exception).collect()))
}

#[utoipa::path(
    get, path = "/api/v1/exceptions/{id}", tag = "exceptions",
    params(("id" = i64, Path)),
    responses((status = 200, body = ExceptionRead), (status = 404)),
    security(("bearer_auth" = []))
)]
pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<ExceptionRead>, ApiError> {
    user.require(Role::Viewer)?;
    let row = sqlx::query(
        "SELECT id, kind, severity, ts, status, assignee, resolution, evidence_ref, \
                created_at, updated_at \
         FROM exception WHERE id = ? AND branch_id = ?",
    )
    .bind(id)
    .bind(DEFAULT_BRANCH_ID)
    .fetch_optional(state.db.pool())
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(row_to_exception(row)))
}

fn row_to_exception(row: sqlx::sqlite::SqliteRow) -> ExceptionRead {
    ExceptionRead {
        id: row.get("id"),
        kind: row.get("kind"),
        severity: row.get("severity"),
        ts: row.get("ts"),
        status: row.get("status"),
        assignee: row.get("assignee"),
        resolution: row.get("resolution"),
        evidence_ref: row.get("evidence_ref"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

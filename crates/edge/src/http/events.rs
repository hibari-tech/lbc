//! Events read-only API (`/api/v1/events`).

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;
use utoipa::ToSchema;

use crate::auth::Role;

use super::error::ApiError;
use super::extractors::AuthUser;
use super::AppState;
use super::DEFAULT_BRANCH_ID;

#[derive(Debug, Serialize, ToSchema)]
pub struct EventRead {
    pub id: i64,
    pub device_id: Option<i64>,
    pub kind: String,
    pub ts: i64,
    #[schema(value_type = Object)]
    pub payload: Value,
    pub ingest_ts: i64,
}

#[derive(Debug, Deserialize)]
pub struct EventQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub device_id: Option<i64>,
    /// Lower bound on `ts` (unix ms, inclusive).
    pub since: Option<i64>,
}

#[utoipa::path(
    get, path = "/api/v1/events", tag = "events",
    params(
        ("limit" = Option<i64>, Query),
        ("offset" = Option<i64>, Query),
        ("device_id" = Option<i64>, Query),
        ("since" = Option<i64>, Query, description = "ts >= since (unix ms)"),
    ),
    responses((status = 200, body = [EventRead])),
    security(("bearer_auth" = []))
)]
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Query(q): Query<EventQuery>,
) -> Result<Json<Vec<EventRead>>, ApiError> {
    user.require(Role::Viewer)?;
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let offset = q.offset.unwrap_or(0).max(0);
    let rows = sqlx::query(
        "SELECT id, device_id, kind, ts, payload, ingest_ts FROM event \
         WHERE branch_id = ? \
           AND (? IS NULL OR device_id = ?) \
           AND (? IS NULL OR ts >= ?) \
         ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
    )
    .bind(DEFAULT_BRANCH_ID)
    .bind(q.device_id)
    .bind(q.device_id)
    .bind(q.since)
    .bind(q.since)
    .bind(limit)
    .bind(offset)
    .fetch_all(state.db.pool())
    .await?;
    rows.into_iter()
        .map(row_to_event)
        .collect::<Result<_, _>>()
        .map(Json)
}

#[utoipa::path(
    get, path = "/api/v1/events/{id}", tag = "events",
    params(("id" = i64, Path)),
    responses((status = 200, body = EventRead), (status = 404)),
    security(("bearer_auth" = []))
)]
pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<EventRead>, ApiError> {
    user.require(Role::Viewer)?;
    let row = sqlx::query(
        "SELECT id, device_id, kind, ts, payload, ingest_ts FROM event \
         WHERE id = ? AND branch_id = ?",
    )
    .bind(id)
    .bind(DEFAULT_BRANCH_ID)
    .fetch_optional(state.db.pool())
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(row_to_event(row)?))
}

fn row_to_event(row: sqlx::sqlite::SqliteRow) -> Result<EventRead, ApiError> {
    let payload_text: String = row.get("payload");
    let payload: Value = serde_json::from_str(&payload_text)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("event payload not json: {e}")))?;
    Ok(EventRead {
        id: row.get("id"),
        device_id: row.get("device_id"),
        kind: row.get("kind"),
        ts: row.get("ts"),
        payload,
        ingest_ts: row.get("ingest_ts"),
    })
}

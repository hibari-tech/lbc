//! Hash-chained audit log.
//!
//! Each row stores `prev_hash` (the hash of the previous row, NULL on the
//! first row) and `hash = blake3(prev_hash || canonical_row_bytes)`. Inserts
//! run inside a `BEGIN IMMEDIATE` transaction so the SELECT-then-INSERT
//! sequence cannot race two concurrent writers — sqlite serialises writers
//! anyway, but `IMMEDIATE` promotes the lock up front.

use anyhow::Context as _;
use sqlx::{Row, SqliteConnection};

use super::Db;

#[derive(Debug, Clone)]
pub struct AuditEntry<'a> {
    pub actor: &'a str,
    pub action: &'a str,
    pub entity: &'a str,
    pub before: Option<&'a str>,
    pub after: Option<&'a str>,
    pub ts_ms: i64,
}

#[derive(Debug, Clone)]
pub struct AuditRow {
    pub id: i64,
    pub actor: String,
    pub action: String,
    pub entity: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub ts_ms: i64,
    pub prev_hash: Option<[u8; 32]>,
    pub hash: [u8; 32],
}

impl Db {
    pub async fn audit_append(&self, entry: AuditEntry<'_>) -> anyhow::Result<i64> {
        let mut conn = self.pool().acquire().await.context("acquire audit conn")?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *conn)
            .await
            .context("BEGIN IMMEDIATE")?;
        let result = append_inner(&mut conn, &entry).await;
        let finish = match &result {
            Ok(_) => "COMMIT",
            Err(_) => "ROLLBACK",
        };
        if let Err(e) = sqlx::query(finish).execute(&mut *conn).await {
            tracing::error!(error = %e, op = finish, "failed to finalise audit tx");
        }
        result
    }

    pub async fn audit_verify_chain(&self) -> anyhow::Result<bool> {
        let rows = sqlx::query(
            "SELECT actor, action, entity, before, after, ts, prev_hash, hash \
             FROM audit_log ORDER BY id ASC",
        )
        .fetch_all(self.pool())
        .await
        .context("loading audit rows")?;
        let mut expected_prev: Option<[u8; 32]> = None;
        for row in rows {
            let actor: String = row.try_get("actor")?;
            let action: String = row.try_get("action")?;
            let entity: String = row.try_get("entity")?;
            let before: Option<String> = row.try_get("before")?;
            let after: Option<String> = row.try_get("after")?;
            let ts_ms: i64 = row.try_get("ts")?;
            let prev_hash: Option<Vec<u8>> = row.try_get("prev_hash")?;
            let hash: Vec<u8> = row.try_get("hash")?;

            let prev_array = match prev_hash {
                Some(v) => Some(<[u8; 32]>::try_from(v.as_slice()).context("prev_hash size")?),
                None => None,
            };
            if prev_array != expected_prev {
                return Ok(false);
            }
            let expected = compute_hash(
                prev_array.as_ref(),
                &AuditEntry {
                    actor: &actor,
                    action: &action,
                    entity: &entity,
                    before: before.as_deref(),
                    after: after.as_deref(),
                    ts_ms,
                },
            );
            let stored = <[u8; 32]>::try_from(hash.as_slice()).context("hash size")?;
            if stored != expected {
                return Ok(false);
            }
            expected_prev = Some(stored);
        }
        Ok(true)
    }
}

async fn append_inner(conn: &mut SqliteConnection, entry: &AuditEntry<'_>) -> anyhow::Result<i64> {
    let prev: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
            .fetch_optional(&mut *conn)
            .await
            .context("loading previous audit hash")?;
    let prev_array = match &prev {
        Some(v) => Some(<[u8; 32]>::try_from(v.as_slice()).context("prev_hash size")?),
        None => None,
    };
    let hash = compute_hash(prev_array.as_ref(), entry);
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO audit_log (actor, action, entity, before, after, ts, prev_hash, hash) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(entry.actor)
    .bind(entry.action)
    .bind(entry.entity)
    .bind(entry.before)
    .bind(entry.after)
    .bind(entry.ts_ms)
    .bind(prev.as_deref())
    .bind(hash.as_slice())
    .fetch_one(&mut *conn)
    .await
    .context("inserting audit row")?;
    Ok(id)
}

fn compute_hash(prev: Option<&[u8; 32]>, entry: &AuditEntry<'_>) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    if let Some(p) = prev {
        h.update(p);
    }
    h.update(entry.actor.as_bytes());
    h.update(b"\0");
    h.update(entry.action.as_bytes());
    h.update(b"\0");
    h.update(entry.entity.as_bytes());
    h.update(b"\0");
    if let Some(b) = entry.before {
        h.update(b.as_bytes());
    }
    h.update(b"\0");
    if let Some(a) = entry.after {
        h.update(a.as_bytes());
    }
    h.update(b"\0");
    h.update(&entry.ts_ms.to_be_bytes());
    *h.finalize().as_bytes()
}

//! Administrative helpers used by the CLI.
//!
//! Phase 0 ships a single command — seeding the first administrator. As
//! later phases land (license activation, branch registration), additional
//! commands should grow here and stay decoupled from the HTTP layer.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;

use crate::auth::{password, Role};
use crate::storage::Db;

pub async fn seed_user(
    db: &Db,
    email: &str,
    password_plain: &str,
    role: Role,
) -> anyhow::Result<i64> {
    let existing: Option<i64> = sqlx::query_scalar("SELECT id FROM user WHERE email = ?")
        .bind(email)
        .fetch_optional(db.pool())
        .await
        .context("checking existing user")?;
    if let Some(id) = existing {
        anyhow::bail!("user with email {email} already exists (id={id})");
    }

    let hash = password::hash(password_plain)?;
    let now = now_ms();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO user (email, password_hash, role, branch_scope, created_at, updated_at) \
         VALUES (?, ?, ?, NULL, ?, ?) RETURNING id",
    )
    .bind(email)
    .bind(hash)
    .bind(role.as_str())
    .bind(now)
    .bind(now)
    .fetch_one(db.pool())
    .await
    .context("inserting seeded user")?;
    Ok(id)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

//! SQLite-backed Control Plane storage.
//!
//! Mirrors the edge migration approach: SQL embedded via `include_str!`,
//! applied versions tracked in `_migrations`, idempotent across reopen.
//! WAL mode + 5 s busy timeout. Phase 0 only — production target is
//! Postgres (see `TOFIX.md`).

use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;

struct EmbeddedMigration {
    version: i64,
    description: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[EmbeddedMigration] = &[EmbeddedMigration {
    version: 20_260_510_140_000,
    description: "initial schema",
    sql: include_str!("../migrations/20260510140000_initial_schema.sql"),
}];

#[derive(Clone)]
pub struct Db {
    pool: SqlitePool,
}

impl Db {
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

pub async fn open(path: &Path) -> anyhow::Result<Db> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating database dir {}", parent.display()))?;
        }
    }
    let url = format!("sqlite://{}", path.display());
    let opts = SqliteConnectOptions::from_str(&url)
        .with_context(|| format!("parsing sqlite url {url}"))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5))
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await
        .with_context(|| format!("opening sqlite pool at {}", path.display()))?;
    apply_migrations(&pool)
        .await
        .context("applying database migrations")?;
    Ok(Db { pool })
}

async fn apply_migrations(pool: &SqlitePool) -> anyhow::Result<()> {
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS _migrations (\
            version INTEGER PRIMARY KEY,\
            description TEXT NOT NULL,\
            applied_at INTEGER NOT NULL\
        ) STRICT",
    )
    .execute(pool)
    .await
    .context("creating _migrations table")?;
    for m in MIGRATIONS {
        let already: Option<i64> =
            sqlx::query_scalar("SELECT version FROM _migrations WHERE version = ?")
                .bind(m.version)
                .fetch_optional(pool)
                .await
                .context("checking _migrations")?;
        if already.is_some() {
            continue;
        }
        let mut tx = pool.begin().await.context("begin migration tx")?;
        sqlx::raw_sql(m.sql)
            .execute(&mut *tx)
            .await
            .with_context(|| format!("applying migration {} ({})", m.version, m.description))?;
        sqlx::query("INSERT INTO _migrations (version, description, applied_at) VALUES (?, ?, ?)")
            .bind(m.version)
            .bind(m.description)
            .bind(now_ms())
            .execute(&mut *tx)
            .await
            .context("recording migration")?;
        tx.commit().await.context("commit migration tx")?;
        tracing::info!(
            version = m.version,
            description = m.description,
            "migration applied"
        );
    }
    Ok(())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

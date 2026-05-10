//! SQLite-backed persistent storage for the edge node.
//!
//! Migrations are embedded at compile time (`crates/edge/migrations/`) and
//! applied automatically by [`open`]. The pool is configured for WAL + a
//! 5 s busy timeout; foreign keys are enforced.

pub mod audit;

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context as _;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

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
    MIGRATOR
        .run(&pool)
        .await
        .context("applying database migrations")?;
    Ok(Db { pool })
}

//! LBC Edge Node library.
//!
//! Phase 0 skeleton: tokio runtime + axum HTTP, structured logging, TOML+env
//! config, graceful shutdown on SIGINT/SIGTERM, sqlx storage, content-addressed
//! blob store, password hashing + JWTs, admin-seed CLI.

pub mod admin;
pub mod auth;
pub mod cli;
pub mod http;
pub mod storage;

mod config;
mod logging;
mod shutdown;

use anyhow::Context as _;
use clap::Parser as _;

pub use config::Config;

const DEFAULT_DEV_JWT_SECRET: &str = "INSECURE_DEV_SECRET_CHANGE_ME";

pub fn run() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    let cfg = Config::load()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    match cli.command.unwrap_or(cli::Command::Run) {
        cli::Command::Run => runtime.block_on(serve(cfg)),
        cli::Command::Admin { cmd } => runtime.block_on(run_admin(cfg, cmd)),
    }
}

async fn run_admin(cfg: Config, cmd: cli::AdminCommand) -> anyhow::Result<()> {
    let _log_guard = logging::init(&cfg.logging)?;
    let db = storage::open(&cfg.database.path)
        .await
        .context("opening edge database")?;
    match cmd {
        cli::AdminCommand::Seed {
            email,
            password,
            role,
        } => {
            let id = admin::seed_user(&db, &email, &password, role).await?;
            tracing::info!(id, email = %email, role = %role, "user seeded");
            println!("user seeded: id={id} email={email} role={role}");
        }
    }
    Ok(())
}

async fn serve(cfg: Config) -> anyhow::Result<()> {
    let _log_guard = logging::init(&cfg.logging)?;
    if cfg.auth.jwt_secret == DEFAULT_DEV_JWT_SECRET {
        tracing::warn!(
            "using the built-in dev JWT secret — set LBC_EDGE_AUTH__JWT_SECRET in production"
        );
    }
    let db = storage::open(&cfg.database.path)
        .await
        .context("opening edge database")?;
    tracing::info!(path = %cfg.database.path.display(), "database ready");
    let _blobs = storage::blobs::BlobStore::open(&cfg.blobs.root).context("opening blob store")?;
    tracing::info!(root = %cfg.blobs.root.display(), "blob store ready");
    let session_ttl_secs = u64::try_from(cfg.auth.session_ttl_secs.max(0)).unwrap_or(0);
    let state = http::AppState {
        db,
        jwt_secret: auth::JwtSecret::from_string(&cfg.auth.jwt_secret),
        session_ttl_secs,
    };
    let listener = tokio::net::TcpListener::bind(cfg.server.bind)
        .await
        .with_context(|| format!("binding {}", cfg.server.bind))?;
    let bound = listener.local_addr()?;
    tracing::info!(addr = %bound, version = env!("CARGO_PKG_VERSION"), "lbc-edge listening");
    axum::serve(listener, http::router(state))
        .with_graceful_shutdown(shutdown::signal())
        .await
        .context("axum::serve")?;
    tracing::info!("lbc-edge stopped");
    Ok(())
}

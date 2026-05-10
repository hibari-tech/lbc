//! LBC Edge Node library.
//!
//! Phase 0 skeleton: tokio runtime + axum HTTP, structured logging, TOML+env
//! config, graceful shutdown on SIGINT/SIGTERM.

pub mod http;
pub mod storage;

mod config;
mod logging;
mod shutdown;

use anyhow::Context as _;

pub use config::Config;

pub fn run() -> anyhow::Result<()> {
    let cfg = Config::load()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    runtime.block_on(serve(cfg))
}

async fn serve(cfg: Config) -> anyhow::Result<()> {
    let _log_guard = logging::init(&cfg.logging)?;
    let _db = storage::open(&cfg.database.path)
        .await
        .context("opening edge database")?;
    tracing::info!(path = %cfg.database.path.display(), "database ready");
    let listener = tokio::net::TcpListener::bind(cfg.server.bind)
        .await
        .with_context(|| format!("binding {}", cfg.server.bind))?;
    let bound = listener.local_addr()?;
    tracing::info!(addr = %bound, version = env!("CARGO_PKG_VERSION"), "lbc-edge listening");
    axum::serve(listener, http::router())
        .with_graceful_shutdown(shutdown::signal())
        .await
        .context("axum::serve")?;
    tracing::info!("lbc-edge stopped");
    Ok(())
}

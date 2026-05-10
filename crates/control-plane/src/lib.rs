//! LBC Control Plane library.
//!
//! Phase 0 skeleton: account / branch / license-key / issued-license
//! schema, ed25519 signing, license activation + revocation HTTP routes.

pub mod http;
pub mod signing;
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
    logging::init(&cfg.logging)?;
    let db = storage::open(&cfg.database.path)
        .await
        .context("opening control-plane database")?;
    tracing::info!(path = %cfg.database.path.display(), "database ready");

    let signer = if cfg.signing.key_hex.is_empty() {
        let s = signing::LicenseSigner::ephemeral();
        tracing::warn!(
            public_key = %s.public_key_hex(),
            "no signing key configured; generated an ephemeral one (set LBC_CP_SIGNING__KEY_HEX in production)"
        );
        s
    } else {
        let s = signing::LicenseSigner::from_seed_hex(&cfg.signing.key_hex)
            .context("loading signing key")?;
        tracing::info!(public_key = %s.public_key_hex(), "signing key loaded");
        s
    };

    let state = http::AppState { db, signer };
    let listener = tokio::net::TcpListener::bind(cfg.server.bind)
        .await
        .with_context(|| format!("binding {}", cfg.server.bind))?;
    let bound = listener.local_addr()?;
    tracing::info!(addr = %bound, version = env!("CARGO_PKG_VERSION"), "lbc-control-plane listening");
    axum::serve(listener, http::router(state))
        .with_graceful_shutdown(shutdown::signal())
        .await
        .context("axum::serve")?;
    tracing::info!("lbc-control-plane stopped");
    Ok(())
}

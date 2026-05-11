//! LBC Edge Node library.
//!
//! Phase 0 skeleton: tokio runtime + axum HTTP, structured logging, TOML+env
//! config, graceful shutdown on SIGINT/SIGTERM, sqlx storage, content-addressed
//! blob store, password hashing + JWTs, admin-seed CLI, hardware fingerprint
//! + license activation against the Control Plane.

pub mod actions;
pub mod activate;
pub mod admin;
pub mod auth;
pub mod cli;
pub mod fingerprint;
pub mod heartbeat;
pub mod http;
pub mod license;
pub mod rules;
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
    match cmd {
        cli::AdminCommand::Seed {
            email,
            password,
            role,
        } => {
            let db = storage::open(&cfg.database.path)
                .await
                .context("opening edge database")?;
            let id = admin::seed_user(&db, &email, &password, role).await?;
            tracing::info!(id, email = %email, role = %role, "user seeded");
            println!("user seeded: id={id} email={email} role={role}");
        }
        cli::AdminCommand::Activate {
            license_key,
            branch_name,
            cp_url,
        } => {
            let cp_url = cp_url.unwrap_or(cfg.auth.cp_url.clone());
            let fp = fingerprint::compute();
            let resp = activate::activate(&cp_url, &license_key, &branch_name, &fp)
                .await
                .context("activating against control plane")?;
            license::save(&cfg.auth.license_path, &resp.license).with_context(|| {
                format!("persisting license to {}", cfg.auth.license_path.display())
            })?;
            let state_path = heartbeat::state_path_for(&cfg.auth.license_path);
            let initial = heartbeat::LicenseHealthState {
                last_seen_at: heartbeat::now_ms(),
                issued_license_id: Some(resp.issued_license_id),
            };
            heartbeat::save_state(&state_path, &initial)
                .context("persisting initial heartbeat state")?;
            tracing::info!(
                issued_id = resp.issued_license_id,
                branch_id = resp.branch_id,
                "license activated and persisted"
            );
            println!(
                "activated: issued_license_id={} branch_id={} path={}",
                resp.issued_license_id,
                resp.branch_id,
                cfg.auth.license_path.display()
            );
        }
        cli::AdminCommand::Fingerprint => {
            println!("{}", fingerprint::compute());
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
    let loaded = load_and_log_license(&cfg)?;
    let db = storage::open(&cfg.database.path)
        .await
        .context("opening edge database")?;
    tracing::info!(path = %cfg.database.path.display(), "database ready");
    let _blobs = storage::blobs::BlobStore::open(&cfg.blobs.root).context("opening blob store")?;
    tracing::info!(root = %cfg.blobs.root.display(), "blob store ready");

    let _heartbeat = start_heartbeat_if_configured(&cfg, loaded.as_ref())?;

    let session_ttl_secs = u64::try_from(cfg.auth.session_ttl_secs.max(0)).unwrap_or(0);
    if cfg.actions.allow_private_targets {
        tracing::warn!(
            "actions.allow_private_targets=true — outbound HTTP actions can hit loopback/private/link-local IPs (do NOT enable in production)"
        );
    }
    let rule_engine = rules::RuleEngine::new();
    let state = http::AppState {
        db: db.clone(),
        jwt_secret: auth::JwtSecret::from_string(&cfg.auth.jwt_secret),
        session_ttl_secs,
        rule_engine: rule_engine.clone(),
        actions_cfg: cfg.actions.clone(),
    };
    let _scheduler = rules::scheduler::spawn(
        db.clone(),
        rule_engine,
        cfg.actions.clone(),
        http::DEFAULT_BRANCH_ID,
        cfg.rules.cron_tick_secs,
    );
    tracing::info!(
        tick_secs = cfg.rules.cron_tick_secs,
        "cron scheduler spawned"
    );
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

fn start_heartbeat_if_configured(
    cfg: &Config,
    loaded: Option<&license::LoadedLicense>,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
    let Some(loaded) = loaded else {
        return Ok(None);
    };
    let state_path = heartbeat::state_path_for(&cfg.auth.license_path);
    let mut state = heartbeat::load_state(&state_path)?;
    let Some(issued_id) = state.issued_license_id else {
        tracing::warn!(
            path = %state_path.display(),
            "license present but no issued_license_id in state — skipping heartbeat"
        );
        return Ok(None);
    };
    if state.last_seen_at <= 0 {
        state.last_seen_at = heartbeat::now_ms();
    }
    let handle = heartbeat::HealthHandle::new(state, loaded.payload.grace_period_days);
    let interval = std::time::Duration::from_secs(cfg.auth.heartbeat_interval_secs.max(1));
    tracing::info!(
        interval_secs = cfg.auth.heartbeat_interval_secs,
        grace_days = loaded.payload.grace_period_days,
        "heartbeat task spawned"
    );
    Ok(Some(heartbeat::spawn(
        cfg.auth.cp_url.clone(),
        issued_id,
        loaded.payload.hardware_fingerprint.clone(),
        interval,
        state_path,
        handle,
    )))
}

fn load_and_log_license(cfg: &Config) -> anyhow::Result<Option<license::LoadedLicense>> {
    if cfg.auth.cp_public_key.is_empty() {
        tracing::warn!(
            "no Control Plane public key configured — license verification disabled (set LBC_EDGE_AUTH__CP_PUBLIC_KEY in production)"
        );
        return Ok(None);
    }
    let pubkey = auth::CpPublicKey::from_hex(&cfg.auth.cp_public_key)
        .context("decoding LBC_EDGE_AUTH__CP_PUBLIC_KEY")?;
    match license::load_and_verify(&cfg.auth.license_path, &pubkey)
        .context("loading edge license")?
    {
        Some(loaded) => {
            tracing::info!(
                tier = ?loaded.payload.tier,
                branch_id = loaded.payload.branch_id,
                expires_at = loaded.payload.expiry,
                grace_days = loaded.payload.grace_period_days,
                "license loaded"
            );
            Ok(Some(loaded))
        }
        None => {
            tracing::warn!(
                path = %cfg.auth.license_path.display(),
                "no license file present — run `lbc-edge admin activate` to bind this node"
            );
            Ok(None)
        }
    }
}

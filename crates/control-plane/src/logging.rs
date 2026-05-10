//! tracing initialisation for the control plane.

use anyhow::Context as _;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{fmt, EnvFilter};

use crate::config::LoggingConfig;

pub fn init(cfg: &LoggingConfig) -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&cfg.level))
        .context("building log filter")?;
    let registry = tracing_subscriber::registry().with(filter);
    if cfg.json {
        registry
            .with(fmt::layer().json().with_writer(std::io::stdout))
            .init();
    } else {
        registry
            .with(fmt::layer().with_writer(std::io::stdout))
            .init();
    }
    Ok(())
}

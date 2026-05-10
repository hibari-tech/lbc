//! tracing initialisation.
//!
//! Always emits to stdout (JSON when `logging.json=true`, otherwise pretty).
//! When `logging.file` is set, also emits JSON to a daily-rotated file. The
//! returned [`LogGuard`] must be kept alive for the lifetime of the process —
//! dropping it stops the non-blocking writer thread and may drop pending logs.

use std::path::Path;

use anyhow::Context as _;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{fmt, EnvFilter};

use crate::config::LoggingConfig;

pub struct LogGuard {
    _file: Option<WorkerGuard>,
}

pub fn init(cfg: &LoggingConfig) -> anyhow::Result<LogGuard> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&cfg.level))
        .context("building log filter")?;

    let (file_writer, file_guard) = match cfg.file.as_deref() {
        Some(path) => {
            let (writer, guard) = open_log_file(path)?;
            (Some(writer), Some(guard))
        }
        None => (None, None),
    };

    let registry = tracing_subscriber::registry().with(filter);
    match (cfg.json, file_writer) {
        (false, None) => registry
            .with(fmt::layer().with_writer(std::io::stdout))
            .init(),
        (true, None) => registry
            .with(fmt::layer().json().with_writer(std::io::stdout))
            .init(),
        (false, Some(writer)) => registry
            .with(fmt::layer().with_writer(std::io::stdout))
            .with(fmt::layer().json().with_writer(writer))
            .init(),
        (true, Some(writer)) => registry
            .with(fmt::layer().json().with_writer(std::io::stdout))
            .with(fmt::layer().json().with_writer(writer))
            .init(),
    }

    Ok(LogGuard { _file: file_guard })
}

fn open_log_file(path: &Path) -> anyhow::Result<(NonBlocking, WorkerGuard)> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("lbc-edge.log"));
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating log directory {}", dir.display()))?;
    let appender = tracing_appender::rolling::daily(dir, name);
    Ok(tracing_appender::non_blocking(appender))
}

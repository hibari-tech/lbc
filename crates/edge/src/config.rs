//! Edge node configuration.
//!
//! Layered: built-in defaults < `lbc-edge.toml` (or `$LBC_EDGE_CONFIG`) <
//! `LBC_EDGE_*` environment variables. Nested fields use `__` as separator,
//! e.g. `LBC_EDGE_SERVER__BIND=0.0.0.0:8080`.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use anyhow::Context as _;
use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind: SocketAddr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub json: bool,
    pub file: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 7878)),
            },
            logging: LoggingConfig {
                level: "info".into(),
                json: false,
                file: None,
            },
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let path = std::env::var("LBC_EDGE_CONFIG").unwrap_or_else(|_| "lbc-edge.toml".to_string());
        Figment::from(Serialized::defaults(Self::default()))
            .merge(Toml::file(&path))
            .merge(Env::prefixed("LBC_EDGE_").split("__"))
            .extract()
            .context("parsing edge config")
    }
}

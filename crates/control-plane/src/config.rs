//! Control Plane configuration loader.

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
    pub database: DatabaseConfig,
    pub signing: SigningConfig,
    #[serde(default)]
    pub admin_auth: AdminAuthConfig,
}

/// HTTP Basic gate for the `/admin/*` routes. An empty
/// `password_hash` disables the gate entirely (dev default) — the
/// runtime logs a loud warn at boot in that case. `password_hash`
/// must be a full argon2 PHC string (e.g.
/// `$argon2id$v=19$m=...$...$...`); generate one with
/// `lbc-control-plane admin hash-password`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAuthConfig {
    #[serde(default = "default_admin_username")]
    pub username: String,
    #[serde(default)]
    pub password_hash: String,
    /// Realm string surfaced in `WWW-Authenticate`. Browsers show
    /// this in the credentials prompt.
    #[serde(default = "default_admin_realm")]
    pub realm: String,
}

fn default_admin_username() -> String {
    "admin".into()
}

fn default_admin_realm() -> String {
    "lbc-admin".into()
}

impl Default for AdminAuthConfig {
    fn default() -> Self {
        Self {
            username: default_admin_username(),
            password_hash: String::new(),
            realm: default_admin_realm(),
        }
    }
}

impl AdminAuthConfig {
    pub fn enabled(&self) -> bool {
        !self.password_hash.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind: SocketAddr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: PathBuf,
}

/// Ed25519 signing key. If `key_hex` is empty an ephemeral key is generated
/// at boot — the public key is logged so devs can wire edge verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningConfig {
    pub key_hex: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 7979)),
            },
            logging: LoggingConfig {
                level: "info".into(),
                json: false,
            },
            database: DatabaseConfig {
                path: PathBuf::from("lbc-control-plane.db"),
            },
            signing: SigningConfig {
                key_hex: String::new(),
            },
            admin_auth: AdminAuthConfig::default(),
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let path =
            std::env::var("LBC_CP_CONFIG").unwrap_or_else(|_| "lbc-control-plane.toml".to_string());
        Figment::from(Serialized::defaults(Self::default()))
            .merge(Toml::file(&path))
            .merge(Env::prefixed("LBC_CP_").split("__"))
            .extract()
            .context("parsing control plane config")
    }
}

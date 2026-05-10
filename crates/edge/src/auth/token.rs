//! Session JWTs (HS256).
//!
//! Tokens carry the user id, role, issued-at, and expiry. The signing key
//! is a wrapper around the configured shared secret bytes; treat it as
//! sensitive material — store via `LBC_EDGE_AUTH__JWT_SECRET` or in a
//! key file referenced from the config.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use super::Role;

#[derive(Clone)]
pub struct JwtSecret(Arc<Vec<u8>>);

impl JwtSecret {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(Arc::new(bytes.into()))
    }

    pub fn from_string(s: &str) -> Self {
        Self::new(s.as_bytes().to_vec())
    }

    fn encoding(&self) -> EncodingKey {
        EncodingKey::from_secret(&self.0)
    }

    fn decoding(&self) -> DecodingKey {
        DecodingKey::from_secret(&self.0)
    }
}

impl std::fmt::Debug for JwtSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtSecret")
            .field("len", &self.0.len())
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i64,
    pub role: Role,
    pub iat: i64,
    pub exp: i64,
    /// Optional list of branch ids the user is scoped to. `None` = unrestricted.
    /// Forward-compat with §0.9 license activation; §0.6 always issues `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch_scope: Option<Vec<i64>>,
}

pub fn issue(
    secret: &JwtSecret,
    user_id: i64,
    role: Role,
    ttl_secs: i64,
) -> anyhow::Result<String> {
    let now = now_secs();
    let claims = Claims {
        sub: user_id,
        role,
        iat: now,
        exp: now.saturating_add(ttl_secs),
        branch_scope: None,
    };
    encode(&Header::new(Algorithm::HS256), &claims, &secret.encoding()).context("encoding jwt")
}

pub fn verify(secret: &JwtSecret, token: &str) -> anyhow::Result<Claims> {
    let validation = Validation::new(Algorithm::HS256);
    let data = decode::<Claims>(token, &secret.decoding(), &validation).context("decoding jwt")?;
    Ok(data.claims)
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

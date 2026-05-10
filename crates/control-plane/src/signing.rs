//! Ed25519 signing key for issued licenses.
//!
//! The Control Plane holds the signing private key. Edge nodes embed the
//! corresponding public key (out of band, or queried over a trusted
//! channel) and call [`shared::license::SignedLicense::verify`].
//!
//! Phase 0 supports two key sources:
//!  * Hex-encoded 32-byte seed via `LBC_CP_SIGNING_KEY_HEX` env / config.
//!  * On first start with no key configured, generate an ephemeral key
//!    and log a loud warning (the public key is logged so devs can wire
//!    edge verification against it).

use std::sync::Arc;

use anyhow::Context as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use rand_core::OsRng;
use shared::license::{LicensePayload, SignedLicense};

#[derive(Clone)]
pub struct LicenseSigner {
    inner: Arc<SigningKey>,
}

impl LicenseSigner {
    pub fn from_seed_hex(seed_hex: &str) -> anyhow::Result<Self> {
        let bytes = decode_hex(seed_hex).context("decoding signing key hex")?;
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .context("signing key seed must be 32 bytes (64 hex chars)")?;
        Ok(Self {
            inner: Arc::new(SigningKey::from_bytes(&seed)),
        })
    }

    pub fn ephemeral() -> Self {
        Self {
            inner: Arc::new(SigningKey::generate(&mut OsRng)),
        }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.inner.verifying_key().to_bytes()
    }

    pub fn public_key_hex(&self) -> String {
        encode_hex(&self.public_key_bytes())
    }

    pub fn sign(&self, payload: LicensePayload) -> anyhow::Result<SignedLicense> {
        let bytes = serde_json::to_vec(&payload).context("serialising payload for signing")?;
        let signature: Signature = self.inner.sign(&bytes);
        Ok(SignedLicense {
            payload,
            signature: signature.to_bytes().to_vec(),
        })
    }
}

impl std::fmt::Debug for LicenseSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LicenseSigner")
            .field("public_key", &self.public_key_hex())
            .finish()
    }
}

pub(crate) fn decode_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        anyhow::bail!("odd-length hex string");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(out)
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(hex_char(b >> 4));
        out.push(hex_char(b & 0xf));
    }
    out
}

fn nibble(c: u8) -> anyhow::Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => anyhow::bail!("invalid hex character"),
    }
}

fn hex_char(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + n - 10) as char,
    }
}

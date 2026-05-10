//! Control-Plane public key — used to verify license signatures.
//!
//! The 32-byte raw ed25519 public key is configured by the operator
//! (typically copied from the CP's first-boot warning log) and stored
//! as a hex string in the edge's TOML / env config.

use anyhow::Context as _;

#[derive(Clone)]
pub struct CpPublicKey([u8; 32]);

impl CpPublicKey {
    pub fn from_hex(hex: &str) -> anyhow::Result<Self> {
        if hex.len() != 64 {
            anyhow::bail!(
                "CP public key must be 64 hex chars (32 raw bytes); got {}",
                hex.len()
            );
        }
        let mut out = [0u8; 32];
        for i in 0..32 {
            let pair = &hex[i * 2..i * 2 + 2];
            out[i] = u8::from_str_radix(pair, 16)
                .with_context(|| format!("invalid hex byte at offset {i}: {pair}"))?;
        }
        Ok(Self(out))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

impl std::fmt::Debug for CpPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CpPublicKey").field(&self.to_hex()).finish()
    }
}

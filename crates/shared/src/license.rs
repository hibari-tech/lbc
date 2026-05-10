//! License payload + ed25519 verification used by both edge and control plane.
//!
//! The control plane holds the private signing key; edge nodes embed the
//! corresponding public key and verify every license they receive.
//! Serialisation for signing is canonical JSON via `serde_json::to_vec` of
//! the payload struct — both sides must derive `Serialize` field order
//! identically (which `#[derive(Serialize)]` does).

use anyhow::Context as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

/// License tiers — sold differentiator. See `lbcspec.md` §7.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Free,
    Trial,
    Starter,
    Pro,
    Enterprise,
}

/// Canonical license payload signed by the Control Plane.
///
/// Field order determines the byte-stream signed; do not reorder once any
/// licenses have shipped. Add new optional fields at the end.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    pub customer_id: String,
    pub tier: Tier,
    pub feature_flags: Vec<String>,
    pub branch_count: u32,
    /// Branch id this license is bound to (Control Plane assigns).
    pub branch_id: i64,
    /// Hardware fingerprint the issuing edge presented at activation.
    pub hardware_fingerprint: String,
    /// Unix epoch seconds.
    pub issued_at: i64,
    /// Unix epoch seconds. `0` = no calendar expiry.
    pub expiry: i64,
    /// Days the edge can run after `last_seen` before degraded mode kicks in.
    pub grace_period_days: u32,
}

/// A `LicensePayload` together with its ed25519 signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedLicense {
    pub payload: LicensePayload,
    /// Ed25519 signature over `serde_json::to_vec(&payload)`. Hex-encoded
    /// for transport; binary at rest.
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

impl SignedLicense {
    /// Verify the signature with the given Control-Plane public key bytes
    /// (32 bytes raw ed25519). Returns the inner payload on success.
    pub fn verify(&self, public_key: &[u8; 32]) -> anyhow::Result<&LicensePayload> {
        let key = VerifyingKey::from_bytes(public_key).context("invalid public key bytes")?;
        let bytes = serde_json::to_vec(&self.payload).context("re-serialising license payload")?;
        let signature_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .context("signature must be 64 bytes")?;
        let signature = Signature::from_bytes(&signature_bytes);
        key.verify(&bytes, &signature)
            .context("license signature does not verify")?;
        Ok(&self.payload)
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        decode(&s).map_err(serde::de::Error::custom)
    }

    fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(nibble(b >> 4));
            out.push(nibble(b & 0xf));
        }
        out
    }

    fn nibble(n: u8) -> char {
        match n {
            0..=9 => (b'0' + n) as char,
            _ => (b'a' + n - 10) as char,
        }
    }

    fn decode(s: &str) -> Result<Vec<u8>, &'static str> {
        if s.len() % 2 != 0 {
            return Err("odd-length hex string");
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        for pair in s.as_bytes().chunks_exact(2) {
            let hi = from_nibble(pair[0])?;
            let lo = from_nibble(pair[1])?;
            out.push((hi << 4) | lo);
        }
        Ok(out)
    }

    fn from_nibble(c: u8) -> Result<u8, &'static str> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err("invalid hex character"),
        }
    }
}

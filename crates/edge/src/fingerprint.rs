//! Hardware fingerprint for license binding.
//!
//! Phase 0 ships a deliberately simple fingerprint: blake3 hash of the
//! hostname plus the primary non-virtual MAC. This is enough to bind a
//! license to a specific machine for development; per `lbcspec.md` §7.3,
//! the production fingerprint must add CPU brand, motherboard / system
//! serial, TPM 2.0 endorsement key, and OS install id, with N-of-M
//! tolerance for partial change. That work is tracked as a Phase 1 TOFIX
//! item — see `TOFIX.md`.

use mac_address::get_mac_address;

/// Hex blake3 digest produced by [`compute`].
pub type Fingerprint = String;

pub fn compute() -> Fingerprint {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"lbc-fingerprint-v0\0");

    let host = gethostname::gethostname();
    hasher.update(host.as_encoded_bytes());
    hasher.update(b"\0");

    if let Ok(Some(mac)) = get_mac_address() {
        hasher.update(&mac.bytes());
    }
    hasher.update(b"\0");

    hasher.finalize().to_hex().to_string()
}

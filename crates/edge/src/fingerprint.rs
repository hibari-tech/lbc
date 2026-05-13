//! Hardware fingerprint for license binding.
//!
//! Builds a stable digest from a structured set of hardware
//! components rather than the Phase-0 hostname-plus-MAC concatenation.
//! The full §7.3 vision is a multi-component identity (CPU brand,
//! motherboard / system serial, TPM endorsement key, OS install id)
//! with N-of-M tolerant matching so a single component change (NIC
//! swap, motherboard battery reset) doesn't invalidate the license.
//! This module covers the **component-collection** half: probe every
//! source available on the host, drop the ones we can't read, and
//! hash the canonical-JSON of what's left. The tolerant-matching
//! half — comparing component-by-component on the Control Plane and
//! accepting ≥K of N — is the follow-up tracked in `TOFIX.md`.
//!
//! Component list:
//!
//! * `os_install_id` — `/etc/machine-id` (Linux). The most stable
//!   anchor across reboots; survives motherboard / NIC changes.
//! * `cpu_brand` — first `model name` from `/proc/cpuinfo`.
//! * `product_uuid` — `/sys/class/dmi/id/product_uuid`. SMBIOS;
//!   often readable only by root.
//! * `product_serial` — `/sys/class/dmi/id/product_serial`. Same.
//! * `board_serial` — `/sys/class/dmi/id/board_serial`. Same.
//! * `primary_mac` — first non-virtual MAC.
//! * `hostname` — kernel hostname.
//!
//! On non-Linux hosts the `/sys` / `/proc` / `/etc/machine-id`
//! reads silently fail and the corresponding components are
//! absent — the digest still differs from a v0 fingerprint because
//! the canonical-JSON wrapper changes the input shape entirely.
//!
//! The version label baked into the hasher (`lbc-fingerprint-v1`)
//! intentionally invalidates every pre-existing fingerprint —
//! re-activation is already required after the heartbeat
//! bearer-secret rollout, so the operator pays the cost once.

use std::collections::BTreeMap;
use std::path::Path;

use mac_address::get_mac_address;

/// Hex BLAKE3 digest produced by [`compute`].
pub type Fingerprint = String;

const VERSION_LABEL: &[u8] = b"lbc-fingerprint-v1\0";

/// Probe every available component and return the canonical map. A
/// `BTreeMap` so the JSON encoding has sorted keys by construction —
/// critical for digest stability.
pub fn collect_components() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();

    insert_if_some(&mut out, "hostname", hostname());
    insert_if_some(&mut out, "primary_mac", primary_mac());
    insert_if_some(&mut out, "os_install_id", read_trim("/etc/machine-id"));
    insert_if_some(
        &mut out,
        "product_uuid",
        read_trim("/sys/class/dmi/id/product_uuid"),
    );
    insert_if_some(
        &mut out,
        "product_serial",
        read_trim("/sys/class/dmi/id/product_serial"),
    );
    insert_if_some(
        &mut out,
        "board_serial",
        read_trim("/sys/class/dmi/id/board_serial"),
    );
    insert_if_some(&mut out, "cpu_brand", cpu_brand());

    out
}

pub fn compute() -> Fingerprint {
    let components = collect_components();
    // serde_json on a BTreeMap emits keys in sort order, which is
    // exactly what we need for stability across calls / hosts.
    let canonical = serde_json::to_vec(&components).expect("serialising a string map cannot fail");
    let mut hasher = blake3::Hasher::new();
    hasher.update(VERSION_LABEL);
    hasher.update(&canonical);
    hasher.finalize().to_hex().to_string()
}

fn insert_if_some(map: &mut BTreeMap<String, String>, key: &str, value: Option<String>) {
    if let Some(v) = value {
        // Skip blanks too: some DMI fields read as empty strings on
        // VMs / cloud hosts and would otherwise add noise without
        // identifying anything.
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            map.insert(key.into(), trimmed.into());
        }
    }
}

fn hostname() -> Option<String> {
    let host = gethostname::gethostname();
    let s = host.to_string_lossy().into_owned();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn primary_mac() -> Option<String> {
    match get_mac_address() {
        Ok(Some(mac)) => Some(mac.to_string()),
        _ => None,
    }
}

fn read_trim<P: AsRef<Path>>(path: P) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|s| s.trim().into())
}

fn cpu_brand() -> Option<String> {
    let raw = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    for line in raw.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim() == "model name" {
                let trimmed = v.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.into());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_is_stable_across_calls() {
        let a = compute();
        let b = compute();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64, "blake3 hex is 64 chars");
    }

    #[test]
    fn collect_components_includes_hostname() {
        // hostname() relies on the libc `gethostname` syscall which
        // is universally present; every host should emit at least
        // this one field.
        let c = collect_components();
        assert!(
            c.contains_key("hostname"),
            "hostname must always be present, got: {c:?}"
        );
    }

    #[test]
    fn canonical_json_keys_are_sorted() {
        // Build a deliberately out-of-order input to prove
        // serialization sorts, not just our insertion order.
        let mut m: BTreeMap<String, String> = BTreeMap::new();
        m.insert("zebra".into(), "z".into());
        m.insert("alpha".into(), "a".into());
        m.insert("middle".into(), "m".into());
        let text = serde_json::to_string(&m).unwrap();
        let alpha_pos = text.find("alpha").unwrap();
        let middle_pos = text.find("middle").unwrap();
        let zebra_pos = text.find("zebra").unwrap();
        assert!(
            alpha_pos < middle_pos && middle_pos < zebra_pos,
            "keys must be sorted in canonical JSON: {text}"
        );
    }

    #[test]
    fn insert_if_some_skips_blank_values() {
        let mut m = BTreeMap::new();
        insert_if_some(&mut m, "a", Some(String::new()));
        insert_if_some(&mut m, "b", Some("   ".into()));
        assert!(m.is_empty(), "blank values must be skipped");
        insert_if_some(&mut m, "k", Some("v".into()));
        assert_eq!(m.get("k"), Some(&"v".to_string()));
    }

    #[test]
    fn insert_if_some_skips_none() {
        let mut m = BTreeMap::new();
        insert_if_some(&mut m, "k", None);
        assert!(m.is_empty());
    }

    #[test]
    fn read_trim_returns_none_for_missing_path() {
        // Pick a path that's almost certainly absent. read_trim
        // must swallow the IO error and return None rather than
        // panicking — the whole probe surface depends on this.
        assert!(read_trim("/this/path/does/not/exist/lbc-fingerprint-probe").is_none());
    }

    #[test]
    fn digest_changes_when_components_change() {
        // Indirect test of canonical-JSON sensitivity: two
        // single-key maps with different values must produce
        // different digests. Mirrors what happens when one
        // component drifts on a host.
        let mut a: BTreeMap<String, String> = BTreeMap::new();
        a.insert("k".into(), "1".into());
        let mut b = a.clone();
        b.insert("k".into(), "2".into());
        assert_ne!(digest_for(&a), digest_for(&b));
    }

    #[test]
    fn v1_digest_differs_from_hashing_the_same_components_with_v0_label() {
        // Bumping VERSION_LABEL must invalidate v0 digests so the
        // CP-side fingerprint compare doesn't accidentally accept a
        // legacy hostname+MAC hash. Hash the same canonical JSON
        // with the old label and confirm the digest differs.
        let components = collect_components();
        let canonical = serde_json::to_vec(&components).unwrap();
        let mut v0 = blake3::Hasher::new();
        v0.update(b"lbc-fingerprint-v0\0");
        v0.update(&canonical);
        let v0_digest = v0.finalize().to_hex().to_string();
        assert_ne!(compute(), v0_digest);
    }

    fn digest_for(components: &BTreeMap<String, String>) -> String {
        let canonical = serde_json::to_vec(components).unwrap();
        let mut hasher = blake3::Hasher::new();
        hasher.update(VERSION_LABEL);
        hasher.update(&canonical);
        hasher.finalize().to_hex().to_string()
    }
}

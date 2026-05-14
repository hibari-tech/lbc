//! Tolerant fingerprint comparison for Phase-1 N-of-M matching.
//!
//! Both `stored` and `presented` arguments are the canonical JSON
//! produced by `edge::fingerprint::canonical_json` — a sorted-keys
//! `BTreeMap<String, String>` of component name → value. We don't
//! reach into either side's secrets here; this module just decides
//! "do enough components match to count as the same machine?".
//!
//! Rule:
//!
//! * Compute the **overlap** — components present in both maps.
//! * Count how many of those have equal values.
//! * Accept iff `overlap >= MIN_OVERLAP` **and**
//!   `matches >= overlap - MAX_DRIFT`.
//!
//! Concretely with the current constants (`MIN_OVERLAP = 2`,
//! `MAX_DRIFT = 1`): you can lose any one hardware component (NIC
//! swap, motherboard battery reset → product_uuid regenerated,
//! `/etc/machine-id` rebuild on OS reinstall, etc.) and still
//! heartbeat; two simultaneous drifts force re-activation.
//!
//! Components present on only one side are **ignored** — they're
//! neither a match nor a mismatch. That handles the common case
//! where one side ran as root (got DMI serials) and the other
//! didn't, or where probing succeeded once and failed later.
//!
//! Parse failures on either input return `false` — the caller
//! must then fall back to the legacy digest byte-compare. A new
//! activation always seeds a parseable `hardware_components`
//! column, so production traffic only hits the parse-fail path
//! during the back-fill window for pre-existing rows.

use std::collections::BTreeMap;

const MIN_OVERLAP: usize = 2;
const MAX_DRIFT: usize = 1;

pub fn compare_tolerant(stored: &str, presented: &str) -> bool {
    let stored: BTreeMap<String, String> = match serde_json::from_str(stored) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let presented: BTreeMap<String, String> = match serde_json::from_str(presented) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let mut overlap = 0usize;
    let mut matches = 0usize;
    for (key, stored_val) in &stored {
        if let Some(presented_val) = presented.get(key) {
            overlap += 1;
            if stored_val == presented_val {
                matches += 1;
            }
        }
    }
    overlap >= MIN_OVERLAP && matches >= overlap.saturating_sub(MAX_DRIFT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(pairs: &[(&str, &str)]) -> String {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect();
        serde_json::to_string(&map).unwrap()
    }

    #[test]
    fn exact_match_passes() {
        let a = json(&[("hostname", "edge-1"), ("primary_mac", "aa:bb:cc:dd:ee:ff")]);
        assert!(compare_tolerant(&a, &a));
    }

    #[test]
    fn single_drift_with_enough_overlap_passes() {
        // 3 overlap, 1 drift → matches=2, overlap-MAX_DRIFT=2 → accept.
        let stored = json(&[
            ("hostname", "edge-1"),
            ("primary_mac", "aa:bb:cc:dd:ee:ff"),
            ("os_install_id", "abc123"),
        ]);
        let presented = json(&[
            ("hostname", "edge-1"),
            // NIC swap
            ("primary_mac", "11:22:33:44:55:66"),
            ("os_install_id", "abc123"),
        ]);
        assert!(compare_tolerant(&stored, &presented));
    }

    #[test]
    fn two_drifts_rejects() {
        let stored = json(&[
            ("hostname", "edge-1"),
            ("primary_mac", "aa:bb:cc:dd:ee:ff"),
            ("os_install_id", "abc123"),
        ]);
        let presented = json(&[
            // hostname changed AND mac changed
            ("hostname", "edge-2"),
            ("primary_mac", "11:22:33:44:55:66"),
            ("os_install_id", "abc123"),
        ]);
        assert!(!compare_tolerant(&stored, &presented));
    }

    #[test]
    fn minimal_overlap_with_match_passes() {
        // exactly MIN_OVERLAP (2) and 0 drift → matches=2, accept.
        let a = json(&[("hostname", "h"), ("primary_mac", "m")]);
        assert!(compare_tolerant(&a, &a));
    }

    #[test]
    fn minimal_overlap_with_one_drift_passes() {
        // overlap=2, matches=1, overlap-MAX_DRIFT=1 → accept.
        let stored = json(&[("hostname", "h"), ("primary_mac", "old")]);
        let presented = json(&[("hostname", "h"), ("primary_mac", "new")]);
        assert!(compare_tolerant(&stored, &presented));
    }

    #[test]
    fn minimal_overlap_with_two_drifts_rejects() {
        // overlap=2, matches=0 → reject.
        let stored = json(&[("hostname", "h1"), ("primary_mac", "m1")]);
        let presented = json(&[("hostname", "h2"), ("primary_mac", "m2")]);
        assert!(!compare_tolerant(&stored, &presented));
    }

    #[test]
    fn under_overlap_rejects_even_when_exact() {
        // overlap=1, matches=1, but MIN_OVERLAP=2 → reject. Caller
        // is expected to fall back to digest byte-compare here.
        let stored = json(&[("hostname", "h")]);
        let presented = json(&[("hostname", "h"), ("primary_mac", "m")]);
        assert!(!compare_tolerant(&stored, &presented));
    }

    #[test]
    fn disjoint_keys_reject() {
        // overlap=0 → reject regardless of map size.
        let stored = json(&[("hostname", "h"), ("primary_mac", "m")]);
        let presented = json(&[("cpu_brand", "intel"), ("os_install_id", "x")]);
        assert!(!compare_tolerant(&stored, &presented));
    }

    #[test]
    fn empty_inputs_reject() {
        assert!(!compare_tolerant("{}", "{}"));
    }

    #[test]
    fn malformed_json_rejects() {
        let good = json(&[("hostname", "h"), ("primary_mac", "m")]);
        assert!(!compare_tolerant("not json", &good));
        assert!(!compare_tolerant(&good, "not json"));
        assert!(!compare_tolerant("", &good));
    }

    #[test]
    fn extra_components_on_one_side_are_ignored() {
        // Stored has 3 components, presented has only 2 (e.g. lost
        // permission to read DMI). The 2 overlapping match exactly
        // → accept; the extra stored field is not a "mismatch".
        let stored = json(&[
            ("hostname", "h"),
            ("primary_mac", "m"),
            ("os_install_id", "abc"),
        ]);
        let presented = json(&[("hostname", "h"), ("primary_mac", "m")]);
        assert!(compare_tolerant(&stored, &presented));
    }

    #[test]
    fn many_components_tolerate_exactly_one_drift() {
        // 5 overlap, 1 drift → matches=4, overlap-MAX_DRIFT=4 → accept.
        let stored = json(&[
            ("hostname", "h"),
            ("primary_mac", "m"),
            ("os_install_id", "a"),
            ("cpu_brand", "intel"),
            ("product_uuid", "u"),
        ]);
        let presented = json(&[
            ("hostname", "h"),
            ("primary_mac", "DRIFTED"),
            ("os_install_id", "a"),
            ("cpu_brand", "intel"),
            ("product_uuid", "u"),
        ]);
        assert!(compare_tolerant(&stored, &presented));
    }

    #[test]
    fn many_components_reject_two_drifts() {
        let stored = json(&[
            ("hostname", "h"),
            ("primary_mac", "m"),
            ("os_install_id", "a"),
            ("cpu_brand", "intel"),
            ("product_uuid", "u"),
        ]);
        let presented = json(&[
            ("hostname", "h"),
            ("primary_mac", "DRIFTED"),
            ("os_install_id", "a"),
            ("cpu_brand", "DRIFTED"),
            ("product_uuid", "u"),
        ]);
        assert!(!compare_tolerant(&stored, &presented));
    }
}

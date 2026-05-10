# TOFIX

Open issues, flaky tests, deferred fixes. Add on discovery, remove on resolve.

Format:
```
- [YYYY-MM-DD] <area> — <one-line description>. Repro / link.
```

---

## Open

_(none yet)_

## Flaky

_(none yet)_

## Deferred (intentional, with reason)

- [2026-05-10] control-plane DB — currently SQLite for Phase 0 simplicity (no testcontainers, single-binary deploy). Spec §6.1 / TASKS §0.8 target Postgres. Swap before fleet-management goes live in Phase 3; data model is portable across both via sqlx.
- [2026-05-10] edge auth — login has no rate limiting / lockout. argon2 verify is expensive; brute-force protection should land before Phase 1.
- [2026-05-10] edge fingerprint — Phase 0 stub uses hostname + primary MAC only. Spec §7.3 requires CPU brand + motherboard / system serial + TPM EK + OS install id with N-of-M tolerant matching. Re-implement before Phase 1 ships paid tiers.

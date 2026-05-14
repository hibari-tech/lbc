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
- [2026-05-11] control-plane admin web — HTTP Basic gate landed (commit `<filled-in-by-PR>`, argon2-hashed password via `LBC_CP_ADMIN_AUTH__PASSWORD_HASH`), disabled by default with a boot warn. OIDC / SSO per spec §4.9 still pending for Phase 1.

# Changelog

All notable changes to LBC. Newest first. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); semver applies
once we tag a `v1.0.0`.

## Phase 0 — 2026-05-10

First end-to-end pass. Two binaries (`lbc-edge`, `lbc-control-plane`)
talk to each other; an edge node can be activated against a CP, hold a
signed license, heartbeat, and degrade after the configured grace
window. Workspace is green across `cargo {build,fmt,clippy,test,deny}`
on Ubuntu / Windows / macOS.

### Edge node (`lbc-edge`)
- tokio + axum runtime, structured `tracing` logs (pretty stdout +
  optional JSON daily-rotated file), figment config (TOML + env),
  graceful SIGINT/SIGTERM shutdown.
- sqlx + SQLite (WAL, busy timeout, FKs on). Schema v1: `branch`,
  `user`, `device`, `event`, `rule`, `rule_run`, `action_log`,
  `evidence`, `exception`, `case`, `case_exception`, `audit_log`,
  `license`. Hash-chained audit log via blake3 (`Db::audit_append` /
  `audit_verify_chain`). Content-addressed blob store on disk.
- Auth primitives: argon2id passwords, HS256 session JWTs (`Claims {
  sub, role, iat, exp, branch_scope }`), six-role RBAC with
  `has_at_least` ranking. `lbc-edge admin seed` CLI.
- Local API v0 at `/api/v1/...` with `AuthUser` extractor + `ApiError`:
  `auth/login`, `auth/me`, full CRUD on `devices` and `rules`,
  read-only `events` and `exceptions` with pagination/filters,
  `openapi.json` via `utoipa`.
- License lifecycle: `lbc-edge admin activate` posts fingerprint to CP,
  persists signed license; `serve()` verifies signature on every start,
  spawns a background heartbeat task, runs a pure-function grace state
  machine (`Healthy` ↔ `Degraded`).
- Phase-0 fingerprint = blake3(hostname || primary MAC). Real
  CPU/TPM/motherboard + N-of-M matching is queued in `TOFIX.md`.

### Control Plane (`lbc-control-plane`)
- axum + sqlx + SQLite (Postgres swap deferred — see `TOFIX.md`).
  Entities: `account`, `branch`, `license_key` (blake3 key hashes —
  cleartext shown only at creation), `issued_license`.
- ed25519 signing via `ring`/`ed25519-dalek`. Ephemeral key generated
  with a loud public-key warn-log when none is configured.
- API: `POST /api/v1/licenses/activate` (verifies key hash, enforces
  branch-count cap, signs, persists), `POST /licenses/{id}/heartbeat`
  (fingerprint match + revoke check, updates `last_seen`),
  `POST /licenses/{id}/revoke` (idempotent), `openapi.json`.
- Server-rendered admin web at `/admin`: index, accounts list + mint
  form, branches list, issued-licenses list with revoke buttons.
  HTML-escaped inputs, CSRF-naïve and unauthenticated for now —
  bind to localhost or front with an auth proxy.

### Shared (`shared`)
- `LicensePayload`, `SignedLicense`, `Tier { Free, Trial, Starter, Pro,
  Enterprise }`. Hex-on-the-wire / raw-at-rest signature transport.
  `SignedLicense::verify(&pubkey32) -> &payload`.

### CI / build
- GitHub Actions matrix on `{ubuntu, windows, macos}`: fmt + clippy
  with `-D warnings`, full test, `cargo-deny` (replaces `cargo-audit`
  — see `REFLECT.md`).
- Workspace lints set to `unsafe_code = "forbid"`,
  `unused_must_use = "deny"`, `clippy::all = "warn"`.
- Release scaffold workflow tagged for first `v*` push.

### Tests
75 across the workspace:
- edge: 11 http, 10 auth, 5 storage, 5 blobs, 14 activation +
  heartbeat / grace.
- control-plane: 13 license issuance/revoke/heartbeat + 8 admin web.
- 4 doc-tests + small bin-test scaffolds.

### Open / not in Phase 0
- §0.7 — Tauri shell + frontend stack choice (SPIKE-01: Leptos /
  Dioxus / React-fallback). Product call.
- Heartbeat JWT refresh per spec §7.4 — currently fingerprint-only.
- Login rate limiting / lockout.
- Hardware fingerprint hardening (TPM EK, motherboard serial,
  N-of-M matching).
- Postgres on the Control Plane (target before fleet management
  ships in Phase 3).

See `TOFIX.md` for the full deferred list and `TASKS.md` for the
remaining checkboxes per Phase-0 sub-bullet.

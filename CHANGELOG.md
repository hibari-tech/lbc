# Changelog

All notable changes to LBC. Newest first. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); semver applies
once we tag a `v1.0.0`.

## Unreleased — Phase 1

### Added
- **Webhook ingest** (`POST /api/v1/ingest/webhooks/{device_id}`) —
  HMAC-SHA256 verification with per-device secret stored in a new
  `device.webhook_secret` column. Headers: `X-LBC-Timestamp` (unix ms,
  ±5 min skew window) + `X-LBC-Signature` (hex of
  `HMAC_SHA256(secret, "<ts>.<body>")`, constant-time-compared).
  Persists to `event` table; uses payload's `kind` field if present,
  else `"webhook"`. Spec `lbcspec.md` §4.1 first bullet, §5.4 replay
  protection.
- **Rule debounce (leading-edge)** — rule definitions can carry
  `debounce_secs: <i64>`; the dispatcher fires the rule on the first
  match of a burst and silently suppresses further matches until
  `debounce_secs` of quiet have elapsed from the last match. The
  window slides on every match (whether fired or suppressed), so a
  sustained burst keeps suppressing. New `RuleEngine::record_match`
  / `last_match_at` primitives. Composable with throttle: both checks
  run independently, so a rule can have `throttle_secs: 60` and
  `debounce_secs: 5` to mean "fire at most once a minute, and only
  after the door has been opened at least 5 s apart from the previous
  opening." Trailing-edge debounce (fire-on-burst-end) needs a timer
  and lands later. Spec `lbcspec.md` §4.2.
- **Rule AST cache + per-rule throttle** — `RuleEngine` now caches
  compiled scripts keyed by `(rule_id, version)`. Subsequent evaluations
  of an unchanged rule reuse the AST instead of recompiling per event;
  bumping `rule.version` (e.g. via `PATCH /rules/{id}`) invalidates the
  entry. New `RuleEngine::compiles_observed()` returns the lifetime
  compile count for tests / metrics.
  Rule definitions can also carry `throttle_secs: <i64>`; if set and
  positive, subsequent matches on the same rule are silently suppressed
  until the window has elapsed since the last fire. Suppressed events
  do not produce a `rule_run` row. Spec `lbcspec.md` §4.2 time
  primitives — first slice (debounce / hold-for / cron schedules
  follow the same in-engine pattern in later PRs).
- **HTTP action SSRF guard** — outbound HTTP actions now verify the
  target before the request is sent. Scheme is restricted to
  `http`/`https` (no `file://` etc.); the host (literal or resolved)
  is checked against an IP block-list of loopback / private / link-local
  / multicast / unspecified ranges, which covers the cloud-metadata
  endpoint `169.254.169.254`. Blocked targets surface as `ok=false`
  with `response: "blocked: <reason>"` and persist as an `error` row
  in `action_log`. The `actions.allow_private_targets` config flag
  (env: `LBC_EDGE_ACTIONS__ALLOW_PRIVATE_TARGETS`) is the dev/test
  escape hatch — startup loud-warn-logs when it's true.
- **Action layer (HTTP)** — rules can return a map with an `actions`
  array of action descriptors `{ kind, target, method, headers, body }`.
  Each is dispatched after the matching `rule_run` is persisted. Phase 1
  ships only `kind = "http"` (POST/GET/etc via `reqwest`, 15 s timeout,
  responses truncated to 16 KiB); SMTP / FTP / MQTT / Modbus / Nx Witness
  share the same shape and land as follow-up modules. Every dispatch
  attempt — success, 5xx, or transport failure — is persisted to the
  `action_log` table linked to the originating `rule_run`. Closes the
  webhook → rule → action → audit-log loop end-to-end.
- **Rule engine MVP** (Rhai sandbox) — `edge::rules::RuleEngine`
  compiles and evaluates user scripts against incoming events. Rules
  whose `definition` JSON has a top-level `script` string are
  evaluated; the script gets `event` in scope as a map (`event.kind`,
  `event.ts`, `event.device_id`, `event.payload`) and returns a truthy
  value to fire. Sandbox bounds: 100k op limit, 20 call levels, 64KB
  string, 10k array, 1k map. Matched rules persist `rule_run` rows
  with the triggering event id. Wired into webhook ingest so a real
  POST that matches a rule produces a `rule_run` row by the time the
  response returns. Visual-builder rules (those without a `script`)
  are silently skipped — they land once §0.7 / SPIKE-01 picks the UI
  stack. Action layer (HTTP / SMTP / FTP / Nx) is the next slice.

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

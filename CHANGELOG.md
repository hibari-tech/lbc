# Changelog

All notable changes to LBC. Newest first. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); semver applies
once we tag a `v1.0.0`.

## Unreleased — Phase 1

### Added
- **N-of-M tolerant fingerprint matching (§7.3 part 2)** — new
  `shared::fingerprint::compare_tolerant(stored, presented)`
  helper: parses both arguments as canonical-JSON component maps,
  counts overlap (keys present on both sides), and accepts when
  there are ≥2 overlapping components and at most 1 differs. A
  single drift (NIC swap, motherboard battery reset, OS
  re-install) no longer forces re-activation; two simultaneous
  drifts still do. New migration `20260511200000_hardware_components.sql`
  adds a nullable `issued_license.hardware_components TEXT`. The
  activation endpoint accepts an optional `hardware_components`
  field (canonical JSON) and persists it. The heartbeat endpoint
  accepts an optional `hardware_components` field and, when both
  sides are populated, uses tolerant comparison; otherwise it
  falls back to the Phase-0 digest byte-compare so pre-migration
  rows and legacy edges keep working. The edge now exposes
  `fingerprint::canonical_json()` and the heartbeat client
  re-derives this every tick so the CP sees live hardware state.
  13 unit tests on the algorithm, 4 integration tests on the
  wired path (accepts single drift, rejects double drift, both
  fallback directions). Closes the remaining half of the §7.3
  TOFIX entry.

### Changed
- **Edge fingerprint — multi-component probe (§7.3 part 1)** —
  `fingerprint::compute()` now gathers a structured component map
  rather than concatenating hostname + MAC. New components on Linux:
  `os_install_id` (`/etc/machine-id`), `cpu_brand` (first
  `model name` from `/proc/cpuinfo`), `product_uuid`,
  `product_serial`, `board_serial` (`/sys/class/dmi/id/`). Existing
  `hostname` + `primary_mac` are preserved. Each probe handles a
  missing/unreadable source by dropping that component — non-Linux
  hosts naturally land with `hostname` + `primary_mac` only.
  The map is serialised as canonical JSON (sorted keys via
  `BTreeMap`) and hashed with BLAKE3 under a bumped version label
  `lbc-fingerprint-v1`, so every pre-existing digest is
  invalidated. Re-activation is already required after the
  heartbeat bearer-secret rollout, so operators pay the cost once.
  Public API surface is unchanged: `compute() -> String` still
  returns a 64-char hex digest. New `collect_components() ->
  BTreeMap<String, String>` exposed for diagnostics. The N-of-M
  tolerant comparator on the Control Plane heartbeat handler is
  the next step — tracked in TOFIX. 8 inline tests.

### Fixed
- **HTTP action DNS-rebinding TOCTOU** — `actions::http` used to
  resolve the target hostname for validation, then let reqwest
  re-resolve at connect time. A rebind-friendly resolver could
  return a public IP for the first lookup and a private IP for the
  second. The validation function (`check_target` →
  `resolve_and_pin`) now returns the resolved `Vec<SocketAddr>`,
  and `execute()` pins those exact addresses into the reqwest
  client via `ClientBuilder::resolve_to_addrs`. Reqwest's connect
  step now uses the pinned IPs and never re-consults the resolver
  for that hostname. HTTPS SNI / cert validation still use the URL
  hostname, so cert pinning is unaffected. New inline tests cover
  every gate branch plus a round-trip that proves the pinning
  actually overrides DNS. Closes TOFIX 2026-05-10 "action-layer
  SSRF — DNS-rebinding TOCTOU window".

### Added
- **Admin web HTTP Basic gate** — every `/admin/*` route on the
  Control Plane is now wrapped in a middleware that requires
  `Authorization: Basic <base64(user:pass)>`. The configured
  password is stored as an argon2 PHC string under
  `admin_auth.password_hash` (env: `LBC_CP_ADMIN_AUTH__PASSWORD_HASH`),
  with `admin_auth.username` (default `admin`) and `admin_auth.realm`
  (default `lbc-admin`) as siblings. Empty `password_hash` keeps the
  Phase-0 dev behaviour — no gate — but the runtime now logs a loud
  `warn` at boot in that case. Username is compared in constant
  time; password is verified with argon2. 401 responses carry a
  `WWW-Authenticate: Basic realm="..."` header so browsers prompt
  for credentials. The public API surface (`/api/v1/*`, `/healthz`)
  is untouched. `AppState` gains `admin_gate: AdminGate`. Stopgap
  before OIDC/SSO (spec §4.9). Closes the Phase-0 TOFIX entry
  "control-plane admin web — no authentication in Phase 0".
- **Heartbeat bearer-secret auth** — `POST /api/v1/licenses/{id}/heartbeat`
  now requires `Authorization: Bearer <token>`. At activation time the
  Control Plane mints 32 random bytes per issued license, hex-encodes
  them, returns the cleartext exactly once in the activation response
  as `heartbeat_token`, and persists only the BLAKE3 hash in the new
  `issued_license.heartbeat_secret_hash` column. The edge stores the
  token in `<license>.state.json` and presents it on every heartbeat;
  the CP recomputes BLAKE3 and constant-time-compares. Replaces the
  Phase-0 fingerprint-only credential: the fingerprint is now a
  second factor, not the sole one. Migration
  `20260511190000_heartbeat_bearer_secret.sql` backfills existing
  rows with random unknowable bytes so legacy activations fail closed
  (operator must re-run `lbc-edge admin activate`). The `404` for
  unknown ids on the heartbeat endpoint is now `401` so id
  enumeration is no easier than guessing the secret. New
  `ApiError::Unauthorized` on the Control Plane. Closes TOFIX
  2026-05-10 "control-plane heartbeat auth — fingerprint as sole
  credential".
- **Login brute-force gate** — `POST /api/v1/auth/login` now tracks
  consecutive failed attempts per account in three new `user` columns
  (`failed_login_count`, `last_failed_login_ms`, `locked_until_ms`).
  After `auth.max_failed_login_attempts` (default 5) consecutive
  failures the account locks for `auth.login_lockout_secs`
  (default 900 = 15 min); a locked account returns `401 Unauthorized`
  even for the correct password — same status as a wrong-password
  response, so probing lock state is no easier than guessing the
  password. A successful login zeroes the counter and clears the
  lock. Unknown emails do **not** touch any counter (you can't lock
  an account that doesn't exist). Set
  `LBC_EDGE_AUTH__MAX_FAILED_LOGIN_ATTEMPTS=0` to disable the gate
  entirely. New `edge::http::LoginRateLimit` (added to `AppState`).
  Migration `20260511180000_user_login_rate_limit.sql`. Closes TOFIX
  2026-05-10 "edge auth — login has no rate limiting / lockout".
- **Nx Witness action** — `kind: "nx"` action descriptors post a
  Generic Event to a configured Nx Witness Media Server
  (`POST <server>/api/createEvent`). Server URL, HTTP Basic
  credentials, and an `accept_invalid_certs` toggle (Nx ships with a
  self-signed cert) live in `actions.nx.*`; rule scripts pass
  `subject` (→ `caption`), optional `source` (defaults to
  `"lbc-edge"`), and `body` (string sent as-is, JSON stringified).
  Empty `server` disables Nx and records an explicit "Nx not
  configured" error row. Like Modbus and FTP, the HTTP SSRF guard
  does **not** apply — Nx is an internal-LAN VMS. New
  `ActionRequest::source`, `NxConfig`, and `actions::nx::plan_event`
  (pure validator) so URL / caption / description parsing is testable
  without a Media Server. Closes the Phase-1 action set
  (HTTP / SMTP / MQTT / Modbus / FTP / Nx) — spec §4.3.
- **FTP action** — `kind: "ftp"` action descriptors upload a small
  evidence payload to an internal FTP server. The `target` is a full
  URL — `ftp://[user[:pass]@]host[:port]/path` — so the destination
  filename, credentials, and (optional) non-default port travel
  in-band; anonymous login is used when the URL has no userinfo. The
  request body becomes the file contents (string bodies sent as-is,
  JSON objects/arrays stringified, `null` / missing rejected). Phase
  1 ships plain FTP (RFC 959) over TCP, passive mode, `STOR` only;
  FTPS / SFTP land later if a deployment needs them and the action
  shape stays the same. Per-action connect / login / `TYPE I` /
  `PASV` / `STOR` / `QUIT` with bounded timeouts (5 s connect, 10 s
  per command, 30 s data transfer). Like Modbus, FTP is treated as an
  internal-LAN protocol — the SSRF guard that gates HTTP does **not**
  apply. `actions::ftp::plan_request` is a pure validator so URL /
  body parsing is testable without an FTP server.
- **Modbus/TCP action** — `kind: "modbus"` action descriptors write a
  coil (FC 0x05) or holding register (FC 0x06) on an industrial device
  via `tokio-modbus`. Action carries `target` (literal `host:port`),
  `function` (`write_coil` | `write_register`), `address` (0..=65535),
  `unit_id` (0..=247, default 1), and `body` (bool/int for coils,
  0..=65535 int for registers). Per-action connect / write / disconnect
  with 5 s connect and 10 s write timeouts. Modbus is an industrial LAN
  protocol with no transport auth — the SSRF guard that gates HTTP
  intentionally does **not** apply here. New `ActionRequest` fields:
  `function`, `unit_id`, `address`. `actions::modbus::plan_request` is
  a pure validator so every parse path is testable without a PLC.
  Modbus/RTU (serial) and reads (FC 0x01..0x04) are follow-ups.
- **Rule cron schedules** — fourth `lbcspec.md` §4.2 time primitive. The
  `rule.schedule` column (7-field cron: `sec min hour DoM Month DoW Year`)
  now drives a periodic scheduler task spawned alongside the heartbeat.
  Each tick (interval set via `rules.cron_tick_secs`, default 10 s)
  iterates enabled scheduled rules in the default branch, fires those
  whose next planned fire time has elapsed, and re-plans. First
  observation of a rule **seeds** the next fire — it never fires
  retroactively on edge restart. Scheduled fires emit `rule_run` rows
  with empty `input_event_ids` so the audit trail distinguishes them
  from event-driven runs; actions returned from the script dispatch
  identically to the event path. Throttle / debounce / hold-for are
  intentionally **not** applied — the cron expression already controls
  cadence. New `crates/edge/src/rules/scheduler.rs`, `RulesConfig`
  block, and `RuleEngine::{next_fire_at, set_next_fire_at}` primitives.
- **Webhook ingest** (`POST /api/v1/ingest/webhooks/{device_id}`) —
  HMAC-SHA256 verification with per-device secret stored in a new
  `device.webhook_secret` column. Headers: `X-LBC-Timestamp` (unix ms,
  ±5 min skew window) + `X-LBC-Signature` (hex of
  `HMAC_SHA256(secret, "<ts>.<body>")`, constant-time-compared).
  Persists to `event` table; uses payload's `kind` field if present,
  else `"webhook"`. Spec `lbcspec.md` §4.1 first bullet, §5.4 replay
  protection.
- **Rule hold-for** — third `lbcspec.md` §4.2 time primitive. Rule
  definitions can carry `hold_for_secs: <i64>`; the dispatcher fires
  the rule only once the script has matched continuously for at
  least that many seconds. The first match of a streak doesn't fire
  but starts a hold timer; subsequent matches keep extending the
  streak until the window elapses, at which point the next match
  fires (and the streak resets). Any non-matching event clears the
  streak — the next match starts a fresh hold cycle. Composable with
  throttle / debounce — those checks still apply once hold-for
  satisfies. Use case: "alert if the door has been open for 30 s."
  New `RuleEngine::set_hold_start` / `hold_start_at` / `clear_hold`
  primitives.
- **MQTT action** — `kind: "mqtt"` action descriptors publish to a
  topic on a globally-configured broker via `rumqttc`. Phase 1
  per-action connect / publish / disconnect (no persistent client
  yet; acceptable for current event volumes). Supports QoS 0/1/2,
  retain flag, and optional username/password auth. Body accepts
  string (sent as-is) or JSON (stringified). Empty `server` disables
  MQTT and records an error row. New `ActionRequest` fields:
  `topic`, `qos`, `retain`. `actions::mqtt::plan_publish` is a pure
  validator so the parse paths are testable without a broker.
- **SMTP action** — `kind: "smtp"` action descriptors send email via
  STARTTLS or implicit-TLS to a globally-configured SMTP server.
  Server / port / credentials / default `From:` live in
  `actions.smtp.*` config; rule scripts pass `to`, `subject`, `body`,
  optional `from`. SMTP body accepts plain strings (sent as-is) or
  JSON (stringified). Empty `server` disables SMTP — actions return
  an explicit "SMTP not configured" error row in `action_log` so
  rule authors get a useful signal.
  `ActionRequest` grew optional `to`/`subject`/`from` fields and now
  derives `Default` so existing call sites can `..Default::default()`.
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

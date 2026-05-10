# TASKS

Status legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked

Active phase: **Phase 0 — Foundations**.

---

## Phase 0 — Foundations

### 0.1 Repo + workspace
- [x] cargo workspace skeleton (`shared`, `edge`, `control-plane`, `ui`, `cli`)
- [x] `.gitignore`, `rust-toolchain.toml` (stable + rustfmt + clippy)
- [x] tracking docs (`PLAN.md`, `TASKS.md`, `TOFIX.md`, `REFLECT.md`)
- [x] `rustfmt.toml` + workspace lints in root `Cargo.toml` (clippy `all=warn`, `unsafe_code=forbid`)
- [x] `deny.toml` for `cargo-deny` (license allowlist + advisories + bans)
- [x] `LICENSE` (proprietary placeholder; flagged for legal sign-off)

### 0.2 CI
- [ ] GH Actions: fmt + clippy + test on `{ubuntu, windows, macos}`
- [ ] matrix add `aarch64` via `cross` (Linux) and native runners (mac arm64)
- [ ] `cargo-audit` + `cargo-deny` jobs
- [ ] cache `~/.cargo` and `target/`
- [ ] release workflow scaffold (`cargo-dist`)

### 0.3 Edge — runtime skeleton
- [ ] add `tokio`, `axum`, `tower`, `tracing`, `tracing-subscriber`, `anyhow`
- [ ] `lbc-edge` boots, binds 127.0.0.1, exposes `GET /healthz`
- [ ] structured JSON logging to file + console
- [ ] config loader (`figment` or `config` crate) — file + env
- [ ] graceful shutdown on SIGINT/SIGTERM

### 0.4 Edge — storage
- [ ] add `sqlx` + SQLite (WAL); embedded migrations dir
- [ ] schema v1: `branch`, `device`, `event`, `rule`, `rule_run`, `action_log`, `exception`, `case`, `evidence`, `user`, `audit_log`, `license`
- [ ] hash-chained `audit_log` insert helper
- [ ] content-addressed blob store on filesystem (`blake3`)

### 0.5 Edge — auth + RBAC
- [ ] argon2 password hashing
- [ ] session JWT (short-lived, signed)
- [ ] role enum: `admin | manager | operator | installer | viewer | auditor`
- [ ] middleware: extract user, enforce role per route
- [ ] seed admin via CLI on first run

### 0.6 Edge — Local API v0
- [ ] `/api/v1/healthz`, `/api/v1/version`
- [ ] `/api/v1/auth/login`, `/api/v1/auth/me`
- [ ] CRUD stubs for `devices`, `rules`, `events` (read-only), `exceptions` (read-only)
- [ ] OpenAPI spec generation (`utoipa` or hand-written)

### 0.7 UI — Tauri shell
- [ ] decide frontend (Leptos / Dioxus / React) — 2-wk spike, see PLAN §F.1
- [ ] Tauri v2 project; loads placeholder page
- [ ] Tailwind wired
- [ ] dark mode default
- [ ] i18n resource layout (English only at v1)

### 0.8 Control Plane — skeleton
- [ ] axum service; Postgres via `sqlx`
- [ ] entities: `account`, `branch`, `license_key`, `issued_license`, `heartbeat`
- [ ] license issuance API: accept fingerprint + key → return ed25519-signed license JSON
- [ ] license revocation API
- [ ] heartbeat API (auth via JWT)
- [ ] minimal admin web (list accounts, branches, licenses)

### 0.9 Activation flow (E2E)
- [ ] Edge: hardware fingerprint module (CPU, MAC, board serial, TPM EK, OS install ID; N-of-M match)
- [ ] Edge: license file storage + signature verify on every start
- [ ] Edge: first-launch UX prompts for key → calls Control Plane → stores signed license
- [ ] Edge: 24 h heartbeat task; refresh short-lived JWT
- [ ] Edge: grace-period state machine (default 30 d) → degraded mode after expiry
- [ ] integration test: activate → revoke → grace expiry → degraded mode

### 0.10 Quality gates
- [ ] `cargo fmt --check` clean
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `cargo test --workspace` green
- [ ] `cargo audit` clean
- [ ] `cargo deny check` clean

---

## Backlog (Phase 1+)

- Webhook receiver w/ HMAC-SHA256 + replay window
- ONVIF pull-point subscriber behind vendor-quirk trait
- Rule engine: visual builder spec + Rhai sandbox
- Action layer: HTTP / SMTP / FTP / Nx Witness
- Bookmarks + evidence capture
- POS adapters: OPOS, JSON-HTTP, journal tail
- Exception templates (8 listed in spec §4.4)
- Case-management workflow + signed evidence export
- Multi-branch sync (CRDT vs event-sourced — see PLAN §F.2)
- Fleet dashboard + update channel
- Mobile companion app
- ML add-on (`ort`)
- Plugin SDK (WASM preferred)
- Compliance packs (PCI-DSS, GDPR, PDPA, food, pharma)

---

## Spike Tickets (open decisions — PLAN §F)

- [ ] SPIKE-01 Frontend: Leptos vs Dioxus vs React (visual rule builder prototype)
- [ ] SPIKE-02 Sync: Automerge vs event-sourced log
- [ ] SPIKE-03 Scripting: Rhai vs Lua
- [ ] SPIKE-04 Video pipeline: GStreamer vs FFmpeg (Apple licensing)
- [ ] SPIKE-05 POS adapter shortlist (sales pipeline data)
- [ ] SPIKE-06 Control Plane hosting model (SaaS vs SaaS + dedicated)
- [ ] SPIKE-07 ML add-on for v1 — go/no-go
- [ ] SPIKE-08 i18n scope at v1

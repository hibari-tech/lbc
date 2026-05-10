# PLAN

LBC — Logic Bridge Controller. Branch-resilient CCTV intelligence + soft-PLC + LP platform. Single Rust binary per branch + cloud Control Plane.

Source of truth: `lbcspec.md` (draft v0.1). This file tracks scope, phases, and decisions.

---

## A. Architecture (one-screen)

- **Edge Node** (per branch): ingest → event bus → rule engine → actions → storage → sync. Local REST + WS API. Tauri UI. Offline-tolerant within license grace.
- **Control Plane** (cloud, required): license root, fleet inventory, aggregated exceptions, update channel, SSO.
- **Comms**: TLS + mTLS. Signed append-only delta log Edge ↔ Control Plane.

Crates (workspace):

| Crate | Role |
|---|---|
| `shared` | canonical types: event, license, sync entry, RBAC enums |
| `edge` | Edge Node binary (`lbc-edge`) |
| `control-plane` | Control Plane binary (`lbc-control-plane`) |
| `ui` | desktop + LAN UI shell |
| `cli` | operator CLI (`lbc`) |

---

## B. Phases

### Phase 0 — Foundations (8–10 wk) [IN PROGRESS]
Repo, CI, cross-platform build, Tauri shell, axum skeleton, SQLite schema, auth, RBAC, Local API v0. Control Plane skeleton: account, branch reg, license issuance + verification, signed-license activation. Gating, not optional.

### Phase 1 — Edge MVP (10–12 wk)
Webhook + ONVIF ingest. Rule engine: visual builder + Rhai. Actions: HTTP/SMTP/FTP/Nx. Bookmarks. UI for events/rules/devices. Single-branch vs Control Plane. License heartbeat + grace enforcement.

### Phase 2 — Loss Prevention (10–12 wk)
POS adapters (OPOS, JSON-HTTP, journal tail). Exception templates. Evidence capture + case management. Scheduled rules. Reporting basics. Signed evidence export.

### Phase 3 — Fleet (10–14 wk)
Multi-branch sync. Fleet dashboard. Aggregated exceptions. License mgmt UI. Update channel. Branch grouping + bulk push.

### Phase 4 — Differentiators (rolling)
Mobile app, ML add-on (`ort`), plugin SDK, compliance packs, anomaly baselining, white-label.

GA target: ~10–13 mo, 4–6 senior engs.

---

## C. Stack (locked unless noted)

- Async: `tokio`. HTTP: `axum` + `tower`. Client: `reqwest`. WS: `tokio-tungstenite` via axum.
- DB: `sqlx` + SQLite (WAL). Migrations: `sqlx::migrate!`.
- Object store: filesystem, content-addressed via `blake3`.
- Templating: `minijinja`. Scripting: `rhai` (pending §F.3).
- ONVIF: `onvif` crate behind internal trait. Modbus: `tokio-modbus`. MQTT: `rumqttc`.
- Video: `gstreamer-rs` (pending §F.4).
- Crypto: `ring` / RustCrypto. Sigs: `ed25519-dalek`.
- Logging: `tracing` + JSON. Metrics: `metrics` + Prometheus.
- Errors: `thiserror` (libs), `anyhow` (bins).
- Frontend: pending §F.1. Tauri v2 shell. Tailwind.
- Build: `cargo workspaces`. CI: GH Actions matrix `{win, linux, mac} × {x86_64, aarch64}`. `cross` for Linux.
- Distro: `cargo-dist` + Tauri bundler. Code-signed per OS.

---

## D. Non-Functional Targets

- 200 ev/s + 200 rules @ commodity N100 / 8 GB, < 5% idle CPU baseline.
- Median rule latency < 100 ms. Cold start < 5 s. UI first paint < 1 s.
- Crash-only. WAL + explicit fsync on event/exception writes.
- TLS by default. HMAC-SHA256 webhooks w/ replay window. Secrets via OS keychain.
- `cargo-audit` + `cargo-deny` enforced in CI.

---

## E. Privacy Guardrails (hard requirements)

- No restroom-area video ingest. Door/badge/anon counters only. UI prevents misassignment.
- Configurable employee-monitoring policy notice w/ regional templates (GDPR, US, PDPA).
- Per-employee data export + deletion (subject access).

---

## F. Open Decisions (lock before Phase 1)

1. **Frontend**: Leptos vs Dioxus vs React-fallback. 2-wk spike on visual rule builder.
2. **Sync model**: Automerge CRDT vs event-sourced log + explicit conflict UX.
3. **Scripting**: Rhai vs Lua (`mlua`).
4. **Video pipeline**: GStreamer vs FFmpeg (Apple licensing).
5. **POS v1 coverage**: which 2–3 native adapters first (sales-driven).
6. **Control Plane hosting**: SaaS-only vs SaaS + dedicated single-tenant for enterprise.
7. **ML add-on for v1**: ship without (recommended) vs first model (POS sweethearting).
8. **i18n at v1**: English-only vs +Thai +1.

---

## G. Risks (top)

- Control Plane availability = customer-facing SLA. Mitigation: grace period, multi-region, license issuance isolated from dashboards.
- Rust frontend maturity (visual rule builder). Mitigation: React fallback ready.
- Cross-platform packaging surprises. Mitigation: CI from week 1.
- Customer expectation of "AI catches thieves." Mitigation: lead with correlation; ML add-on with scoped claims.
- Regulatory exposure (employee monitoring, biometrics). See §E.
- Nx Witness lock-in. Mitigation: VMS abstraction layer day 1.

---

## H. Working Agreement

- Tracking docs: `PLAN.md`, `TASKS.md`, `TOFIX.md`, `REFLECT.md`. Each ≤ 200 lines.
- Source files > 320 lines → ask before splitting.
- Per task: branch → edit → diag → test → lint → update docs → ask commit → push → PR.
- Tests in `tests/`, not co-located. One suite per behaviour.
- Conventional Commits; one commit per task.

See `RULES.md` for full workflow.

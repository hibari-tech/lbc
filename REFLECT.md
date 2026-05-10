# REFLECT

Append-only. After each fix or incident: what broke, why, what to do differently.

Format:
```
## YYYY-MM-DD — <short title>
**Broke:** <what>
**Why:** <root cause>
**Differently:** <guard, test, process change>
```

---

## 2026-05-10 — cargo-audit false-positives on disabled sqlx backends
**Broke:** PR #5 CI red on `cargo-audit` (RUSTSEC-2023-0071, `rsa` via `sqlx-mysql`). Merged anyway, leaving `main` red on every subsequent PR.
**Why:** `cargo-audit` walks `Cargo.lock` as a flat list; it has no feature awareness. `sqlx 0.8` lists `sqlx-mysql/postgres/sqlite/macros` unconditionally in its lockfile entry, so they appear in the lock even when only `sqlite` is enabled. Disabling our `macros` feature didn't help — same lockfile shape. `cargo-deny`, by contrast, builds the dep graph from `cargo metadata` and correctly reports `advisories ok` on the same tree.
**Differently:** Removed the dedicated `cargo-audit` job from `ci.yml`; `cargo-deny check` now owns the advisory gate alongside licenses/bans/sources. Single source of truth, no false positives. If we ever need a second opinion, run `cargo audit --deny warnings` locally — don't re-add it to CI without an `ignore` list grounded in feature analysis.

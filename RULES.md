# Development Rules

Language- and framework-agnostic workflow. Apply where the stack supports it.

## Workflow

1. Read `PLAN.md` and `TASKS.md` first.
2. After every edit: run diagnostics (LSP, type-checker, compiler). Fix all issues.
3. Before commit: run tests + linter. Zero errors, zero warnings.
4. On task done: update `PLAN.md` and `TASKS.md`.

## Tracking Files

- `TOFIX.md` — add new issues, remove resolved ones.
- `REFLECT.md` — append after each fix: what broke, why, what to do differently.
- All `.md` files ≤ **200 lines**. Short words. Dense info. No filler.

## File Size

- Source file > **320 lines** → stop and ask user before refactoring into smaller modules.

## Code Style

- Prefer pattern matching (`match`, `switch`, `case`) over `if`/`else if` chains.
- Use early returns / guard clauses, not nested `else`.

```
// prefer
if (!ok) return err;
doWork();

// avoid
if (ok) { doWork(); } else { return err; }
```

## Tests

- Put tests in `tests/` (or the framework's standard dir).
- Don't co-locate with source.
- One suite per behaviour, not per source file.

## Commits

- Ask before committing. Wait for confirmation.
- One commit per task.
- Conventional Commits: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`, `perf:`, `style:`, `ci:`.
- Subject: imperative, lowercase, ≤ 72 chars.

## Branches

- Name: `type/short-kebab-description` (e.g. `feat/user-auth`).
- Include task ID if available: `fix/123-login-crash`.
- ≤ 50 chars. No personal names, no dates.
- One branch per task. Branch from latest `main`.

## Pull Requests

Template:

```
## What
<one line>

## Why
<one line / link to task>

## How
<key changes>

## Test
<how to verify>

## Notes
<breaking changes, migrations, follow-ups>
```

- Title = commit subject.
- Link task: `Closes #123` or `Refs PLAN.md §X`.
- Diff > ~400 lines or > ~10 files → ask before opening.
- Self-review before requesting review.
- Tests + lint green in CI before un-drafting.

## Merge Conflicts

- Never auto-resolve silently. Show each conflict + proposed resolution. Wait for confirmation if intent unclear.
- After resolution: diag, tests, lint.
- Prefer **rebase** for feature branches; **merge** for shared/pushed-for-review.
- Repeated rebase conflicts → ask whether to abort and merge.
- Never force-push to shared branches. Use `--force-with-lease` on your own.

## CI/CD Failures

- Red CI = blocker. Don't push more on top.
- Reproduce locally first. CI-only failure → suspect env, OS, timezone, locale, perms, cache, parallel order.
- Read the **full** log. Real cause often earlier than the last error.
- Triage:
  - **Real** → fix.
  - **Flaky** → log in `TOFIX.md`, don't delete. Never re-run hoping it passes.
  - **Infra** → retry once, then escalate.
- Never skip/disable a test to go green without confirmation + `TOFIX.md` entry.
- Never weaken an assertion to pass. Fix the code or the test's intent — ask which.
- CI config changes commit as `ci:`.

## Dependencies

- Use the lockfile. Always commit it. Never hand-edit — regenerate via the package manager.
- One logical update per commit/PR. Group only when tightly coupled.
- Before update: read changelog for breaking changes. Note them in PR.
- After update: full tests + lint + smoke check.
- Pin: apps = exact; libs = ecosystem range convention.
- Security updates: same-day. Use `fix(deps):` if it closes a CVE.
- Bot PRs (Dependabot/Renovate): no auto-merge. Same gates as any change.
- Removing a dep is a dep change. Confirm no imports remain.

## Rollback & Hotfix

**Choose first:**

- **Revert** when: bug in production, high severity, root cause unclear, or fix is slow.
- **Fix-forward** when: small, known cause, trivial fix, or revert would break more (migrations, contracts).
- Unsure → ask. Default to revert under pressure.

**Revert**

1. Find offending commit(s) — `git log`, `git bisect`.
2. `git revert <sha>`. Never `reset` or force-push shared branches.
3. PR title: `revert: <original subject>`. Link original + incident.
4. Diag, tests, lint.
5. `TOFIX.md` entry to re-attempt later.

**Hotfix**

1. Branch from **production** ref, not `main` (unless same).
2. Name: `hotfix/<short>` or `hotfix/<version>-<short>`.
3. Minimal diff. No opportunistic refactors.
4. All gates apply. Skipping needs confirmation + `TOFIX.md`.
5. Commit `fix:` or `fix!:` for breaking.
6. Merge to production ref **and** back-merge into `main`.
7. Tag if project uses tags.

**After any incident**

- `REFLECT.md` entry: what shipped broken, how caught, why missed, what guards recurrence.
- If a missing test would have caught it, add the test as a follow-up — not bundled with hotfix.

## Order of Operations

**Per task:** branch → edit → diag → fix diag → test → lint → update `PLAN.md`/`TASKS.md`/`TOFIX.md`/`REFLECT.md` → ask commit → commit on confirm → push → CI green → open PR → resolve conflicts on confirm → merge on confirm.

**Per incident:** assess → revert or hotfix → same gates → `REFLECT.md`.

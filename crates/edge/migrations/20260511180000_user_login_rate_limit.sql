-- Failed-login counter + timed lockout to throttle brute-force / password
-- spraying. argon2 verify is already expensive (~100 ms / attempt / core)
-- but the API is otherwise unguarded; a single locked-out window per
-- account closes the obvious hole.
--
-- `failed_login_count`     — consecutive failures since the last success.
-- `last_failed_login_ms`   — unix ms of the most recent failure (audit).
-- `locked_until_ms`        — unix ms; non-null means the account is
--                            currently locked and login must reject even
--                            valid credentials. Null = no lock.
--
-- A success resets `failed_login_count` to 0 and clears `locked_until_ms`.
-- The feature is gated by `auth.max_failed_login_attempts`; setting it to
-- 0 disables the gate entirely (existing behaviour).

ALTER TABLE user ADD COLUMN failed_login_count   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE user ADD COLUMN last_failed_login_ms INTEGER;
ALTER TABLE user ADD COLUMN locked_until_ms      INTEGER;

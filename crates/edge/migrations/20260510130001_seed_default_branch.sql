-- Seed the default branch so device/event/rule/exception FKs resolve before
-- the license activation flow lands in §0.9. The id is deliberately fixed at
-- 1 and referenced by `http::DEFAULT_BRANCH_ID`. Idempotent via INSERT OR IGNORE
-- and the surrounding _migrations tracking, so reopen is safe.

INSERT OR IGNORE INTO branch (id, name, timezone, status, created_at)
VALUES (1, 'default', 'UTC', 'active', strftime('%s', 'now') * 1000);

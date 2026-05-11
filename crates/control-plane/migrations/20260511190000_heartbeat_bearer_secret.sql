-- Heartbeat bearer-secret hash. Each issued license now carries a
-- 32-byte BLAKE3 hash of a server-minted heartbeat secret; the
-- cleartext secret is returned exactly once in the activation
-- response. The edge persists it in `<license>.state.json` and
-- presents `Authorization: Bearer <hex(secret)>` on every
-- `POST /api/v1/licenses/{id}/heartbeat`. The CP recomputes the
-- BLAKE3 hash and constant-time-compares against this column.
--
-- Existing rows (pre-migration) lose the ability to heartbeat: we
-- seed them with random bytes that nobody has the preimage for, so
-- every heartbeat against a legacy license id will 401 until the
-- branch re-activates. This is intentional — we'd rather force a
-- re-issue than silently leave the bearer gate open on old rows.

ALTER TABLE issued_license
    ADD COLUMN heartbeat_secret_hash BLOB NOT NULL DEFAULT (x'00');

-- Replace the placeholder default on existing rows with 32 random
-- bytes so they can't be matched by any possible token.
UPDATE issued_license SET heartbeat_secret_hash = randomblob(32);

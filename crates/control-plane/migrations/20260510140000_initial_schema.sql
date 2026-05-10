-- Phase 0 Control Plane schema v1.
--
-- SQLite-backed for the Phase-0 skeleton. Per `lbcspec.md` §6.1 and
-- `TASKS.md` §0.8, production targets Postgres; the data model is
-- portable so the swap is a deploy-time concern (TOFIX entry).

CREATE TABLE account (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    email      TEXT NOT NULL,
    tier       TEXT NOT NULL DEFAULT 'starter',
    created_at INTEGER NOT NULL
) STRICT;

-- Pre-purchase keys customers redeem to activate edge nodes. We store the
-- blake3 hash of the key, not the key itself; the cleartext value is shown
-- only once at creation. `allowed_branch_count` caps how many distinct
-- branches may activate against this key.
CREATE TABLE license_key (
    id                   INTEGER PRIMARY KEY,
    account_id           INTEGER NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    key_hash             BLOB NOT NULL UNIQUE,
    tier                 TEXT NOT NULL,
    allowed_branch_count INTEGER NOT NULL,
    expires_at           INTEGER NOT NULL DEFAULT 0,
    revoked_at           INTEGER,
    created_at           INTEGER NOT NULL
) STRICT;

CREATE INDEX idx_license_key_account ON license_key(account_id);

CREATE TABLE branch (
    id                   INTEGER PRIMARY KEY,
    account_id           INTEGER NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    name                 TEXT NOT NULL,
    hardware_fingerprint TEXT NOT NULL,
    created_at           INTEGER NOT NULL,
    UNIQUE(account_id, name)
) STRICT;

CREATE INDEX idx_branch_account ON branch(account_id);

-- One row per signed license issued. `signature` is the raw 64-byte
-- ed25519 signature over the canonical JSON of the embedded payload.
CREATE TABLE issued_license (
    id              INTEGER PRIMARY KEY,
    license_key_id  INTEGER NOT NULL REFERENCES license_key(id) ON DELETE CASCADE,
    branch_id       INTEGER NOT NULL REFERENCES branch(id) ON DELETE CASCADE,
    payload         TEXT NOT NULL,
    signature       BLOB NOT NULL,
    issued_at       INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL DEFAULT 0,
    revoked_at      INTEGER
) STRICT;

CREATE INDEX idx_issued_license_branch ON issued_license(branch_id);

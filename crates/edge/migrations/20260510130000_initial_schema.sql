-- Phase 0 schema v1.
--
-- Conventions:
--   * INTEGER PRIMARY KEY = sqlite rowid alias (auto-increments).
--   * `ts` columns are unix epoch milliseconds (INTEGER).
--   * JSON-bearing columns stored as TEXT; sqlite JSON1 functions apply.
--   * BLOB hashes are 32-byte blake3 digests.
--   * STRICT tables enforce column types (sqlite >= 3.37).

CREATE TABLE branch (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    timezone    TEXT NOT NULL DEFAULT 'UTC',
    address     TEXT,
    status      TEXT NOT NULL DEFAULT 'active',
    license_id  INTEGER,
    created_at  INTEGER NOT NULL
) STRICT;

CREATE TABLE user (
    id            INTEGER PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    branch_scope  TEXT,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
) STRICT;

CREATE TABLE device (
    id              INTEGER PRIMARY KEY,
    branch_id       INTEGER NOT NULL REFERENCES branch(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,
    vendor          TEXT,
    model           TEXT,
    address         TEXT,
    credentials_ref TEXT,
    status          TEXT NOT NULL DEFAULT 'unknown',
    last_seen       INTEGER,
    created_at      INTEGER NOT NULL
) STRICT;

CREATE INDEX idx_device_branch ON device(branch_id);

CREATE TABLE event (
    id          INTEGER PRIMARY KEY,
    branch_id   INTEGER NOT NULL REFERENCES branch(id) ON DELETE CASCADE,
    device_id   INTEGER REFERENCES device(id) ON DELETE SET NULL,
    kind        TEXT NOT NULL,
    ts          INTEGER NOT NULL,
    payload     TEXT NOT NULL,
    ingest_ts   INTEGER NOT NULL
) STRICT;

CREATE INDEX idx_event_branch_ts ON event(branch_id, ts);
CREATE INDEX idx_event_device     ON event(device_id);

CREATE TABLE rule (
    id          INTEGER PRIMARY KEY,
    branch_id   INTEGER NOT NULL REFERENCES branch(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    version     INTEGER NOT NULL DEFAULT 1,
    definition  TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    schedule    TEXT,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    UNIQUE(branch_id, name)
) STRICT;

CREATE TABLE rule_run (
    id              INTEGER PRIMARY KEY,
    rule_id         INTEGER NOT NULL REFERENCES rule(id) ON DELETE CASCADE,
    fired_at        INTEGER NOT NULL,
    input_event_ids TEXT NOT NULL,
    outcomes        TEXT NOT NULL
) STRICT;

CREATE INDEX idx_rule_run_rule_fired ON rule_run(rule_id, fired_at);

CREATE TABLE action_log (
    id          INTEGER PRIMARY KEY,
    rule_run_id INTEGER NOT NULL REFERENCES rule_run(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    target      TEXT,
    request     TEXT,
    response    TEXT,
    status      TEXT NOT NULL,
    latency_ms  INTEGER,
    ts          INTEGER NOT NULL
) STRICT;

CREATE TABLE evidence (
    id            INTEGER PRIMARY KEY,
    kind          TEXT NOT NULL,
    content_hash  BLOB NOT NULL,
    size          INTEGER NOT NULL,
    mime          TEXT NOT NULL,
    source_device INTEGER REFERENCES device(id) ON DELETE SET NULL,
    ts_start      INTEGER NOT NULL,
    ts_end        INTEGER NOT NULL,
    signature     BLOB,
    created_at    INTEGER NOT NULL
) STRICT;

CREATE INDEX idx_evidence_hash ON evidence(content_hash);

CREATE TABLE exception (
    id           INTEGER PRIMARY KEY,
    branch_id    INTEGER NOT NULL REFERENCES branch(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,
    severity     TEXT NOT NULL DEFAULT 'medium',
    ts           INTEGER NOT NULL,
    evidence_ref INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    status       TEXT NOT NULL DEFAULT 'open',
    assignee     INTEGER REFERENCES user(id) ON DELETE SET NULL,
    resolution   TEXT,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
) STRICT;

CREATE INDEX idx_exception_branch_ts ON exception(branch_id, ts);
CREATE INDEX idx_exception_status    ON exception(status);

CREATE TABLE "case" (
    id                  INTEGER PRIMARY KEY,
    opened_by           INTEGER NOT NULL REFERENCES user(id),
    status              TEXT NOT NULL DEFAULT 'open',
    notes               TEXT,
    evidence_bundle_ref TEXT,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
) STRICT;

CREATE TABLE case_exception (
    case_id      INTEGER NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
    exception_id INTEGER NOT NULL REFERENCES exception(id) ON DELETE CASCADE,
    PRIMARY KEY (case_id, exception_id)
) STRICT;

CREATE TABLE audit_log (
    id        INTEGER PRIMARY KEY,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    entity    TEXT NOT NULL,
    before    TEXT,
    after     TEXT,
    ts        INTEGER NOT NULL,
    prev_hash BLOB,
    hash      BLOB NOT NULL
) STRICT;

CREATE TABLE license (
    id             INTEGER PRIMARY KEY,
    payload        TEXT NOT NULL,
    signature      BLOB NOT NULL,
    last_heartbeat INTEGER,
    activated_at   INTEGER NOT NULL
) STRICT;

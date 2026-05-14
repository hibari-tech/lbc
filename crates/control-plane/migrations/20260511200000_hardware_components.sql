-- Stores the canonical-JSON map of the edge's multi-component
-- fingerprint at activation time. The CP heartbeat handler does
-- N-of-M tolerant comparison (see
-- `shared::fingerprint::compare_tolerant`) — a NIC swap or
-- motherboard battery reset can flip a single component without
-- forcing re-activation.
--
-- Nullable: rows from before this migration (or from legacy edges
-- that didn't send a `hardware_components` field at activation)
-- keep `NULL` here, and the heartbeat handler falls back to the
-- digest byte-compare it used in Phase 0. A re-activation populates
-- the column.

ALTER TABLE issued_license ADD COLUMN hardware_components TEXT;

-- Track when each issued license last checked in.
-- The edge heartbeats here every `heartbeat_interval_secs` (default 24h);
-- the cap on staleness vs grace_period_days drives the degraded-mode
-- decision on the edge side.

ALTER TABLE issued_license ADD COLUMN last_seen INTEGER;

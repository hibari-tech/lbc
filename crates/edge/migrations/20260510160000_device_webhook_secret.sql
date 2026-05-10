-- Per-device webhook shared secret for HMAC-SHA256 verification on
-- inbound POSTs to `/api/v1/ingest/webhooks/{device_id}`.
--
-- Stored in cleartext (HMAC needs the raw key for verification). The
-- column is nullable; devices without a secret cannot receive webhooks
-- and any POST returns 401.

ALTER TABLE device ADD COLUMN webhook_secret TEXT;

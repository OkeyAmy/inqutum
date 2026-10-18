-- Durable idempotency ledger for outbound notifications and webhooks.
-- Safe to re-run. Keep destination values out of the ledger; only their hash is stored.
CREATE TABLE IF NOT EXISTS delivery_deduplication (
  delivery_key CHAR(64) PRIMARY KEY,
  scope TEXT NOT NULL,
  channel TEXT NOT NULL CHECK (channel IN ('notification', 'webhook')),
  event_id TEXT NOT NULL,
  destination_hash CHAR(64) NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('in_progress', 'delivered', 'failed')),
  claim_token UUID NOT NULL,
  lease_until TIMESTAMPTZ,
  attempts INTEGER NOT NULL DEFAULT 1 CHECK (attempts > 0),
  last_error TEXT,
  delivered_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK ((status = 'delivered' AND delivered_at IS NOT NULL) OR status <> 'delivered')
);

CREATE INDEX IF NOT EXISTS delivery_deduplication_updated_at_idx
  ON delivery_deduplication (updated_at);
CREATE INDEX IF NOT EXISTS delivery_deduplication_expired_lease_idx
  ON delivery_deduplication (lease_until)
  WHERE status = 'in_progress';

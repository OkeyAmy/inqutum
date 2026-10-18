ALTER TABLE email_deliveries ADD COLUMN IF NOT EXISTS dedupe_key VARCHAR(320);
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_deliveries_dedupe_key ON email_deliveries(dedupe_key) WHERE dedupe_key IS NOT NULL;

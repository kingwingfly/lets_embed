ALTER TABLE images ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;

-- rows already stranded in `processing` become reclaimable one TTL after this migration
UPDATE images SET claimed_at = NOW() WHERE status = 'processing'::process_status AND claimed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_images_claimed_at ON images (claimed_at) WHERE status = 'processing'::process_status;

DROP INDEX IF EXISTS idx_images_claimed_at;
ALTER TABLE images DROP COLUMN IF EXISTS claimed_at;

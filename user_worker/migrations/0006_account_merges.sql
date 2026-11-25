-- user_worker D1 migration 0006: Account Fusion / Merge audit ledger and tombstone column.
-- Apply with: wrangler d1 execute lets-embed --remote --file user_worker/migrations/0006_account_merges.sql
--
-- Keeps abandoned `users_v2` rows tombstoned (`merged_into = preserved_user_id`) so
-- legacy `users` rows can never be re-adopted after their wallets are moved/unlinked,
-- and records an idempotent audit trail of every account merge.

ALTER TABLE users_v2
    ADD COLUMN merged_into TEXT;

CREATE TABLE IF NOT EXISTS account_merges (
    merge_id               TEXT PRIMARY KEY,
    preserved_user_id      TEXT NOT NULL,
    abandoned_user_id      TEXT NOT NULL,
    preserved_do_key       TEXT NOT NULL,
    abandoned_do_key       TEXT NOT NULL,
    favorites_mode         TEXT NOT NULL CHECK (favorites_mode IN ('both', 'keep_preserved', 'keep_abandoned')),
    paid_credits_moved     INTEGER NOT NULL DEFAULT 0,
    plan_refund_moved      INTEGER NOT NULL DEFAULT 0,
    free_credits_forfeited INTEGER NOT NULL DEFAULT 0,
    identities_moved       INTEGER NOT NULL DEFAULT 0,
    status                 TEXT NOT NULL CHECK (status IN ('started', 'completed')),
    created_at             INTEGER NOT NULL,
    completed_at           INTEGER
);

CREATE INDEX IF NOT EXISTS idx_account_merges_preserved
    ON account_merges(preserved_user_id, created_at DESC);

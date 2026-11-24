-- Versioned encrypted provider secrets keyed by `(policy_rev, provider_id, field_name)`.
-- Allows admin_dashboard_worker to stage provider secret updates at `new_rev` BEFORE
-- Phase-2 SitePolicyDO activation while live user_worker requests continue reading
-- the secret version matching `active_policy_rev` (prevents sending a newly staged
-- API key to the previous endpoint during activation or after a failed activation).

CREATE TABLE IF NOT EXISTS provider_secret_versions (
  policy_rev  INTEGER NOT NULL,
  provider_id TEXT    NOT NULL,
  field_name  TEXT    NOT NULL,
  kid         TEXT    NOT NULL DEFAULT '',
  nonce       BLOB    NOT NULL DEFAULT X'',
  ciphertext  BLOB    NOT NULL DEFAULT X'',
  deleted     INTEGER NOT NULL DEFAULT 0,
  updated_at  INTEGER NOT NULL,
  updated_by  TEXT,
  PRIMARY KEY (policy_rev, provider_id, field_name)
);

CREATE INDEX IF NOT EXISTS idx_provider_secret_versions_lookup
  ON provider_secret_versions (provider_id, field_name, policy_rev DESC);

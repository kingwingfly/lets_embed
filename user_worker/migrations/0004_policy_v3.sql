-- user_worker D1 migration 0004: Policy v3 Safe Mode removal migration,
-- optimistic-concurrency `pref_version`, AdminAssertion v2 single-use nonce
-- replay guard, and two-phase `site_settings` activation status tracking.
--
-- Applies on top of:
-- - `0002_site_settings.sql` (`site_settings` policy revision history table)
-- - `0003_identities_safety.sql` (`users_v2.content_prefs_json` user safety preferences)

-- 1. Add monotonic optimistic-concurrency `pref_version` to `users_v2`.
ALTER TABLE users_v2
    ADD COLUMN pref_version INTEGER NOT NULL DEFAULT 1;

-- 2. Safe Mode removal migration (Codex MEDIUM #6):
--    Clear `enabled_switchers` to `[]` and strip `safe_mode` for any account
--    where `safe_mode` was active (`true` / `1`), so removing Safe Mode NEVER
--    silently restores previously suppressed opt-ins.
UPDATE users_v2
   SET content_prefs_json = json_object('enabled_switchers', json('[]')),
       pref_version = pref_version + 1
 WHERE json_extract(content_prefs_json, '$.safe_mode') IN (1, 'true', 'TRUE');

--    Strip the obsolete `safe_mode` key from remaining rows where it was false.
UPDATE users_v2
   SET content_prefs_json = json_remove(content_prefs_json, '$.safe_mode')
 WHERE json_type(content_prefs_json, '$.safe_mode') IS NOT NULL
   AND json_extract(content_prefs_json, '$.safe_mode') NOT IN (1, 'true', 'TRUE');

-- 3. Single-use replay protection for AdminAssertion v2 (`jti` nonces).
CREATE TABLE IF NOT EXISTS admin_assertion_nonces (
    jti        TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_admin_assertion_nonces_exp
    ON admin_assertion_nonces(expires_at);

-- 4. Two-phase Policy v3 publication status on `site_settings` (`pending_do_ack` -> `active`).
ALTER TABLE site_settings
    ADD COLUMN activation_status TEXT NOT NULL DEFAULT 'active'
    CHECK (activation_status IN ('pending_do_ack', 'active', 'failed'));
CREATE INDEX IF NOT EXISTS idx_site_settings_activation_status
    ON site_settings(activation_status, revision DESC);

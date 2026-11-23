-- user_worker D1 migration 0003: Multi-provider identities, revocable accounts,
-- encrypted provider secrets, and content moderation reports.
--
-- Idempotent and backwards-compatible with 0001_users.sql + 0002_site_settings.sql:
-- - Migrated legacy wallet users keep `id = address` AND `account_do_key = address`
--   so 100% of existing `likes`, `payments`, and `UserAccount` DO balances, quotas,
--   bans, and signup-grant guards continue working seamlessly.
-- - Brand-new multi-auth accounts use `account_do_key = 'usr:' || uuid`, completely
--   disjoint from legacy wallet addresses.

CREATE TABLE IF NOT EXISTS users_v2 (
    id                     TEXT PRIMARY KEY,
    account_do_key         TEXT NOT NULL UNIQUE,
    display_name           TEXT,
    email                  TEXT,
    created_at             INTEGER NOT NULL,
    last_login             INTEGER NOT NULL,
    terms_version_accepted INTEGER,
    terms_digest_accepted  TEXT,
    terms_accepted_at      INTEGER,
    content_prefs_json     TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(content_prefs_json)),
    plan                   TEXT,
    banned                 INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_users_v2_last_login ON users_v2(last_login DESC);

CREATE TABLE IF NOT EXISTS user_identities (
    provider_id           TEXT NOT NULL,
    issuer                TEXT NOT NULL,
    subject               TEXT NOT NULL,
    user_id               TEXT NOT NULL REFERENCES users_v2(id) ON DELETE CASCADE,
    purpose               TEXT NOT NULL DEFAULT 'login' CHECK (purpose IN ('login', 'payment')),
    label                 TEXT,
    verified_email        TEXT,
    assurance_level       TEXT NOT NULL DEFAULT 'none',
    assurance_method      TEXT,
    assurance_verified_at INTEGER,
    assurance_expires_at  INTEGER,
    created_at            INTEGER NOT NULL,
    PRIMARY KEY (provider_id, issuer, subject)
);
CREATE INDEX IF NOT EXISTS idx_user_identities_user_id ON user_identities(user_id);
CREATE INDEX IF NOT EXISTS idx_user_identities_user_purpose ON user_identities(user_id, purpose);

CREATE TABLE IF NOT EXISTS provider_secrets (
    provider_id TEXT NOT NULL,
    field_name  TEXT NOT NULL,
    kid         TEXT NOT NULL,
    nonce       BLOB NOT NULL,
    ciphertext  BLOB NOT NULL,
    updated_at  INTEGER NOT NULL,
    updated_by  TEXT,
    PRIMARY KEY (provider_id, field_name)
);

CREATE TABLE IF NOT EXISTS content_reports (
    id               TEXT PRIMARY KEY,
    reporter_key     TEXT NOT NULL,
    reporter_user_id TEXT,
    target_kind      TEXT NOT NULL CHECK (target_kind IN ('post', 'image', 'video')),
    target_id        INTEGER NOT NULL,
    reason           TEXT NOT NULL,
    note             TEXT,
    status           TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'reviewing', 'resolved', 'dismissed')),
    created_at       INTEGER NOT NULL,
    resolved_at      INTEGER,
    resolved_by      TEXT
);
CREATE INDEX IF NOT EXISTS idx_content_reports_status_created
    ON content_reports(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_content_reports_target
    ON content_reports(target_kind, target_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_content_reports_open_dedup
    ON content_reports(reporter_key, target_kind, target_id)
    WHERE status = 'open';

-- ---------------------------------------------------------------------------
-- Idempotent backfill from legacy `users` table
-- ---------------------------------------------------------------------------

-- 1. Migrate existing wallet accounts preserving `id = address` and `account_do_key = address`.
INSERT OR IGNORE INTO users_v2 (
    id,
    account_do_key,
    display_name,
    email,
    created_at,
    last_login,
    terms_version_accepted,
    terms_digest_accepted,
    terms_accepted_at,
    content_prefs_json,
    plan,
    banned
)
SELECT
    u.address,
    u.address,
    NULL,
    NULL,
    u.created_at,
    u.last_login,
    NULL,
    NULL,
    NULL,
    '{}',
    u.plan,
    u.banned
FROM users u;

-- 2. Backfill primary Ethereum (SIWE) and Solana (SIWS) login identities.
--    Ethereum addresses are lowercase 0x-prefixed hex; base58 Solana pubkeys never contain '0'.
INSERT OR IGNORE INTO user_identities (
    provider_id,
    issuer,
    subject,
    user_id,
    purpose,
    label,
    verified_email,
    assurance_level,
    assurance_method,
    assurance_verified_at,
    assurance_expires_at,
    created_at
)
SELECT
    CASE WHEN u.address LIKE '0x%' THEN 'siwe' ELSE 'siws' END,
    CASE WHEN u.address LIKE '0x%' THEN 'eip155:1' ELSE 'solana:mainnet' END,
    u.address,
    u.address,
    'login',
    CASE WHEN u.address LIKE '0x%' THEN 'Ethereum wallet' ELSE 'Solana wallet' END,
    NULL,
    'none',
    NULL,
    NULL,
    NULL,
    u.created_at
FROM users u;

-- 3. Backfill linked Solana top-up wallets (`solana_address`) as `purpose = 'payment'`
--    when present and distinct from the primary account address.
INSERT OR IGNORE INTO user_identities (
    provider_id,
    issuer,
    subject,
    user_id,
    purpose,
    label,
    verified_email,
    assurance_level,
    assurance_method,
    assurance_verified_at,
    assurance_expires_at,
    created_at
)
SELECT
    'siws',
    'solana:mainnet',
    u.solana_address,
    u.address,
    'payment',
    'Linked Solana wallet',
    NULL,
    'none',
    NULL,
    NULL,
    NULL,
    u.created_at
FROM users u
WHERE u.solana_address IS NOT NULL
  AND trim(u.solana_address) != ''
  AND u.solana_address != u.address;

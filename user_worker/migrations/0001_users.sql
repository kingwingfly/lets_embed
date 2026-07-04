-- user_worker D1 schema (database: lets-embed, binding: DB)
-- Apply with: wrangler d1 execute lets-embed --remote --file migrations/0001_users.sql
--
-- Note: balance / subscription quota / view-dedupe live ONLY in the UserAccount
-- Durable Object (single source of truth). `users.plan` and `users.banned` are
-- display mirrors for the admin list; enforcement is DO-side.

CREATE TABLE IF NOT EXISTS users (
    address    TEXT PRIMARY KEY,               -- lowercase 0x-prefixed eth address
    created_at INTEGER NOT NULL,
    last_login INTEGER NOT NULL,
    plan       TEXT,                           -- display mirror; DO is authority
    banned     INTEGER NOT NULL DEFAULT 0      -- display mirror; DO is authority
);

CREATE TABLE IF NOT EXISTS payments (
    tx_hash    TEXT PRIMARY KEY,               -- lowercase 0x + 64 hex; global replay guard
    address    TEXT NOT NULL,
    amount_wei TEXT NOT NULL DEFAULT '0',      -- decimal string (wei exceeds SQLite int precision safety)
    token      TEXT NOT NULL DEFAULT 'ETH',
    points     INTEGER NOT NULL DEFAULT 0,
    status     TEXT NOT NULL DEFAULT 'pending', -- pending | credited | rejected
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_payments_address ON payments(address, created_at DESC);

CREATE TABLE IF NOT EXISTS likes (
    address    TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('post', 'image', 'video')),
    target_id  INTEGER NOT NULL,               -- i64 id from the Postgres search DB
    created_at INTEGER NOT NULL,
    PRIMARY KEY (address, kind, target_id)
);
CREATE INDEX IF NOT EXISTS idx_likes_address_created ON likes(address, created_at DESC);

-- Cutover (manual, after both workers are deployed and verified):
-- DROP TABLE IF EXISTS applications;

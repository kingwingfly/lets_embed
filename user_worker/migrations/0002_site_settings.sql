-- Keep published revisions so a delayed deposit can use the terms at its block time.
CREATE TABLE IF NOT EXISTS site_settings (
    revision INTEGER PRIMARY KEY,
    document TEXT NOT NULL CHECK (json_valid(document)),
    updated_at INTEGER NOT NULL,
    updated_by TEXT
);
INSERT OR IGNORE INTO site_settings (revision, document, updated_at) VALUES (0, '{}', 0);

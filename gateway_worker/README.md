# Usage

- Prepare bindings in `wrangler.toml`.
- Prepare d1:
```sql
CREATE TABLE IF NOT EXISTS applications (
    id            TEXT PRIMARY KEY,
    reason        TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending', /* pending / approved / denied */
    duration_secs INTEGER,
    created_at    INTEGER NOT NULL,
    approved_by   TEXT,
    approved_at   INTEGER
);
```

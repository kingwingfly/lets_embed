# Let's Embed E2E & Local Dev Harness

Self-contained end-to-end verification harness covering standalone mode, the 3-Worker Cloudflare stack (`gateway_worker` + `user_worker` + `admin_dashboard_worker`), Policy v3 enforcement, Geo/WAF rules, and headless Chromium UI tests.

## Prerequisites

1. **PostgreSQL** running with migrations applied (`sqlx migrate run`) and `DATABASE_URL` set (or in `.env`).
2. **Built web & worker artifacts**:
   ```bash
   cargo leptos build
   (cd gateway_worker && worker-build --release)
   (cd user_worker && ./build-web.sh && worker-build --release)
   (cd admin_dashboard_worker && ./build-web.sh && worker-build --release)
   ```
3. **Chromium binary**: auto-discovered from `CHROME_BIN`, Playwright cache (`~/.cache/ms-playwright`), or system `chromium` / `google-chrome`.

## Commands

| Command | Description |
| :--- | :--- |
| `npm run test:e2e` | **Full isolated E2E run**: allocates 3 ephemeral ports, spawns standalone origin + fresh Miniflare 3-worker stack + managed origin, runs headless Chromium suite (`tests/e2e/suite.mjs`), saves screenshots to `target/e2e-screenshots/`, and tears everything down cleanly. |
| `npm run test:e2e:attach` | Runs `tests/e2e/suite.mjs` directly against already-running dev servers (`E2E_ORIGIN=http://127.0.0.1:8787`, `E2E_STANDALONE=http://127.0.0.1:3000`). |
| `npm run dev:workers` | Starts only the local 3-Worker Miniflare edge (`http://127.0.0.1:8787`) pointing at `WEB_MANAGED_ORIGIN` (default `http://127.0.0.1:3001`). |
| `npm run test:worker-policy` | Runs the Worker-level Policy v3 / security / geo HTTP 451 Miniflare integration tests (`gateway_worker/tests/site-policy.cjs`). |

## Environment Overrides

- `CHROME_BIN` — explicit path to Chromium / Chrome binary
- `MEDIA_ROOT` — local media root (default `/tmp/lets_embed_dev_media`)
- `E2E_SCREENSHOTS_DIR` — output folder for E2E screenshots (default `target/e2e-screenshots`)
- `E2E_VERBOSE=1` — stream live logs from standalone, managed, and worker processes
- `SITE_SECRET` — override the local dev master secret (default deterministic local dev secret)

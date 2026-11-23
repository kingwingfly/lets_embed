# Gallery gateway (`lets-embed-gateway-worker`)

The edge gateway enforces authoritative geo-blocking, Cloudflare Access admin routing, revocable `v2` sessions, capability-based media authorization, locked server-side blurred previews, and search/view metering in front of `lets-embed-web`, `lets-embed-user-worker`, `lets-embed-admin-dashboard-worker`, and private media origins.

## Enforcement Pipeline

1. **Canonical path check**: Rejects traversal-bearing or non-canonical request paths (`400 Bad Request`).
2. **`/admin` & `/admin/*` (geo-exempt)**: Verified via Cloudflare Access (`CF_ACCESS_AUD` + identity email) and forwarded to `ADMIN_DASHBOARD_WORKER` (`props = { gallery_admin = true }`) with `X-Gallery-Admin-Email` and `Cache-Control: private, no-store`. `GET /admin/browse` issues the 15-minute `__Host-ue_admin_view` browsing pass and redirects to `/`.
3. **Authoritative policy & geo-block (`SitePolicyDO`)**: Loads `{ policy, digest }` from singleton `SITE_POLICY` DO (`"global"`, `GET /policy`), verifies SHA-256 digest (failing closed with `503` if unreachable or invalid), and evaluates `policy.geo.is_blocked(request.cf().country())` (never trusting incoming `CF-IPCountry`). Blocked visitors receive `451 Unavailable For Legal Reasons`.
4. **`/user/admin*` retired (`404`) & `/user/*` routing**: `/user/admin` and `/user/admin/*` unconditionally return `404 Not Found`. All other `/user/*` routes forward to `USER_WORKER` with all privileged headers stripped.
5. **Raw `/images/*` and `/videos/*` blocked (`404`)**: Media bytes are only served via signed capability URLs at `/media/{image,video,preview}/{id}?cap=...`.
   - Verifies HMAC-SHA256 `cap` (`MEDIA_CAP_SECRET`), `(kind, id)`, expiry, and `cap.rev >= policy.min_enforce_rev` (`403` on failure).
   - Authorizes caller live against `USER_ACCOUNT` DO (`POST /session-context`), `safe_mode`, Terms acceptance, age policy (`SelfAttestation` / `StrictProviderVerified18`), and eligible active switchers **before** any billing or budget check (denied requests incur zero charge).
   - `Preview` checks `POST /preview-budget` (`preview:{id}`) and never deducts clear-view balance; requires `policy.cloudflare_images_blur = true` (fails closed `403` when disabled) and attaches hardcoded Worker `cf.image` parameters (`blur: 80, width: 360, quality: 30, format: "webp"`).
   - `Image`/`Video` settle against canonical `MediaBillingKey` (`media:image:{id}` / `media:video:{id}`, `HEAD` -> `can-charge`, `GET` -> `charge`).
   - Upstream media fetches use `redirect: "manual"` (rejecting any `3xx` with `502`), `cf.cacheTtl = 0`, and `Cache-Control: private, no-store`.
6. **Gallery / web forwarding (`API_UPSTREAM`)**:
   - Strips all `site_access::is_privileged_request_header` headers and `STRIPPED_ORIGIN_COOKIES`, and attaches a freshly signed short-lived `X-Gateway-Assertion` (`GATEWAY_ASSERTION_SECRET`, 30s TTL, audience `"lets-embed-web"`).
   - `__Host-ue_admin_view` only waives the login wall and metering; it still runs Step 0 geo checks, signs `X-Gateway-Assertion` (`is_admin_view: true`), enforces `/media/*` capabilities, and enforces same-origin CSRF on all `POST` requests to `API_UPSTREAM`.
   - Keeps `/robots.txt`, `/terms`, `/privacy`, `/dmca`, `/content-policy`, `/pkg/*`, and `/favicon.ico` publicly accessible (after geo check); preserves public caching only on `/pkg/*`, `/robots.txt`, and anonymous `/sitemap.xml` / `/sitemap/*`.

## Bindings & Secrets (`wrangler.toml`)

- **Service bindings**:
  - `USER_WORKER` -> `lets-embed-user-worker` (no `gallery_admin` prop)
  - `ADMIN_DASHBOARD_WORKER` -> `lets-embed-admin-dashboard-worker` (`props = { gallery_admin = true }`)
- **Durable Objects**:
  - `USER_ACCOUNT` -> `UserAccount` on `lets-embed-user-worker`
  - `SITE_POLICY` -> `SitePolicyDO` on `lets-embed-user-worker`
- **Required secrets**:
  - `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET`
  - `JWT_SECRET`
  - `GATEWAY_ASSERTION_SECRET`
  - `MEDIA_CAP_SECRET`
- **Optional cutover secret**:
  - `SESSION_V2_SECRET` — dedicated secret for revocable `v2.` session cookies. When unset or empty during cutover, `gateway_worker` verifies `v2.` tokens using `JWT_SECRET` with `site_access`'s built-in `"session/v2\0"` HMAC domain separation.
- **Never bound**: `SETTINGS_ENCRYPTION_KEY` must never be bound to `gateway_worker`.

## Verification

```bash
cargo test -p gateway_worker
cargo clippy -p gateway_worker --target wasm32-unknown-unknown --all-targets -- -D warnings
worker-build --profile wasm-release
node --test gateway_worker/tests/site-policy.cjs
```

# Gallery gateway (`lets-embed-gateway-worker`)

The edge gateway enforces Policy v3 content safety, authoritative geo-blocking, Cloudflare Access staff routing with request-bound `AdminAssertion` v2, HKDF `SITE_SECRET` key derivation, revocable `v2` sessions, capability-based media redemption with authoritative `facts_rev` verification, locked server-side blurred previews, guest click-to-reveal cookies (`le_guest_sid`), and search/view metering in front of `lets-embed-web`, `lets-embed-user-worker`, `lets-embed-admin-dashboard-worker`, and private media origins.

## Enforcement Pipeline

1. **Canonical path check**: Rejects traversal-bearing or non-canonical request paths (`400 Bad Request`).
2. **`/admin` & `/admin/*` (geo-exempt, `SITE_POLICY`-outage-exempt)**:
   - Verified via live Cloudflare Access (`CF_ACCESS_AUD` + identity email, checked against optional `ADMIN_ALLOWED_EMAILS`).
   - Lazily resolves `KeyDomain::AdminAssertion` (`ADMIN_ASSERTION_SECRET` override or `SITE_SECRET` HKDF) ONLY on the `/admin*` branch so rolling out an override key never breaks gallery traffic.
   - Signs request-bound `AdminAssertionClaims` v2 (`aa2.`, binding `m`, `p`, `bh = sha256_hex(body)`, random 128-bit `jti`, `email`, `aud`, `exp`) in `X-Gallery-Admin-Assertion` and forwards to `ADMIN_DASHBOARD_WORKER` (`props = { gallery_admin = true }`) with `Cache-Control: private, no-store`.
   - `GET /admin/browse` issues the 15-minute `__Host-ue_admin_view` browsing pass (strictly limited to billing & guest-wall waiver — NEVER grants `LiveAdmin` bypass or Switcher unlocks) and redirects to `/`.
3. **Authoritative Policy v3 & geo-block (`SitePolicyDO`)**:
   - Loads `{ policy, digest }` from singleton `SITE_POLICY` DO (`"global"`, `GET /policy`) and strictly decodes with `site_access::decode_active_policy_v3` + digest verification (failing closed with `503` on unsupported schema, legacy `"rules"`, malformed policy, or digest mismatch).
   - Evaluates `policy.geo.is_blocked(request.cf().country())` (never trusting incoming `CF-IPCountry`). Blocked visitors receive `451 Unavailable For Legal Reasons`.
4. **`/user/admin*` retired (`404`) & `/user/*` routing**:
   - `/user/admin` and `/user/admin/*` unconditionally return `404 Not Found`. All other `/user/*` routes forward to `USER_WORKER` with all privileged headers and untrusted client `cf-ipcountry` stripped, injecting trusted `cf-ipcountry` from Cloudflare runtime `request.cf().country()` when present.
5. **Raw `/images/*`, `/videos/*`, and `/internal/*` blocked (`404`)**:
   - Media bytes are only served via signed Policy v3 capability URLs at `/media/{image,video,preview}/{id}?cap=...`.
   - Strictly verifies `MediaCapability` v3 (`mc3.`, rejecting all v1/v2 tokens!), `(kind, asset_id)`, expiry, and `min_enforce_rev <= cap.policy_rev <= active_rev` BEFORE billing, cache delivery, or upstream fetch on `GET`, `HEAD`, and `Range` requests.
   - Resolves live `ActorBinding` (`User` > live staff `LiveAdmin` > signed `le_guest_sid` `GuestSession` > `Anon`) and evaluates `site_access::compute_policy_access` using live `SessionContext`, live verified staff email (NEVER browse cookie), and runtime `cf.country`.
   - When `policy.safety_enabled == true`, queries `{API_UPSTREAM}/internal/facts-rev/{image|video}/{id}` (authenticated with `X-Gateway-Assertion` v3 + optional `CF-Access-Client-*` service token headers) to enforce `cap.facts_rev == current_facts_rev` (failing closed `503` on origin error, `403` on 404/mismatch — including for previously public `Anon` caps!).
   - Authorizes via `site_access::authorize_media_capability_v3` (`granted = live_direct_grants ∪ (cap.revealed_refs ∩ live_click_eligible)`) BEFORE any billing or preview-budget check (denied requests incur zero charge).
   - `Preview` checks `POST /preview-budget` (`preview:{id}`), requires `policy.fixed_blur_enabled == true` (fails closed `403` when disabled), strips `Range`/`If-Range`, attaches hardcoded Worker `cf.image` parameters (`blur: 80, width: 360, quality: 30, format: "webp"`), and fails closed with `502` if Cloudflare Images transform confirmation (`cf-resized: internal=ok...`) is missing or failed — NEVER serving clear original bytes.
   - `Image`/`Video` settle against canonical `MediaBillingKey` (`media:image:{id}` / `media:video:{id}`, `HEAD` -> `can-charge`, `GET` -> `charge`).
   - Upstream media fetches use `redirect: "manual"` (rejecting any `3xx` with `502`), `cf.cacheTtl = 0`, and `Cache-Control: private, no-store`.
6. **Gallery / web forwarding (`API_UPSTREAM`) & `POST /api/safety/reveal`**:
   - Strips all `site_access::is_privileged_request_header` headers and `STRIPPED_ORIGIN_COOKIES`, and attaches a freshly signed short-lived `X-Gateway-Assertion` v3 (`ga3.`, 30s TTL, audience `"lets-embed-web"`) carrying `{ actor, rev, min_enforce_rev, digest, direct_grants, click_eligible, is_billing_waived, caller_age_verified, caller_terms_accepted }`.
   - `__Host-ue_admin_view` waives ONLY the login wall and quota/payment metering (`is_billing_waived: true`); it NEVER grants `LiveAdmin` bypass or Switcher unlocks and still enforces geo, CSRF, and media capability verification.
   - `POST /api/safety/reveal` enforces same-origin + `X-Requested-With: fetch`; if caller has no `User`/`LiveAdmin` actor and no valid `le_guest_sid` cookie, mints a fresh signed `GuestSessionToken` (`le_guest_sid`, `HttpOnly; SameSite=Lax; Path=/; Secure` on https), passes `ActorBinding::GuestSession` in `X-Gateway-Assertion`, forwards to `API_UPSTREAM`, and attaches `Set-Cookie` + `Cache-Control: private, no-store`.

## Bindings & Secrets (`wrangler.toml`)

- **Service bindings**:
  - `USER_WORKER` -> `lets-embed-user-worker` (no `gallery_admin` prop)
  - `ADMIN_DASHBOARD_WORKER` -> `lets-embed-admin-dashboard-worker` (`props = { gallery_admin = true }`)
- **Durable Objects**:
  - `USER_ACCOUNT` -> `UserAccount` on `lets-embed-user-worker`
  - `SITE_POLICY` -> `SitePolicyDO` on `lets-embed-user-worker`
- **Recommended master secret**:
  - `SITE_SECRET` — single >= 32-byte secret deriving isolated HKDF-SHA256 subkeys for `Session`, `MediaCap`, `GatewayAssertion`, `InternalApi`, `GuestSession`, and (lazily on `/admin*`) `AdminAssertion`.
- **Optional overrides & allowlist**:
  - `JWT_SECRET`, `SESSION_V2_SECRET` (or `SESSION_SECRET`), `MEDIA_CAP_SECRET`, `GATEWAY_ASSERTION_SECRET`, `INTERNAL_API_SECRET`, `GUEST_SESSION_SECRET`, `ADMIN_ASSERTION_SECRET`
  - `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET`
  - `ADMIN_ALLOWED_EMAILS` (comma-separated, case-insensitive)
- **Never bound**: `PROVIDER_SECRETS_KEY` must never be bound to `gateway_worker`.

## Verification

```bash
CARGO_TARGET_DIR=/run/media/louis/Work/rust/lets_embed/target cargo test --offline -p gateway_worker
CARGO_TARGET_DIR=/run/media/louis/Work/rust/lets_embed/target cargo clippy --offline -p gateway_worker --target wasm32-unknown-unknown -- -D warnings
(cd gateway_worker && CARGO_TARGET_DIR=/run/media/louis/Work/rust/lets_embed/target worker-build --release)
node --test gateway_worker/tests/site-policy.cjs
```

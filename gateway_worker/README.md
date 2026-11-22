# Gallery gateway (`lets-embed-gateway-worker`)

The gateway applies the visitor policy published at `/user/admin`. New installations require a wallet. In public mode guests can browse the gallery and use the configured free allowances. Personal accounts, payments and favorites still require a wallet session.

The gateway meters image views, video views, by-ID similarity searches (`/api/search_similar`, `/api/search_advanced_embed`), uploaded-image searches (`/api/search_by_image`, `/api/search_advanced_image`) and description/CLIP searches (`/api/search_by_desc`, `/api/search_advanced_clip`) through the account Durable Object. Metadata-only advanced search (`/api/search_advanced`) and other read-only metadata requests do not spend points. Guests receive one allowance per client IP and item type each UTC day. The gateway derives the guest key from Cloudflare's client IP and the shared secret. Clients without an IP share a fallback allowance. Signed-in accounts use their wallet's allowance, then their subscription quota and points balance.

When an allowance or balance runs out, browser navigation goes to `/user/upgrade`. Embedded gallery media and search requests receive HTTP 402. The gallery reads the response’s Server Timing marker and opens the same page. Guests can sign in there, and wallets with a session go directly to the account top-up form.

## Cloudflare Access and deployment

1. Restrict `/user/admin` and its descendants on the public gallery hostname to your administrator group in Cloudflare Access. Set the application's audience in this Worker's `CF_ACCESS_AUD`. Leave the gallery paths public at the Access layer if the dashboard should control guest access. A matching administrator identity must have an email. [Cloudflare Worker identity and path protection](https://developers.cloudflare.com/workers/configuration/cloudflare-access/)
2. Configure the upstream origin variables in `gateway_worker/wrangler.toml` under `[vars]`: `API_UPSTREAM`, `IMAGE_UPSTREAM` and `VIDEO_UPSTREAM` (trailing slashes are trimmed at runtime).
3. Keep the two service bindings in `wrangler.toml` targeting `lets-embed-user-worker`. Only `ADMIN_WORKER` carries the `gallery_admin` property. The gateway checks the runtime Access audience and identity before using it. `lets-embed-user-worker` checks the binding on every admin operation. Browser-submitted settings and account changes also require the gallery's own origin, configured in `SIWE_DOMAIN`. [Service binding properties](https://developers.cloudflare.com/workers/runtime-apis/context/)
4. Set `JWT_SECRET` to the same secret as `lets-embed-user-worker`. Set `CF_ACCESS_CLIENT_ID` and `CF_ACCESS_CLIENT_SECRET` to the service token authorized for the API and media origins.
5. Apply the D1 migration and deploy `lets-embed-user-worker` first, then deploy `lets-embed-gateway-worker`. [User Worker deployment](../user_worker/README.md#setup--deployment)
6. Because `workers_dev = false` and `preview_urls = false` disable the default `*.workers.dev` and preview hostnames, bind your public gallery hostname to `lets-embed-gateway-worker` using a Custom Domain or Zone Route in the Cloudflare Dashboard (or configure `routes = [...]` in `gateway_worker/wrangler.toml`).

Administrators can open **View gallery** from the dashboard or **Browse as administrator** on the login page without connecting a wallet. Opening the dashboard grants a 15-minute, host-only browsing cookie for gallery pages, searches and media. Reopen the dashboard to refresh it. Admin actions always require Cloudflare Access. Personal wallet actions require a wallet session.

For tunnel-only origins, `cloudflared` can validate the application token with **Protect with Access**. Keep origin validation for Cloud Run or any origin also reachable outside that tunnel. [Cloudflare origin validation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/)

## Local development

Use a local-only gateway Wrangler configuration with a matching `[access.dev]` audience and `[access.dev.identity]` email to exercise admin access. Remove the local Access simulation to test a guest. The integration test builds on the same runtime identities, service bindings, SQLite Durable Objects and D1 migrations used by the deployed Workers. From the repository root, after `npm ci` and building both Workers, run `node --test gateway_worker/tests/site-policy.cjs`.

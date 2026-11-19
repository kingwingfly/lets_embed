# Gallery gateway

The gateway applies the visitor policy published at `/user/admin`. New installations require a wallet. In public mode guests can browse the gallery and use the configured free allowances. Personal accounts, payments and favorites still require a wallet session.

The gateway meters image views, video views, by-ID similarity searches, uploaded-image searches and description searches through the account Durable Object. Guests receive one allowance per client IP and item type each UTC day. The gateway derives the guest key from Cloudflare's client IP and the shared secret. Clients without an IP share a fallback allowance. Signed-in accounts use their wallet's allowance, then their subscription quota and points balance. Read-only metadata requests do not spend points.

## Cloudflare Access and deployment

1. Restrict `/user/admin` and its descendants on the public gallery hostname to your administrator group in Cloudflare Access. Set the application's audience in this Worker's `CF_ACCESS_AUD`. Leave the gallery paths public at the Access layer if the dashboard should control guest access. A matching administrator identity must have an email. [Cloudflare Worker identity and path protection](https://developers.cloudflare.com/workers/configuration/cloudflare-access/)
2. Keep the two service bindings in `wrangler.toml`. Only `ADMIN_WORKER` carries the `gallery_admin` property. The gateway checks the runtime Access audience and identity before using it. The user Worker checks the binding on every admin operation. Browser-submitted settings and account changes also require the gallery's own origin, configured in `SIWE_DOMAIN`. [Service binding properties](https://developers.cloudflare.com/workers/runtime-apis/context/)
3. Set `JWT_SECRET` to the same secret as the user Worker. Set `CF_ACCESS_CLIENT_ID` and `CF_ACCESS_CLIENT_SECRET` to the service token authorized for the API and media origins.
4. Apply the D1 migration and deploy the user Worker first, then deploy this gateway. [User Worker deployment](../user_worker/README.md#setup--deployment)

Administrators can open **View gallery** from the dashboard or **Browse as administrator** on the login page without connecting a wallet. Opening the dashboard grants a 15-minute, host-only browsing cookie for gallery pages, searches and media. Reopen the dashboard to refresh it. Admin actions always require Cloudflare Access. Personal wallet actions require a wallet session.

For tunnel-only origins, `cloudflared` can validate the application token with **Protect with Access**. Keep origin validation for Cloud Run or any origin also reachable outside that tunnel. [Cloudflare origin validation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/)

## Local development

Use a local-only gateway Wrangler configuration with a matching `[access.dev]` audience and `[access.dev.identity]` email to exercise admin access. Remove the local Access simulation to test a guest. The integration test builds on the same runtime identities, service bindings, SQLite Durable Objects and D1 migrations used by the deployed Workers. From the repository root, after `npm ci` and building both Workers, run `node --test gateway_worker/tests/site-policy.cjs`.

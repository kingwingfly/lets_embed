# user_worker

SIWE (Sign-In with Ethereum) user system for lets_embed, running as a Cloudflare
Worker. Replaces the old apply/approve flow in `gateway_worker`.

- **Auth**: SIWE (EIP-4361) only; EOA wallets via `personal_sign` (EIP-1271
  contract wallets are not supported).
- **Metering**: every image/video view costs points, deduped per user per file
  per 24h. Enforced by `gateway_worker` calling the per-user `UserAccount`
  Durable Object (bound cross-script).
- **Billing**: pay-as-you-go points balance + optional subscription plans
  (periodic quota, renewed from the balance; overage falls back to PAYG).
  New users get a free grant.
- **Top-up**: crypto only — send ETH to the deposit address, submit the tx
  hash, the worker verifies it via JSON-RPC and credits points.
- **Likes**: post/image/video favorites stored in D1.
- **Storage**: balance/quota/dedupe live only in the Durable Object; D1 holds
  `users`, `payments`, `likes` (see `migrations/0001_users.sql`).

## Routes

Pages: `/user/login`, `/user/account`, `/user/favorites`
API: `/user/api/{nonce,verify,logout,me,topup,payments,subscribe,unsubscribe,like,likes}`
Admin (Cloudflare Access): `/user/admin`, `/user/admin/{credit,ban}`

## Setup & deployment

TODO(unit 10): full runbook — KV namespace creation (NONCES), Access app for
`/user/admin*`, D1 migration, deploy order (user-worker **before**
gateway-worker), cutover steps (drop `applications`), limitations.

```sh
wrangler kv namespace create NONCES          # fill id into wrangler.toml
wrangler d1 execute lets-embed --remote --file migrations/0001_users.sql
npx wrangler deploy
```

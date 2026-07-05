# user_worker

SIWE (Sign-In with Ethereum) user system for lets_embed, running as a Cloudflare
Worker. Replaces the old apply/approve flow in `gateway_worker`.

- **Auth**: SIWE (EIP-4361) only; EOA wallets via `personal_sign` (EIP-1271
  contract wallets are not supported). A successful verify sets an HS256 session
  cookie `ue_session` (signed with the same `lets-embed-jwt-secret` as the
  gateway; `sub` = lowercase address). Nonces are single-use, stored in the
  `NONCES` KV namespace with a 300s TTL.
- **Metering**: every image/video view costs points, deduped per user per file
  per 24h. Enforced by `gateway_worker` calling the per-user `UserAccount`
  Durable Object (bound cross-script).
- **Billing**: pay-as-you-go points balance + optional subscription plans
  (periodic quota, renewed from the balance; overage falls back to PAYG).
  New users get a free grant.
- **Top-up**: crypto only — send ETH to the deposit address, submit the tx
  hash, the worker verifies it via JSON-RPC and credits points.
- **Likes**: post/image/video favorites stored in D1, surfaced as like buttons
  on the Leptos details page and a `/user/favorites` page.
- **Storage**: balance/quota/dedupe live only in the Durable Object; D1 holds
  `users`, `payments`, `likes` (see `migrations/0001_users.sql`).

## Routes

| Route | Method | What |
| --- | --- | --- |
| `/user/login` | GET | wallet login page (`?next=` redirect target) |
| `/user/account` | GET | balance, plan, top-up (submit tx hash), payment history |
| `/user/favorites` | GET | liked posts/images/videos |
| `/user/api/nonce` | GET | issue a SIWE nonce (KV, 300s, single-use) |
| `/user/api/verify` | POST | verify SIWE message + signature, set `ue_session` |
| `/user/api/logout` | POST | clear the session cookie |
| `/user/api/me` | GET | current address + balance/plan/quota status |
| `/user/api/topup` | POST | submit an ETH tx hash for verification + credit |
| `/user/api/payments` | GET | payment history |
| `/user/api/subscribe` | POST | buy/renew a plan from the balance |
| `/user/api/unsubscribe` | POST | stop auto-renewal |
| `/user/api/like` | GET/POST/DELETE | check / add / remove a like |
| `/user/api/likes` | GET | list likes (keyset paginated) |
| `/user/admin` | GET | admin page (Cloudflare Access protected) |
| `/user/admin/credit` | POST | admin credit/deduct points |
| `/user/admin/ban` | POST | admin ban/unban |

## Points & billing model

All numbers are placeholders in `src/config.rs` — tune before launch.

- Image view: **1 pt**; video view: **5 pts** (`COST_IMAGE_VIEW`,
  `COST_VIDEO_VIEW`). Repeat views of the same path within 24h
  (`DEDUPE_WINDOW_SECS`) are free — dedupe happens inside the DO.
- New accounts get **200 pts** free on first touch (`FREE_GRANT_POINTS`).
- Plans (`PLANS`), purchased and auto-renewed **from the PAYG balance**:
  `basic` = 1,000 pts → 5,000 quota / 30d; `pro` = 3,000 pts → 20,000 quota /
  30d. Views draw quota first, then the balance. If renewal can't be paid
  (DO alarm), the account lapses back to PAYG.
- Top-up: send ETH to `DEPOSIT_ADDRESS`, submit the tx hash on
  `/user/account`. The worker checks via `RPC_URL`: correct to-address,
  value ≥ 0.001 ETH (`MIN_TOPUP_WEI`), receipt status success, ≥ 6
  confirmations (`MIN_CONFIRMATIONS`). Points = wei × `POINTS_PER_ETH` / 1e18
  (100,000 pts/ETH). `payments.tx_hash` is a primary key — each tx credits
  exactly once.

## Setup & deployment

1. Create the nonce KV namespace and put its id into `wrangler.toml`:

   ```sh
   wrangler kv namespace create NONCES     # fill id into [[kv_namespaces]] binding = "NONCES"
   ```

2. Fill in `[vars]` in `wrangler.toml`:
   - `DEPOSIT_ADDRESS` — the ETH address that receives top-ups (**lowercase**).
   - `SIWE_DOMAIN` — the public hostname users sign in on (the
     gateway-worker's domain).
   - `RPC_URL` / `CHAIN_ID` — JSON-RPC endpoint and chain
     (defaults: `https://cloudflare-eth.com`, mainnet `1`).

3. Create a **new** Cloudflare Access application covering
   `/user/admin*` on the public hostname, and put its AUD into
   `CF_ACCESS_AUD` (`CF_ACCESS_TEAM_DOMAIN` is your team domain).

4. Apply the D1 migration (shared `lets-embed` database):

   ```sh
   wrangler d1 execute lets-embed --remote --file migrations/0001_users.sql
   ```

5. Deploy **user-worker first**:

   ```sh
   npx wrangler deploy
   ```

   The gateway's `USER_WORKER` service binding and cross-script
   `USER_ACCOUNT` DO binding reference this worker — deploying the gateway
   first fails.

6. Deploy `gateway_worker` (see its README).

7. Cutover: verify a wallet login works and a media view is charged
   (check `/user/api/me` before/after), then drop the retired table and
   delete the old `/admin` Access application:

   ```sql
   DROP TABLE IF EXISTS applications;
   ```

## Limitations

- **EOA only.** Signatures are verified by ecrecover; EIP-1271 contract
  wallets (Safe, etc.) cannot sign in.
- **Native ETH only.** ERC-20 (e.g. USDC) top-ups are phase-2, not
  implemented.
- **First submitter owns the tx.** A top-up is credited to whoever submits
  the hash first (guarded by the `payments.tx_hash` PK); the sender address
  of the tx is not required to match the logged-in wallet.
- **KV nonces are eventually consistent.** A nonce issued at one edge
  location may briefly be invisible (or appear unconsumed) at another;
  worst case a login retry, not a security hole — verification still
  requires a valid signature over a fresh nonce.

# user_worker (`lets-embed-user-worker`)

Identity, session, billing, and safety-preference Cloudflare Worker for lets_embed
(`lets-embed-user-worker`, called via service binding by `lets-embed-gateway-worker`).

- **Auth & Sessions**: supports Ethereum (SIWE), Solana (SIWS), Google, GitHub, X, Discord, Email OTP, Telegram, and OIDC Age Assurance. Issues revocable `v2` sessions (`__Host-ue_session`, tracked in `UserAccount` DO SQLite) and hosts the `AuthChallengeDO` (single-use nonces, OAuth/OIDC/Telegram transactions, Email OTP) and `SitePolicyDO` (authoritative Policy v3 singleton).
- **Admin Dashboard**: lives in the separate `lets-embed-admin-dashboard-worker` mounted at `/admin` behind Cloudflare Access (`/user/admin*` is retired and returns `404`).
- **Metering & Billing (v2)**: pay-as-you-go points balance + optional subscription plans
  (per-window view/search allowances, bought/renewed **from** the balance, **no
  auto-renew** — they lapse to PAYG at period end). Overage falls back to PAYG.
  New users get a free grant.
- **Top-ups**: support ETH, SOL, USDT and USDC. The account page opens the transfer in the customer's wallet and automatically checks the receipt for points.
- **Likes**: post/image/video favorites stored in D1, surfaced as like buttons
  on the Leptos details page and a `/user/favorites` page.
- **Storage**: balance/plan/window/dedupe/sessions/prefs live in Durable Object SQLite; D1
  holds `users_v2`, `user_identities`, `payments`, `likes`, `site_settings`, and
  revision-scoped `provider_secret_versions` (AES-256-GCM encrypted).

## Routes

| Route | Method | What |
| --- | --- | --- |
| `/user/login` | GET | sign-in SPA (`?next=` redirect target) |
| `/user/upgrade` | GET | sign in after reaching a free limit, then open the account top-up form. Signed-in visitors go directly to top-up. |
| `/user/account` | GET | balance, plan, linked sign-in methods, safety preferences, wallet payments, transfer recovery and payment history |
| `/user/favorites` | GET | liked posts/images/videos |
| `/user/api/nonce` | GET | issue a purpose-scoped SIWE / SIWS / link nonce (`AuthChallengeDO`, 300s, single-use) |
| `/user/api/verify` | POST | verify SIWE message + signature, set `__Host-ue_session` |
| `/user/api/verify_solana` | POST | verify SIWS message + ed25519 signature, set `__Host-ue_session` |
| `/user/api/logout` | POST | revoke session in DO and clear `__Host-ue_session` |
| `/user/api/me` | GET | current identity + balance / plan / window status |
| `/user/api/topup/prepare` | POST | prepare an unsigned mainnet wallet transfer and point estimate for `{account, chain, token, amount}`. Supply the amount as a decimal string in asset units. |
| `/user/api/topup` | POST | submit a `{chain, token, tx_hash, account?}` top-up for verification + credit |
| `/user/api/payments` | GET | payment history |
| `/user/api/subscribe` | POST | buy/renew a plan from the balance (no auto-renew) |
| `/user/api/unsubscribe` | POST | cancel the active plan and refund prorated unused paid time |
| `/user/api/rates` | GET | spot USD prices for ETH/SOL (Chainlink feeds) |
| `/user/api/link_solana` | GET/POST/DELETE | read, link (by signing a challenge), or unlink a Solana payment wallet |
| `/user/api/like` | GET/POST/DELETE | check / add / remove a like |
| `/user/api/likes` | GET | list likes (keyset paginated) |
| `/user/api/likes/status` | GET | batch check liked status for comma-separated `kind:target_id` pairs |
| `/admin/*` | — | Served by `lets-embed-admin-dashboard-worker` behind Cloudflare Access (`/user/admin*` returns `404`) |

## Points & billing model (v2)

Open the Admin Dashboard at `/admin` on the gateway hostname (protected by Cloudflare Access). Saving checks the revision shown in the form. Reload and reapply edits if another administrator has already published a change.

- **Browsing access** switches between wallet-required and public browsing. To show a public image gallery, select **Public browsing** and set **Image views → Free per day** to a positive number or `-1`.
- **Free media folders** optionally limits daily free media to selected albums or files. Use decoded gallery paths, one per line, such as `/images/Sample album`. An empty list includes all folders. These rules govern access to media bytes. Search results can still list the full catalog.
- **Prices & free access** sets a point price and a daily free allowance for each of the five metered actions. Guests share an allowance per client IP. Wallet holders get their own allowance. A daily allowance of `0` closes that action to guests, and `-1` grants unlimited access. A zero point price makes the action free for signed-in customers. The gallery listing itself is free in public mode.
- **Subscriptions** sets each plan's purchase price and five-hour usage limits. Existing purchases retain their original refund basis. An administrator can grant, replace or revoke an individual plan under **Accounts**. Replacing a paid period refunds its unused portion. Complimentary days have zero refund value.
- **Payments & credits** sets the receiving addresses, points per USD, minimum top-up and welcome grant. Empty receiving addresses close new deposits on that chain. Verification uses the address, minimum and points conversion in effect at the transfer's block time, including when a customer submits the hash later. Native-token market prices still come from the existing spot feeds.
- **Accounts** also supports balance adjustments with a reason and account suspension. Wallet-specific controls apply to signed-in users. Public quotas identify guests by IP, so people sharing an IP share the quota.

The tables below show the initial billing values from `src/config.rs`. Existing deployments start with wallet-required browsing, their current prices and their configured receiving addresses.

### Initial pay-as-you-go pricing

- Image view: **1 pt**; video view: **5 pts**.
- Similarity search comes in two tiers by cost-to-serve:
  - **upload-image / text description search: 100 pts** — runs neural inference (expensive).
    For subscribers it draws from the per-window search allowance.
  - **by-id search: 10 pts** — reuses a stored embedding (a pgvector query, no
    inference — cheap), so it is a view-class charge: for subscribers it draws
    from the (abundant) view allowance, not the scarce search allowance.
- Repeat use of the same resource within 24h (`DEDUPE_WINDOW_SECS`) is free —
  dedupe happens inside the DO (per media path, per search query).
- New accounts get a **3,000 pt** free grant on first touch
  (`FREE_GRANT_POINTS`).

### Initial plans

Plans are bought/renewed **from the points balance** (there is **no
auto-renew**): at period end an account simply lapses back to PAYG, and the
user clicks Subscribe/Renew to start a new period. A plan grants per-window
allowances that refresh every rolling **5h** window; overage past the window
allowance falls back to the PAYG balance. An account can be PAYG-only,
plan-only, or plan+PAYG.

| Plan | Price | Points | Period | Per 5h window |
| --- | --- | --- | --- | --- |
| `basic` | $2 | 20,000 pts | 30d | 2,000 view-units + 10 similarity searches |
| `pro` | $5 | 50,000 pts | 30d | **unlimited** views + 50 similarity searches |

## Payment rails

On `/user/account`, choose the chain and asset, enter an amount, and select **Pay with wallet**. The Worker checks the current receiving address, network and minimum top-up. The customer approves the transfer in their Ethereum provider or Solana Wallet Standard wallet. The page submits the returned receipt to the on-chain verifier and refreshes the balance once credited.

Pending receipts are saved under the signed-in account in browser storage. Reopening the account page in that browser resumes verification. **Check again** retries a delayed receipt, and **Dismiss** clears a canceled or replaced one. **Pay manually or recover a transfer** accepts a hash or signature for a payment sent directly from the account's own wallet (as the transaction sender / fee payer) outside checkout, from another browser, or with an older wallet. Each transaction credits once through the payment ledger and the account's idempotent credit key.

- **Ethereum** — mainnet native **ETH** plus ERC-20 **USDT** / **USDC**. Token
  transfers are verified from the `Transfer` event in the receipt logs.
  Requires **≥ 6 confirmations** (`MIN_CONFIRMATIONS`) on the canonical block;
  deposits must go to the active Ethereum receiving address.
- **Solana** — mainnet native **SOL** plus SPL **USDT** / **USDC**. The wallet pays from its associated token account for SPL assets. The transfer creates the recipient's associated token account if needed and attaches a unique checkout memo. Verification requires **`finalized`** commitment and matches the fee payer/sender and active receiving address.
- **USD pricing**: stablecoins (USDT/USDC) are treated as **$1**. Volatile
  assets (ETH, SOL) are priced in USD from **Chainlink on-chain price feeds**
  (an `eth_call` to `latestRoundData` over `RPC_URL`). Credited points =
  USD value × the published points per USD.

### Solana wallet linking

A customer who signed in with Solana can pay directly from that wallet. To pay from Solana while signed in with another provider (Ethereum, Google, Email, etc.), the customer links a Solana wallet once from `/user/account`. They sign a purpose-bound challenge with the wallet (`ed25519` `signMessage`, e.g. Phantom) and POST it to `/user/api/identities/link/wallet` (or legacy `/user/api/link_solana`). The verified address is stored in D1 `user_identities` (`purpose = 'payment'`) and synced to `users.solana_address` for migrated accounts. Verification matches the sender to the linked wallet when present, or to the customer's Solana sign-in address.

## Setup & deployment (Policy v3 — 3-Worker Stack)

1. Run `npm ci` from the repository root. All single-use auth nonces, OAuth/OIDC/Telegram transactions, Email OTP challenges, and Policy v3 snapshots live in Durable Object SQLite (`UserAccount`, `AuthChallengeDO`, `SitePolicyDO`) — no KV `NONCES` namespace is required.
2. Configure `SIWE_DOMAIN`, `PUBLIC_URL`, `DEPLOYMENT_ID`, `RPC_URL`, `CHAIN_ID`, and `SOL_RPC_URL` in `user_worker/wrangler.toml`, and matching host/upstream settings in `admin_dashboard_worker/wrangler.toml` and `gateway_worker/wrangler.toml`. Fresh deployments start with deposits closed; configure receiving addresses in `/admin` → **Access & Pricing**.
3. Protect ONLY the public gateway's `/admin` and `/admin/*` paths with an administrator-only Cloudflare Access policy (do NOT attach Access to public gallery routes). Put its audience in `CF_ACCESS_AUD` and allowlisted staff emails in `ADMIN_ALLOWED_EMAILS` in `gateway_worker/wrangler.toml`. (`/user/admin` is retired and returns `404`.) See [Gateway Access setup](../gateway_worker/README.md#cloudflare-access-and-deployment).
4. Apply ALL D1 migrations in order (`0001` through `0005`). Existing pre-v3 deployments can apply any missing migrations starting from their last applied file; all migrations are idempotent where possible:

   ```sh
   npx wrangler d1 execute lets-embed --cwd user_worker --remote --file migrations/0001_users.sql
   npx wrangler d1 execute lets-embed --cwd user_worker --remote --file migrations/0002_site_settings.sql
   npx wrangler d1 execute lets-embed --cwd user_worker --remote --file migrations/0003_identities_safety.sql
   npx wrangler d1 execute lets-embed --cwd user_worker --remote --file migrations/0004_policy_v3.sql
   npx wrangler d1 execute lets-embed --cwd user_worker --remote --file migrations/0005_versioned_provider_secrets.sql
   npx wrangler d1 execute lets-embed --cwd user_worker --remote --command 'SELECT MAX(revision) AS revision FROM site_settings'
   ```

5. Configure a single high-entropy master `SITE_SECRET` (at least 32 random bytes; RFC 5869 HKDF-SHA256 automatically derives isolated domain keys for sessions, internal APIs, admin assertions, media capabilities, guest sessions, and AES-256-GCM provider secrets) identically across ALL THREE Workers AND the managed `lets-embed-web` origin:

   ```sh
   npx wrangler secret put SITE_SECRET --cwd user_worker
   npx wrangler secret put SITE_SECRET --cwd admin_dashboard_worker
   npx wrangler secret put SITE_SECRET --cwd gateway_worker
   ```

   Upgrading deployments with live legacy wallet sessions may additionally keep `JWT_SECRET` set on `user_worker` and `gateway_worker` during the cutover window. Set the gateway's upstream variables (`API_UPSTREAM`, `IMAGE_UPSTREAM`, `VIDEO_UPSTREAM`) and upstream Access service token (`CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET`) on both `gateway_worker` and `admin_dashboard_worker`.
6. Build both SPAs (`./build-web.sh` in `user_worker` and `admin_dashboard_worker`) and deploy `lets-embed-user-worker` first, then `lets-embed-admin-dashboard-worker`, then `lets-embed-gateway-worker`:

   ```sh
   (cd user_worker && ./build-web.sh)
   (cd admin_dashboard_worker && ./build-web.sh)
   npx wrangler deploy --cwd user_worker
   npx wrangler deploy --cwd admin_dashboard_worker
   npx wrangler deploy --cwd gateway_worker
   ```

   > **Upgrading from legacy `user-worker` / `gateway-worker` script names:** `user_worker/wrangler.toml` keeps `[[migrations]] tag = "v1" new_sqlite_classes = ["UserAccount"]` (and subsequent tags for `AuthChallengeDO` and `SitePolicyDO`) for fresh installs. Cloudflare scopes Durable Object namespaces to the owning Worker script name, so deploying under the new `lets-embed-user-worker` name creates a separate empty `UserAccount` namespace rather than inheriting state from an existing `user-worker` script. Existing deployments with live Durable Object balances/plans must either keep the old script name until migrating state or run a Cloudflare Durable Objects transfer migration (`transferred_classes` from `user-worker` to `lets-embed-user-worker`) before retiring `user-worker` and switching bindings.

7. Open `/admin` from the public gallery hostname (authenticated via Cloudflare Access). Verify **Content Safety**, **Auth Providers**, and **Access & Pricing**, then publish revision #1 to activate Policy v3 in `SitePolicyDO`.
8. Leave **Require sign-in** selected for the first save if you want a closed gallery, or disable it for public browsing with daily free quotas. Use **View gallery** to obtain a billing-waived browse pass (note that the browse pass never waives content safety rules), and test both a normal customer account and a signed-out private window.

## Limitations

- **EOA only.** Signatures are verified by ecrecover; EIP-1271 contract wallets (Safe, etc.) cannot sign in.
- **Durable Object single-use challenges.** Wallet nonces, OAuth/Telegram states, Email OTPs, and handoff transfers are verified atomically in `AuthChallengeDO` / `UserAccount` SQLite storage.

# user_worker

SIWE (Sign-In with Ethereum) user system for lets_embed, running as a Cloudflare
Worker. Replaces the old apply/approve flow in `gateway_worker`.

- **Auth** supports Ethereum (SIWE) and Solana wallet sign-in. The gateway validates the signed `ue_session` cookie. The dashboard uses a dedicated Cloudflare Access application.
- **Metering** uses the pricing and free allowances published at `/user/admin`. The gateway asks the account Durable Object to enforce each metered request.
- **Billing (v2)**: pay-as-you-go points balance + optional subscription plans
  (per-window view/search allowances, bought/renewed **from** the balance, **no
  auto-renew** — they lapse to PAYG at period end). Overage falls back to PAYG.
  New users get a free grant.
- **Top-up**: crypto only, **multi-chain**. Ethereum (native ETH + ERC-20
  USDT/USDC) and Solana (native SOL + SPL USDT/USDC). Submit the tx
  hash/signature; the worker verifies it on-chain and credits points.
- **Likes**: post/image/video favorites stored in D1, surfaced as like buttons
  on the Leptos details page and a `/user/favorites` page.
- **Storage**: balance/plan/window/dedupe live only in the Durable Object; D1
  holds `users` (incl. linked `solana_address`), `payments` (chain-aware) and
  `likes`. D1 also keeps the published site policy revisions.

## Routes

| Route | Method | What |
| --- | --- | --- |
| `/user/login` | GET | wallet login page (`?next=` redirect target) |
| `/user/upgrade` | GET | sign in after reaching a free limit, then open the account top-up form. Signed-in visitors go directly to top-up. |
| `/user/account` | GET | balance, plan, top-up (submit tx hash), payment history |
| `/user/favorites` | GET | liked posts/images/videos |
| `/user/api/nonce` | GET | issue a SIWE / link nonce (KV, 300s, single-use) |
| `/user/api/verify` | POST | verify SIWE message + signature, set `ue_session` |
| `/user/api/logout` | POST | clear the session cookie |
| `/user/api/me` | GET | current address + balance / plan / window status |
| `/user/api/topup` | POST | submit a `{chain, token, tx_hash}` top-up for verification + credit |
| `/user/api/payments` | GET | payment history |
| `/user/api/subscribe` | POST | buy/renew a plan from the balance (no auto-renew) |
| `/user/api/rates` | GET | spot USD prices for ETH/SOL (Chainlink feeds) |
| `/user/api/link_solana` | POST | link a Solana wallet by signing a challenge |
| `/user/api/like` | GET/POST/DELETE | check / add / remove a like |
| `/user/api/likes` | GET | list likes (keyset paginated) |
| `/user/admin` | GET | admin page (Cloudflare Access protected) |
| `/user/admin/settings` | POST | publish the visitor, pricing, plan and payment settings |
| `/user/admin/plan` | POST | grant or revoke a customer subscription |
| `/user/admin/credit` | POST | admin credit/deduct points |
| `/user/admin/ban` | POST | admin ban/unban |

## Points & billing model (v2)

Open **Gallery controls** at `/user/admin` on the gateway hostname. Saving checks the revision shown in the form. Reload and reapply edits if another administrator has already published a change.

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
  - **upload-image search: 100 pts** — runs dinov3 ONNX inference (expensive).
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

Top-ups are crypto only. Submit `{chain, token, tx_hash}` on `/user/account`;
each transaction credits exactly once (`payments` is keyed on the tx hash).

- **Ethereum** — native **ETH** plus ERC-20 **USDT** / **USDC**. Token
  transfers are verified from the `Transfer` event in the receipt logs.
  Requires **≥ 6 confirmations** (`MIN_CONFIRMATIONS`); deposits must go to
  the active Ethereum receiving address.
- **Solana** — native **SOL** plus SPL **USDT** / **USDC**. Verified at the
  **`finalized`** commitment; deposits must go to the active Solana receiving address and
  originate from the user's linked Solana address (see below).
- **USD pricing**: stablecoins (USDT/USDC) are treated as **$1**. Volatile
  assets (ETH, SOL) are priced in USD from **Chainlink on-chain price feeds**
  (an `eth_call` to `latestRoundData` over `RPC_URL`). Credited points =
  USD value × the published points per USD.

### Solana wallet linking

A Solana transaction carries no on-chain link to the SIWE (Ethereum) session,
so a user links a Solana wallet **once**: they sign a challenge with the wallet
(`ed25519` `signMessage`, e.g. Phantom) and POST it to
`/user/api/link_solana`. The verified address is stored on
`users.solana_address` (UNIQUE). SOL/SPL top-ups are only accepted when the
transaction's sender matches this linked address.

## Setup & deployment

1. Create the nonce KV namespace and put its id into `wrangler.toml`:

   ```sh
   wrangler kv namespace create NONCES     # fill id into [[kv_namespaces]] binding = "NONCES"
   ```

2. Set `SIWE_DOMAIN` to your public gallery hostname. Configure `RPC_URL`, `CHAIN_ID` and `SOL_RPC_URL` for your deployment. Fresh deployments start with deposits closed. Enter your receiving addresses in **Payments & credits**. Upgrades retain existing `DEPOSIT_ADDRESS` and `SOL_DEPOSIT_ADDRESS` variables through Wrangler’s `keep_vars` setting. Verify those addresses on the dashboard before the first save, which records the original recipients for historical payments.
3. Protect the public gateway's `/user/admin` path and descendants with an administrator-only Access policy. Put its audience in **gateway_worker/wrangler.toml**. The gateway calls this Worker through the dedicated admin service binding. [Gateway Access setup](../gateway_worker/README.md#cloudflare-access-and-deployment)
4. From the repository root, run `npm ci` to install the pinned Wrangler. For a fresh D1 database, apply `0001_users.sql` first. An existing wallet site with the `users`, `payments` and `likes` tables can start at `0002_site_settings.sql`. This migration adds the settings table and seeds revision 0. It is safe to rerun.

   ```sh
   npx wrangler d1 execute lets-embed --config user_worker/wrangler.toml --remote --file user_worker/migrations/0001_users.sql
   npx wrangler d1 execute lets-embed --config user_worker/wrangler.toml --remote --file user_worker/migrations/0002_site_settings.sql
   npx wrangler d1 execute lets-embed --config user_worker/wrangler.toml --remote --command 'SELECT MAX(revision) AS revision FROM site_settings'
   ```

5. New deployments need the same `JWT_SECRET` in both Workers. Upgrades reuse the existing secret. Set the gateway’s upstream service token as described in its README.
6. Deploy the user Worker first, then the gateway. Run both commands from the repository root.

   ```sh
   npx wrangler deploy --cwd user_worker
   npx wrangler deploy --cwd gateway_worker
   ```

7. Open `/user/admin` from the public gallery hostname. On an upgrade, verify that each chain accepting payments shows its existing receiving address. If an address is unexpectedly blank or wrong, restore its legacy variable on the user Worker and reload before the first save. The first save snapshots those variables for transfers made before the change.
8. Leave **Require a wallet** selected for the first save. Choose **View gallery** to check admin browsing without a wallet, then verify a customer account and a signed-out private window. To enable guest browsing, select **Public browsing**, set **Image views → Free per day** to a positive number or `-1` for unlimited, choose any free media folders, and save. To close public browsing again, select **Require a wallet** and save.

## Limitations

- **EOA only.** Signatures are verified by ecrecover; EIP-1271 contract
  wallets (Safe, etc.) cannot sign in.
- **KV nonces are eventually consistent.** A nonce issued at one edge
  location may briefly be invisible (or appear unconsumed) at another;
  worst case a login retry, not a security hole — verification still
  requires a valid signature over a fresh nonce.

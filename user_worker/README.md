# user_worker

SIWE (Sign-In with Ethereum) user system for lets_embed, running as a Cloudflare
Worker. Replaces the old apply/approve flow in `gateway_worker`.

- **Auth**: SIWE (EIP-4361) only; EOA wallets via `personal_sign` (EIP-1271
  contract wallets are not supported). A successful verify sets an HS256 session
  cookie `ue_session` (signed with the same `lets-embed-jwt-secret` as the
  gateway; `sub` = lowercase address). Nonces are single-use, stored in the
  `NONCES` KV namespace with a 300s TTL.
- **Metering**: every image view (1 pt), video view (5 pts), upload-image
  search (100 pts) and by-id search (10 pts) costs points, deduped per user per
  resource per 24h.
  Enforced by `gateway_worker` calling the per-user `UserAccount` Durable
  Object (bound cross-script).
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
  `likes` (see `migrations/0001_users.sql`).

## Routes

| Route | Method | What |
| --- | --- | --- |
| `/user/login` | GET | wallet login page (`?next=` redirect target) |
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
| `/user/admin/credit` | POST | admin credit/deduct points |
| `/user/admin/ban` | POST | admin ban/unban |

## Points & billing model (v2)

Points are the single internal currency. **$1 = 10,000 points.** Numbers live
in `src/config.rs`.

### Pricing (pay-as-you-go)

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

### Plans

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
  `DEPOSIT_ADDRESS`.
- **Solana** — native **SOL** plus SPL **USDT** / **USDC**. Verified at the
  **`finalized`** commitment; deposits must go to `SOL_DEPOSIT_ADDRESS` and
  originate from the user's linked Solana address (see below).
- **USD pricing**: stablecoins (USDT/USDC) are treated as **$1**. Volatile
  assets (ETH, SOL) are priced in USD from **Chainlink on-chain price feeds**
  (an `eth_call` to `latestRoundData` over `RPC_URL`). Credited points =
  USD value × 10,000.

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

2. Fill in `[vars]` in `wrangler.toml`:
   - `DEPOSIT_ADDRESS` — the ETH address that receives top-ups (**lowercase**
     `0x`).
   - `RPC_URL` / `CHAIN_ID` — Ethereum JSON-RPC endpoint and chain
     (defaults: `https://cloudflare-eth.com`, mainnet `1`). Also used for the
     Chainlink `latestRoundData` price-feed `eth_call`s.
   - `SOL_RPC_URL` — Solana JSON-RPC endpoint (default
     `https://api.mainnet-beta.solana.com`).
   - `SOL_DEPOSIT_ADDRESS` — the Solana address (base58) that receives SOL/SPL
     top-ups. **Set it** — Solana top-ups are rejected until it is configured.
   - `SIWE_DOMAIN` — the public hostname users sign in on (the
     gateway-worker's domain).

3. Create a **new** Cloudflare Access application covering
   `/user/admin*` on the public hostname, and put its AUD into
   `CF_ACCESS_AUD` (`CF_ACCESS_TEAM_DOMAIN` is your team domain).

4. Apply the D1 migration (shared `lets-embed` database). It now adds
   `users.solana_address` (UNIQUE) and a chain-aware `payments` table with
   `chain`, `token` and `amount` columns:

   ```sh
   wrangler d1 execute lets-embed --remote --file user_worker/migrations/0001_users.sql
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

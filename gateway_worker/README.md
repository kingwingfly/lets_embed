# gateway_worker

Edge gateway in front of the Access-service-token-protected Cloud Run
upstreams (api / images / videos). Since the SIWE user system landed, this
worker does **proxy + enforcement only** — all user state lives in
`user_worker`:

- `/user/*` is forwarded to the user-worker via the `USER_WORKER` service
  binding, before any auth (the login page must be reachable).
- Every other request needs a valid `ue_session` cookie (HS256, signed with
  `lets-embed-jwt-secret`, `sub` = lowercase 0x eth address). Unauthenticated
  media GET/HEAD get a plain **401** (an `<img>` tag can't follow a login
  redirect); everything else is **302**'d to `/user/login?next=...`.
- Authenticated `GET /images/*` and `GET /videos/*` are charged against the
  user's `UserAccount` Durable Object (cross-script binding, `script_name =
  "user-worker"`); the DO dedupes repeat views per 24h. DO `402` renders an
  "out of points" page, `403` = account suspended, anything else fails closed
  with 502. HEAD is free.
- Allowed requests are proxied upstream with the `CF-Access-Client-Id/Secret`
  service-token headers; gateway cookies are stripped first.

The old apply/admin-approve flow is gone. Admin now lives at `/user/admin` in
the user-worker, behind a **new** Cloudflare Access application (new AUD).
Legacy `gw_token` / `gw_app` cookies are dead: they were signed with the same
secret, but their UUID `sub` fails the eth-address-shape check, so they are
rejected (and stripped before proxying).

## Usage

- Prepare bindings in `wrangler.toml`: secrets `lets-embed-client-id`,
  `lets-embed-client-secret`, `lets-embed-jwt-secret`, plus the two bindings
  onto the user-worker:

  ```toml
  [[services]]
  binding = "USER_WORKER"
  service = "user-worker"

  [durable_objects]
  bindings = [{ name = "USER_ACCOUNT", class_name = "UserAccount", script_name = "user-worker" }]
  ```

- This worker no longer touches D1 (no D1/KV bindings). The user-system
  schema (`users`, `payments`, `likes`) lives in
  `user_worker/migrations/0001_users.sql`.
- Deploy **after** `user_worker` — both bindings above reference the deployed
  `user-worker` script, so deploying the gateway first fails. Full runbook and
  cutover steps: `user_worker/README.md`.

## Metering

Besides charging media views (`GET /images/*`, `GET /videos/*`) against the
user's `UserAccount` Durable Object, the gateway now also meters **similarity
searches**: `POST /api/search_similar` and `POST /api/search_by_image` are
charged as `ChargeKind::Search`, deduped per query per 24h in the DO (so
paginated re-searches with the same query are free). On insufficient points
these endpoints return a `402` JSON error (`{"error":"out of points"}`) to the
fetch caller — not the HTML payment page used for media navigations.

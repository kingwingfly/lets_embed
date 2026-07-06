# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A distributed image inference + semantic-search system. Images are ingested, tagged and embedded by
ML models (ONNX), stored in Postgres + pgvector, and served through a full-stack search app. It can
run locally (podman + filesystem/HTTP storage) or serverlessly (Cloudflare + GCP, R2 object storage).

## Toolchain & prerequisites

- **Rust nightly** (pinned in `rust-toolchain.toml`), edition 2024, workspace resolver 3. Many crates
  rely on nightly features (`portable_simd`, `iterator_try_collect`, etc.).
- ONNX runtime is loaded dynamically via `ort` with `load-dynamic`. Inference and the search server
  require these env vars at runtime: `ORT_DYLIB_PATH=/path/to/libonnxruntime.so` and
  `ORT_CUDA_VERSION=<cuda major>` (CUDA builds; macOS uses WebGPU instead).
- A reachable Postgres with the **pgvector** extension is required not only at runtime but **at compile
  time** — `sqlx` macros verify queries against a live DB (`DATABASE_URL`) unless offline data exists.
- ML model files are not in the repo; download per `README.md` into `models/`.

## Common commands

```sh
# Build / check the whole workspace
cargo check --workspace
cargo build --release -p embed          # build a single crate

# sqlx: queries are checked at compile time. After changing any SQL, regenerate offline data:
cargo sqlx prepare --workspace          # writes .sqlx/ — required for CI / SQLX_OFFLINE builds
cargo sqlx migrate run                  # apply migrations in migrations/

# Run the inference pipeline against a local image dir
ORT_CUDA_VERSION=13 ORT_DYLIB_PATH=/path/to/libonnxruntime.so \
  cargo run --release -p embed -- -s fs:path/to/images

# Run the search full-stack app (leptos SSR + wasm hydrate, serves on :3000)
cargo leptos serve                      # needs cargo-leptos installed

# Examples (per-crate, run model inference / DB import)
cargo run --example infer_text          # siglip2
cargo run --example infer_tag           # wd_tagger
cargo run --example images2db           # db: import image records
cargo run --example translations2db     # db: import tag translations
```

CI builds with `SQLX_OFFLINE=true`, relying on committed `.sqlx/` data — keep it in sync.

## Local dev infra (podman)

```sh
podman run -d --name pgvector -p 5432:5432 -v ./pgdata:/var/lib/postgresql \
  -e POSTGRES_PASSWORD=postgres docker.io/pgvector/pgvector:pg18-trixie
# GreptimeDB receives OTLP telemetry from `embed` (OTEL_EXPORTER_OTLP_ENDPOINT)
```

## Architecture

The workspace splits into ML model wrappers, an ingestion pipeline, a search stack, and edge/gateway
pieces. Three independent ONNX models drive everything: **wd_tagger** (image → tags),
**siglip2** (CLIP text+vision, used for text→vision search), **dinov3** (vision embeddings).

### Ingestion pipeline — `embed/`
`embed/src/cli.rs` is the heart of the system: a 4-stage Tokio pipeline connected by bounded mpsc
channels:
1. `fetch_batch` — pulls a batch of un-embedded image rows from Postgres using
   `SELECT ... FOR UPDATE SKIP LOCKED`, so many worker nodes can run concurrently without coordination.
2. `convert_image` — streams image bytes from an **OpenDAL** `Operator` (storage is chosen by the
   `-s/--storage` URL scheme: `fs:`, `http(s)://`, or S3/R2 from env vars when omitted).
3. `infer` (blocking) — runs all three ONNX models, producing tags + `HalfVector` embeddings.
4. `record` — upserts results back to Postgres.

Telemetry (`embed/src/telemetry.rs`) exports traces/metrics/logs over OTLP to GreptimeDB; also samples
host + NVML GPU stats.

### Data layer — `db/`
Thin crate of `sqlx` types and bulk-upsert functions (`upsert_metas`, `upsert_translations`). Note the
large CTE-based upserts that fan a single `meta[]` array into posts/images/authors/tags and their join
tables in one statement. Postgres composite types (`image`, `meta`, `translation`) mirror the Rust
structs. Schema lives in `migrations/`.

### Search stack — `search/` + `search_engine/` + `search_types/`
- `search_engine/` — query engine. `LazyModel` lazily loads ONNX sessions and reaps them after an idle
  timeout (saves GPU memory in serverless). Does text→vision (siglip2) and image→vision (dinov3)
  similarity search over pgvector, with a `moka` result cache.
- `search/` is a **Leptos 0.8** full-stack app, split into the standard three crates:
  `app` (shared UI/components, compiles to both SSR and `hydrate`), `server` (axum SSR binary,
  exposes `/api/search` SSE endpoint, serves `/images` + `/videos` static dirs), `frontend`
  (wasm cdylib hydration entry). `cargo-leptos` config is in the root `Cargo.toml`
  (`[[workspace.metadata.leptos]]`), wasm uses the `wasm-release` profile.
- `search_types/` — plain shared types (Post/Image/Author/Tag/Video), `serde` behind a feature so the
  wasm frontend can avoid pulling server deps.

### Edge / access control
- `gateway/` — a **Pingora** reverse proxy. Cloudflare-Access JWT validation lives behind the
  `validate-jwt` feature (`gateway/src/jwt.rs`).
- `gateway_worker/` — a **Cloudflare Worker** (`axum`), now **proxy + enforcement only** (no D1/KV).
  Validates the `ue_session` cookie (HS256, `sub` = lowercase eth address): 401s unauthenticated
  media GET/HEAD, 302s everything else to `/user/login`, forwards `/user/*` to the user-worker via
  the `USER_WORKER` service binding, and charges media views + similarity searches against the
  per-user `UserAccount` Durable Object (cross-script binding). `npm run dev` / `npm run deploy`.
- `user_worker/` — a **Cloudflare Worker** (`axum` + D1 + Durable Objects) that owns the whole user
  system: **SIWE** (EIP-4361) wallet login → `ue_session` cookie; a points-based **billing v2** model
  (pay-as-you-go balance + optional per-window subscription plans, no auto-renew) enforced in the
  per-user `UserAccount` DO; **multi-chain crypto top-up** (Ethereum ETH/ERC-20 + Solana SOL/SPL,
  verified on-chain, priced via Chainlink feeds); and likes/favorites. D1 holds
  `users`/`payments`/`likes` (`user_worker/migrations/0001_users.sql`); balance/plan/dedupe live only
  in the DO. **Deploy `user_worker` before `gateway_worker`** — the gateway's `USER_WORKER` service
  and `USER_ACCOUNT` DO bindings reference it. Full model in `user_worker/README.md`.

### Utilities
- `img2webp/` — converts source images to `.webp` (libvips) between object stores (used as a GCP Cloud
  Run job in the serverless path).
- `tsv/` — scripts to download models to a bucket.

## Deployment

`Dockerfile` is multi-target (`--target=`): `embed-cpu|cuda12|cuda13`, `search-cpu|cuda12|cuda13`,
`img2webp`. `cloudbuild.yaml` builds and pushes all of them to a GCP Artifact Registry. The full
serverless topology (Cloudflare Access tokens, R2, Cloud Run, domain mappings) is documented in
`README.md`.

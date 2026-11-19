This tool converts newly uploaded images in R2 (or a local directory) to `.webp` with `libvips`, writes the converted `.webp` back to R2, and optionally deletes the original object.

# Incremental Mode (Cloudflare Queue HTTP Pull, default for R2)

Instead of walking every directory in R2 (`O(N)`), `img2webp` pulls newly uploaded keys from a Cloudflare Queue (`O(delta)`):

1. Create a queue and enable HTTP Pull Consumer:
   ```sh
   npx wrangler queues create img-webp
   npx wrangler queues consumer http add img-webp
   ```
2. Configure `crawler-worker` (`WEBP_QUEUE` producer) or R2 Event Notifications (`object-create` -> `img-webp`) to enqueue new keys.
3. Run `img2webp --delete-origin` with Cloudflare Queue credentials in `.env`:
   ```
   R2_ENDPOINT=
   R2_BUCKET=
   R2_KEY_ID=
   R2_SECRET_KEY=
   # S3 only
   R2_REGION=

   # Required for queue pull mode
   CF_ACCOUNT_ID=
   CF_QUEUE_ID=
   # API token with Queues Read & Write permissions
   CF_API_TOKEN=

   # Optional: override one-shot metadata crash-recovery journal path
   # (defaults to $TMPDIR/img2webp-meta-<CF_ACCOUNT_ID>-<CF_QUEUE_ID>.json)
   IMG2WEBP_META_JOURNAL=
   ```

Useful flags:
- `--concurrency <N>`: max concurrent storage I/O tasks (`1..=256`, default `2x` logical CPUs clamped to `4..=32`). Network I/O is decoupled from CPU `libvips` encoding (`1x` logical CPUs) and bounded by a `256 MiB` in-flight source buffer budget.
- `--daemon`: keep polling every `--poll-interval-secs` (default `10`) instead of exiting once the queue drains (omit on Cloud Run Jobs; in `--daemon` mode, metadata is not accumulated and `[]` is printed on clean shutdown).
- `--prefix <PREFIX>`: walk only a specific R2/FS directory prefix (`/` appended for directory scoping; empty prefix rejected).
- `--full-scan`: walk the entire R2 bucket (`"/"`) recursively (e.g. one-time backfill). Resumed scans without `--delete-origin` skip downloading/re-encoding objects whose destination `source-etag` already matches.

One-shot metadata recovery:
- In default one-shot queue mode (without `--daemon`), `img2webp` atomically persists converted metadata to `IMG2WEBP_META_JOURNAL` (or `$TMPDIR/img2webp-meta-<CF_ACCOUNT_ID>-<CF_QUEUE_ID>.json`) *before* acknowledging queue leases. If a later batch fails or the process is interrupted by `SIGINT`/`SIGTERM` (which exits non-zero after releasing unstarted leases), the journal is preserved so the next one-shot run recovers and emits all previously converted metadata before deleting the journal on clean completion.

# Deploy

## deploy on vm
```sh
podman build --target img2webp -t img2webp:latest .
podman save img2webp:latest | gzip > img2webp.tar.gz
podman load -i img2webp.tar.gz
podman run --rm --name img2webp --env-file .env img2webp:latest --delete-origin
```

## or gcloud run

- Build img2webp as container
- `gcloud artifacts repositories create <REPO> --repository-format=docker --location=us-central1`
- `gcloud auth configure-docker us-central1-docker.pkg.dev`
- `podman tag img2webp:latest us-central1-docker.pkg.dev/<PROJECT>/<REPO>/img2webp:latest`
- `podman push us-central1-docker.pkg.dev/<PROJECT>/<REPO>/img2webp:latest`
- `gcloud secrets create img2webp-env --data-file=.env`
- Run on Cloud Run Jobs with `--set-secrets=/app/.env=img2webp-env:latest` and `--args="--delete-origin"`

# Compile

For macos only:
```sh
export LIBRARY_PATH="/opt/homebrew/lib:$LIBRARY_PATH"
export DYLD_LIBRARY_PATH="/opt/homebrew/lib:$DYLD_LIBRARY_PATH"
export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig:$PKG_CONFIG_PATH"
```

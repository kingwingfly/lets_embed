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
   ```

Useful flags:
- `--daemon`: keep polling every `--poll-interval-secs` (default `10`) instead of exiting once the queue drains (omit on Cloud Run Jobs).
- `--prefix <PREFIX>`: walk only a specific R2/FS directory prefix.
- `--full-scan`: walk the entire R2 bucket (`"/"`) recursively (e.g. one-time backfill).

# Deploy

## deploy on vm
```sh
podman build -t img2webp:latest img2webp
podman save img2webp:latest | gzip > img2webp.tar.gz
podman load -i img2webp.tar.gz
podman run --rm --name img2webp --env-file .env img2webp:latest --delete-origin
```

## or gcloud run

- Build img2webp as container
- `gcloud artifacts repositories create xx --repository-format=docker ...`
- `gcloud auth configure-docker us-central1-docker.pkg.dev`
- `podman tag img2webp:latest us-central1-docker.pkg.dev/xx/img2webp:latest`
- `podman push ...`
- `gcloud secrets create --data-file=.env`
- run it with `gcloud run` (`--args="--delete-origin"`)

# Compile

For macos only:
```sh
export LIBRARY_PATH="/opt/homebrew/lib:$LIBRARY_PATH"
export DYLD_LIBRARY_PATH="/opt/homebrew/lib:$DYLD_LIBRARY_PATH"
export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig:$PKG_CONFIG_PATH"
```

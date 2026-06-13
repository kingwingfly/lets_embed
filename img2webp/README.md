This tool walk through the directory, convert all `.bin` to `.webp` with `libvips`.
Then write the converted `.webp` back to R2 and delete the original `.bin`.

# Deploy

## deploy on vm
```sh
podman build -t img2webp:latest img2webp
podman save img2webp:latest | gzip > img2webp.tar.gz
podman load -i img2webp.tar.gz
podman run --rm --name img2webp --env-file .env run img2webp:latest
```

## or gcloud run

- Build img2webp as container
- `gcloud artifacts repositories create xx --repository-format=docker ...`
- `gcloud auth configure-docker us-central1-docker.pkg.dev`
- `podman tag img2webp:latest us-central1-docker.pkg.dev/xx/img2webp:latest` 
- `podman push ...`
- `gcloud secrets create --data-file=.env`
- run it with `gcloud run`

# Compile

For macos only:
```sh
export LIBRARY_PATH="/opt/homebrew/lib:$LIBRARY_PATH"
export DYLD_LIBRARY_PATH="/opt/homebrew/lib:$DYLD_LIBRARY_PATH"
export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig:$PKG_CONFIG_PATH"
```

`--release` walk through directory in R2
`--debug` walk through directory in `./assets`

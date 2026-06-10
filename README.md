# Usage

Model download
```sh
mkdir -p models/wd-eva02-large-tagger-v3/onnx
# download wd-tagger ONNX
wget -O models/wd-eva02-large-tagger-v3/onnx/wd-eva02-large-tagger-v3.onnx https://huggingface.co/SmilingWolf/wd-eva02-large-tagger-v3/resolve/main/model.onnx?download=true
wget -O models/wd-eva02-large-tagger-v3/selected_tags.csv https://huggingface.co/SmilingWolf/wd-eva02-large-tagger-v3/resolve/main/selected_tags.csv?download=true

mkdir -p models/siglip2-so400m-patch14-384/onnx
# download google/siglip2-so400m-patch14-384 ONNX
wget -O models/siglip2-so400m-patch14-384/onnx/text_model.onnx https://huggingface.co/onnx-community/siglip2-so400m-patch14-384-ONNX/resolve/main/onnx/text_model.onnx?download=true
wget -O models/siglip2-so400m-patch14-384/onnx/text_model.onnx_data https://huggingface.co/onnx-community/siglip2-so400m-patch14-384-ONNX/resolve/main/onnx/text_model.onnx_data?download=true
wget -O models/siglip2-so400m-patch14-384/tokenizer.json https://huggingface.co/onnx-community/siglip2-so400m-patch14-384-ONNX/resolve/main/tokenizer.json?download=true
wget -O models/siglip2-so400m-patch14-384/onnx/vision_model.onnx https://huggingface.co/onnx-community/siglip2-so400m-patch14-384-ONNX/resolve/main/onnx/vision_model.onnx?download=true

mkdir -p models/dinov3-vitb16-pretrain-lvd1689m/onnx
# download facebook/dinov3-vitb16-pretrain-lvd1689m ONNX
wget -O models/dinov3-vitb16-pretrain-lvd1689m/onnx/model.onnx https://huggingface.co/onnx-community/dinov3-vitb16-pretrain-lvd1689m-ONNX/resolve/main/onnx/model.onnx?download=true
wget -O models/dinov3-vitb16-pretrain-lvd1689m/onnx/model.onnx_data https://huggingface.co/onnx-community/dinov3-vitb16-pretrain-lvd1689m-ONNX/resolve/main/onnx/model.onnx_data?download=true
```

Try infer
```sh
# set `ORT_CUDA_VERSION` you cuda version
ORT_CUDA_VERSION=13 ORT_DYLIB_PATH=/path/to/libonnxruntime.so cargo run --example infer_text
ORT_CUDA_VERSION=13 ORT_DYLIB_PATH=/path/to/libonnxruntime.so cargo run --example infer_vision
ORT_CUDA_VERSION=13 ORT_DYLIB_PATH=/path/to/libonnxruntime.so cargo run --example infer_tag
```

# Distributed inference

Based on `wd-tagger`, `dinov3` and `siglip2`, the tags and vision embeddings are stored into db.

## Control node

```sh
# set up pgdb
mkdir pgdata
podman run -d --name pgvector -p 5432:5432 -v ./pgdata:/var/lib/postgresql -e POSTGRES_PASSWORD=postgres docker.io/pgvector/pgvector:pg18-trixie
# - migrate
cargo install sqlx-cli --no-default-features --features native-tls,postgres
cargo sqlx migrate run
# - import image records
cargo run --release --example images2db
# set up greptime db for telemetry
mkdir gtdata
podman run -d --name greptime -p 4000:4000 -v ./gtdata:/greptimedb_data docker.io/greptime/greptimedb:v1.0.2 standalone start --http-addr=0.0.0.0:4000
# (option) set up grafana, or you can use greptimedb's `127.0.0.1:4000/dashboard` directly
podman run -d --name grafana -p 3000:3000 docker.io/greptime/grafana-greptimedb:11.2.5-greptime-v2.1.7
```

## Worker node

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4000/v1/otlp \
DATABASE_URL=postgres://postgres:postgres@postgres:5432/postgres \
ORT_CUDA_VERSION=13 \
ORT_DYLIB_PATH=/path/to/libonnxruntime.so \
cargo run --release -p embed -- -s fs:path/to/images
```

## Telemetry

Visit `127.0.0.1:4000/dashboard` to see the training process.

Moreover, `greptime db` [dashboard config file](assets/dashboard.json) is provided.

# Wd-tags Translation

Add translations/alias_names to wd_tags.

```sh
# (optional) use scraper to get translations (aliases) of wd tagger selected tags
cargo run --example translate
# import translations into db (use assets/translations.json)
cargo run --example translations2db
```

# Search (full-stack app based on axum/sqlx and **leptos**)

After inferring/embedding, you can do search on the data:
```sh
cargo binstall --locked cargo-leptos

ORT_CUDA_VERSION=13 \
ORT_DYLIB_PATH=/path/to/libonnxruntime.so \
cargo leptos serve

# broswer http://127.0.0.1:3000
```

# Dev

```sh
mkdir pg_data
podman run -d --name pgvector -p 5432:5432 -v ./pgdata:/var/lib/postgresql -e POSTGRES_PASSWORD=postgres docker.io/pgvector/pgvector:pg18-trixie
# so that sqlx can compile

# to compile in CI
cargo sqlx prepare --workspace
```

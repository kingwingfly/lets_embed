# Usage

Model download
```sh
mkdir models
wget -O models/cn_clip_text.onnx https://huggingface.co/felixdu/chinese-clip-vit-base-patch16-onnx/resolve/main/cn_clip_text.onnx
wget -O models/cn_clip_vision.onnx https://huggingface.co/felixdu/chinese-clip-vit-base-patch16-onnx/resolve/main/cn_clip_vision.onnx
wget -O models/tokenizer.json https://huggingface.co/Xenova/chinese-clip-vit-base-patch16/resolve/main/tokenizer.json?download=true

wget -O models/wd-eva02-large-tagger-v3.onnx https://huggingface.co/SmilingWolf/wd-eva02-large-tagger-v3/resolve/main/model.onnx
wget -O models/selected_tags.csv https://huggingface.co/SmilingWolf/wd-eva02-large-tagger-v3/resolve/main/selected_tags.csv?download=true
```

Try infer
```sh
# set `ORT_CUDA_VERSION` you cuda version
ORT_CUDA_VERSION=13 cargo run --example infer_text
ORT_CUDA_VERSION=13 cargo run --example infer_vision
```

# Distribute infer

## Control node

```sh
# set up pgdb
mkdir pgdata
podman run -d --name pgvector -p 5432:5432 -v ./pgdata:/var/lib/postgresql -e POSTGRES_PASSWORD=postgres docker.io/pgvector/pgvector:pg18-trixie
# - migrate
cargo install --locked sqlx-cli --no-default-features --features native-tls,postgres
cargo sqlx migrate run
# - import image records
cargo run --release --example images2db
# set up greptime db for telemetry
mkdir gtdata
podman run -d --name greptime -p 4000:4000 -v ./gtdata:/greptimedb_data docker.io/greptime/greptimedb:v1.0.2 standalone start --http-addr=0.0.0.0:4000
# (option) set up grafana, or you can use `127.0.0.1:4000/dashboard` directly
podman run -d --name grafana -p 3000:3000 docker.io/greptime/grafana-greptimedb:11.2.5-greptime-v2.1.7
```

## Worker node

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4000/v1/otlp \
ORT_CUDA_VERSION=13 \
ORT_DYLIB_PATH=/path/to/libonnxruntime.so \
cargo run --release -p embed -- -s fs:path/to/images
# or `OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4000/v1/otlp` if telemetry to greptime db directly
```

## Telemetry

Visit `127.0.0.1:4000/dashboard` to see the training process.

Moreover, `greptime db` [dashboard config file](assets/dashboard.json) is provided.

# Search

After infer/embed, you can do search on the data:
```sh
ORT_CUDA_VERSION=13 \
ORT_DYLIB_PATH=/path/to/libonnxruntime.so \
cargo run --example search
```

# Search

```sh
cargo run -p search -- serve --prefix /data/to/images

# broswer http://127.0.0.1:3000

# search by tag
cargo run -p search -- tag --include "genshin impact" --limit 20
# search by clip
cargo run -p search --example client -- clip --query "长满青苔的小路" --query "樱花飞舞" --limit 10
```

# Dev

```bash
mkdir pg_data
podman run -d --name pgvector -p 5432:5432 -v ./pgdata:/var/lib/postgresql -e POSTGRES_PASSWORD=postgres docker.io/pgvector/pgvector:pg18-trixie
# so that sqlx can compile
```

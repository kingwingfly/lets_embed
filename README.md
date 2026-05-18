# Usage

Model download
```sh
mkdir models
wget -O models/cn_clip_text.onnx https://huggingface.co/felixdu/chinese-clip-vit-base-patch16-onnx/resolve/main/cn_clip_text.onnx
wget -O models/cn_clip_vision.onnx https://huggingface.co/felixdu/chinese-clip-vit-base-patch16-onnx/resolve/main/cn_clip_vision.onnx
wget -O models/tokenizer.json https://huggingface.co/Xenova/chinese-clip-vit-base-patch16/resolve/main/tokenizer.json?download=true
```

# Dev

```bash
mkdir pg_data
podman run -d --name pgvector -p 5432:5432 -v ./pgdata:/var/lib/postgresql -e POSTGRES_PASSWORD=postgres docker.io/pgvector/pgvector:pg18-trixie
```

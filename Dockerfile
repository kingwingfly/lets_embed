# syntax=docker/dockerfile:1
ARG ORT_VERSION=1.26.0

############################################################
# onnxruntime download stage
############################################################
FROM debian:bookworm-slim AS dl-base
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /opt

FROM dl-base AS ort-cpu
ARG ORT_VERSION
RUN curl -fL https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VERSION}/onnxruntime-linux-x64-${ORT_VERSION}.tgz | tar xz && \
    mv onnxruntime-linux-x64-${ORT_VERSION} onnxruntime

FROM dl-base AS ort-cuda12
ARG ORT_VERSION
RUN curl -fL https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VERSION}/onnxruntime-linux-x64-gpu-${ORT_VERSION}.tgz | tar xz && \
    mv onnxruntime-linux-x64-gpu-${ORT_VERSION} onnxruntime

FROM dl-base AS ort-cuda13
ARG ORT_VERSION
RUN curl -fL https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VERSION}/onnxruntime-linux-x64-gpu_cuda13-${ORT_VERSION}.tgz | tar xz && \
    mv onnxruntime-linux-x64-gpu-${ORT_VERSION} onnxruntime

############################################################
# builders
############################################################
FROM rust:1.96-bookworm AS builder-base
WORKDIR /app
COPY . .
ENV SQLX_OFFLINE=true

FROM builder-base AS embed-builder
RUN cargo build -p embed --release

FROM builder-base AS search-builder
RUN apt-get update && \
    apt-get install -y --no-install-recommends cmake && \
    rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-unknown-unknown && \
    curl -fL --proto '=https' --tlsv1.2 https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash && \
    cargo binstall --locked --no-confirm cargo-leptos
RUN cargo leptos build --release
RUN cargo build -p gateway -F validate-jwt --release

############################################################
# embed runtimes
############################################################
FROM debian:bookworm-slim AS embed-cpu
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=ort-cpu /opt/onnxruntime /opt/onnxruntime
COPY --from=embed-builder /app/target/release/embed /usr/local/bin/embed
WORKDIR /app
RUN useradd -r -u 10001 appuser
USER appuser
ENV ORT_DYLIB_PATH=/opt/onnxruntime/lib/libonnxruntime.so
ENTRYPOINT ["embed"]

FROM nvidia/cuda:12.9.2-cudnn-runtime-ubuntu24.04 AS embed-cuda12
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates cuda-compat-12-9 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=ort-cuda12 /opt/onnxruntime /opt/onnxruntime
COPY --from=embed-builder /app/target/release/embed /usr/local/bin/embed
WORKDIR /app
RUN useradd -r -u 10001 appuser
USER appuser
ENV LD_LIBRARY_PATH=/usr/local/cuda/compat:${LD_LIBRARY_PATH} \
    ORT_DYLIB_PATH=/opt/onnxruntime/lib/libonnxruntime.so
ENTRYPOINT ["embed"]

FROM nvidia/cuda:13.3.0-cudnn-runtime-ubuntu24.04 AS embed-cuda13
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=ort-cuda13 /opt/onnxruntime /opt/onnxruntime
COPY --from=embed-builder /app/target/release/embed /usr/local/bin/embed
WORKDIR /app
RUN useradd -r -u 10001 appuser
USER appuser
ENV ORT_DYLIB_PATH=/opt/onnxruntime/lib/libonnxruntime.so
ENTRYPOINT ["embed"]

############################################################
# search runtimes
############################################################
FROM debian:bookworm-slim AS search-cpu
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=ort-cpu /opt/onnxruntime /opt/onnxruntime
COPY --from=search-builder /app/target/release/server /usr/local/bin/server
COPY --from=search-builder /app/target/release/gateway /usr/local/bin/gateway
COPY --from=search-builder /app/target/site /site

COPY <<'EOF' /usr/local/bin/start.sh
#!/usr/bin/env bash
set -uo pipefail
trap 'kill -TERM $(jobs -p) 2>/dev/null' TERM INT

server "$@" &
gateway &

wait -n                      # 任一进程退出
code=$?
kill -TERM $(jobs -p) 2>/dev/null
wait
exit $code
EOF
RUN chmod +x /usr/local/bin/start.sh

WORKDIR /app
RUN useradd -r -u 10001 appuser
USER appuser
ENV ORT_DYLIB_PATH=/opt/onnxruntime/lib/libonnxruntime.so \
    LEPTOS_SITE_ROOT=/site
ENTRYPOINT ["start.sh"]

FROM nvidia/cuda:12.9.2-cudnn-runtime-ubuntu24.04 AS search-cuda12
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates cuda-compat-12-9 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=ort-cuda12 /opt/onnxruntime /opt/onnxruntime
COPY --from=search-builder /app/target/release/server /usr/local/bin/server
COPY --from=search-builder /app/target/release/gateway /usr/local/bin/gateway
COPY --from=search-builder /app/target/site /site

COPY <<'EOF' /usr/local/bin/start.sh
#!/usr/bin/env bash
set -uo pipefail
trap 'kill -TERM $(jobs -p) 2>/dev/null' TERM INT

server "$@" &
gateway &

wait -n                      # any process exits
code=$?
kill -TERM $(jobs -p) 2>/dev/null
wait
exit $code
EOF
RUN chmod +x /usr/local/bin/start.sh

WORKDIR /app
RUN useradd -r -u 10001 appuser
USER appuser
ENV ORT_DYLIB_PATH=/opt/onnxruntime/lib/libonnxruntime.so \
    LEPTOS_SITE_ROOT=/site
ENTRYPOINT ["start.sh"]

FROM nvidia/cuda:13.3.0-cudnn-runtime-ubuntu24.04 AS search-cuda13
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=ort-cuda13 /opt/onnxruntime /opt/onnxruntime
COPY --from=search-builder /app/target/release/server /usr/local/bin/server
COPY --from=search-builder /app/target/release/gateway /usr/local/bin/gateway
COPY --from=search-builder /app/target/site /site

COPY <<'EOF' /usr/local/bin/start.sh
#!/usr/bin/env bash
set -uo pipefail
trap 'kill -TERM $(jobs -p) 2>/dev/null' TERM INT

server "$@" &
gateway &

wait -n                      # any process exits
code=$?
kill -TERM $(jobs -p) 2>/dev/null
wait
exit $code
EOF
RUN chmod +x /usr/local/bin/start.sh

WORKDIR /app
RUN useradd -r -u 10001 appuser
USER appuser
ENV ORT_DYLIB_PATH=/opt/onnxruntime/lib/libonnxruntime.so \
    LEPTOS_SITE_ROOT=/site
ENTRYPOINT ["start.sh"]

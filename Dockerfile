# syntax=docker/dockerfile:1
ARG ORT_VERSION=1.32.0
ARG VIPS_VERSION=8.18.2

############################################################
# onnxruntime download stage
############################################################
# github.com/microsoft/onnxruntime release assets are currently unavailable
# (repo returns 404), so pull the official Microsoft NuGet packages instead.
# They ship the same linux-x64 shared libraries under
# runtimes/linux-x64/native/. The sha256 pins are for ORT_VERSION=1.32.0;
# update them together with ORT_VERSION.
#   cpu    : nuget.org  Microsoft.ML.OnnxRuntime
#   cuda13 : nuget.org  Microsoft.ML.OnnxRuntime.Gpu.Linux (CUDA 13 build)
#   cuda12 : MS ADO feed onnxruntime-cuda-12, Microsoft.ML.OnnxRuntime.Gpu.Linux
FROM debian:bookworm-slim AS dl-base
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates unzip && \
    rm -rf /var/lib/apt/lists/*
COPY <<'EOF' /usr/local/bin/fetch-ort
#!/bin/sh
# usage: fetch-ort <nupkg-url> <sha256>
set -eu
url="$1"
sha="$2"
curl -fsSL --retry 5 --retry-delay 2 -o /tmp/ort.nupkg "$url"
echo "${sha}  /tmp/ort.nupkg" | sha256sum -c -
unzip -q /tmp/ort.nupkg 'runtimes/linux-x64/native/*' -d /tmp/ort
mkdir -p /opt/onnxruntime/lib
mv /tmp/ort/runtimes/linux-x64/native/* /opt/onnxruntime/lib/
ln -s libonnxruntime.so /opt/onnxruntime/lib/libonnxruntime.so.1
rm -rf /tmp/ort /tmp/ort.nupkg
test -f /opt/onnxruntime/lib/libonnxruntime.so
EOF
RUN chmod +x /usr/local/bin/fetch-ort
WORKDIR /opt

FROM dl-base AS ort-cpu
ARG ORT_VERSION
ARG ORT_CPU_SHA256=a9150bc2992cbbb6722070da9910e1ffa989a8bfc67bdd5bb8e745ca755641db
RUN fetch-ort \
    "https://api.nuget.org/v3-flatcontainer/microsoft.ml.onnxruntime/${ORT_VERSION}/microsoft.ml.onnxruntime.${ORT_VERSION}.nupkg" \
    "${ORT_CPU_SHA256}"

FROM dl-base AS ort-cuda12
ARG ORT_VERSION
ARG ORT_CUDA12_SHA256=aa4220de9938f974657d9c29fec5f87f3897c4b57eaa7419efa3cfb810e56c43
RUN fetch-ort \
    "https://aiinfra.pkgs.visualstudio.com/PublicPackages/_packaging/onnxruntime-cuda-12/nuget/v3/flat2/microsoft.ml.onnxruntime.gpu.linux/${ORT_VERSION}/microsoft.ml.onnxruntime.gpu.linux.${ORT_VERSION}.nupkg" \
    "${ORT_CUDA12_SHA256}" && \
    test -f /opt/onnxruntime/lib/libonnxruntime_providers_cuda.so

FROM dl-base AS ort-cuda13
ARG ORT_VERSION
ARG ORT_CUDA13_SHA256=3d01949bc846d41961b37988d1e63d782a6effcb93b650a6e0577fef982d38b5
RUN fetch-ort \
    "https://api.nuget.org/v3-flatcontainer/microsoft.ml.onnxruntime.gpu.linux/${ORT_VERSION}/microsoft.ml.onnxruntime.gpu.linux.${ORT_VERSION}.nupkg" \
    "${ORT_CUDA13_SHA256}" && \
    test -f /opt/onnxruntime/lib/libonnxruntime_providers_cuda.so

############################################################
# builders
############################################################
FROM rust:1.96-bookworm AS builder-base
RUN apt-get update && \
    apt-get install -y --no-install-recommends cmake && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
ENV SQLX_OFFLINE=true

FROM builder-base AS embed-builder
RUN cargo build -p embed --release

FROM builder-base AS search-builder
RUN rustup target add wasm32-unknown-unknown && \
    curl -fL --proto '=https' --tlsv1.2 https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash && \
    cargo binstall --locked --no-confirm cargo-leptos
RUN cargo leptos build --release
RUN cargo build -p gateway -F validate-jwt --release

FROM debian:bookworm-slim AS vips-builder
ARG VIPS_VERSION
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ninja-build meson pkg-config wget ca-certificates \
    libglib2.0-dev libexpat1-dev \
    libjpeg62-turbo-dev libpng-dev libwebp-dev libtiff-dev \
    libgif-dev libexif-dev librsvg2-dev libheif-dev \
    && rm -rf /var/lib/apt/lists/*
RUN wget -q https://github.com/libvips/libvips/releases/download/v${VIPS_VERSION}/vips-${VIPS_VERSION}.tar.xz \
    && tar xf vips-${VIPS_VERSION}.tar.xz \
    && cd vips-${VIPS_VERSION} \
    && meson setup build --prefix=/usr/local --buildtype=release \
    && ninja -C build \
    && ninja -C build install \
    && ldconfig

FROM rust:1.96-bookworm AS img2webp-builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config clang cmake \
    libglib2.0-dev libexpat1-dev libjpeg62-turbo-dev libpng-dev libwebp-dev \
    libtiff-dev libgif-dev libexif-dev librsvg2-dev libheif-dev \
    && rm -rf /var/lib/apt/lists/*
COPY --from=vips-builder /usr/local /usr/local
RUN ldconfig
ENV PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig:/usr/local/lib/pkgconfig
ENV RUSTFLAGS="-L /usr/local/lib/x86_64-linux-gnu -L /usr/local/lib"
ENV SQLX_OFFLINE=true
WORKDIR /app
COPY . .
RUN cargo build -p img2webp --release

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

FROM nvcr.io/nvidia/cuda:12.9.2-cudnn-runtime-ubuntu24.04 AS embed-cuda12
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates cuda-compat-12-9 && \
    rm -f /etc/ld.so.conf.d/*cuda*compat*.conf && \
    ldconfig && \
    rm -rf /var/lib/apt/lists/*
COPY --from=ort-cuda12 /opt/onnxruntime /opt/onnxruntime
COPY --from=embed-builder /app/target/release/embed /usr/local/bin/embed
COPY <<'EOF' /usr/local/bin/cuda-entrypoint.sh
#!/usr/bin/env bash
set -euo pipefail

use_compat="0"
case "${CUDA_COMPAT:-auto}" in
    always|1|true)
        use_compat="1"
        ;;
    never|0|false)
        use_compat="0"
        ;;
    auto|"")
        driver_ver=""
        if [[ -r /proc/driver/nvidia/version ]]; then
            driver_ver=$(sed -nE 's/^NVRM version:.*[[:space:]]([0-9]{3,}\.[0-9.]+).*/\1/p' /proc/driver/nvidia/version | head -n1 || true)
        fi
        if [[ -z "$driver_ver" ]]; then
            for lib in /usr/local/nvidia/lib64/libcuda.so.[0-9]* /usr/local/nvidia/lib/libcuda.so.[0-9]* /usr/lib/x86_64-linux-gnu/libcuda.so.[0-9]* /usr/lib64/libcuda.so.[0-9]*; do
                resolved=$(readlink -f "$lib" 2>/dev/null || printf '%s' "$lib")
                if [[ -e "$resolved" && "$resolved" =~ \.so\.([0-9]{3,}\.[0-9]+(\.[0-9]+)?)$ ]]; then
                    driver_ver="${BASH_REMATCH[1]}"
                    break
                fi
            done
        fi
        if [[ -n "$driver_ver" ]] && (( 10#${driver_ver%%.*} >= 525 && 10#${driver_ver%%.*} < 575 )); then
            use_compat="1"
        fi
        ;;
    *)
        echo "invalid CUDA_COMPAT=${CUDA_COMPAT} (expected auto|always|never)" >&2
        exit 2
        ;;
esac
if [[ "$use_compat" == "1" && -d /usr/local/cuda/compat ]]; then
    export LD_LIBRARY_PATH="/usr/local/cuda/compat${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

exec embed "$@"
EOF
RUN chmod +x /usr/local/bin/cuda-entrypoint.sh
WORKDIR /app
RUN useradd -r -u 10001 appuser
USER appuser
ENV ORT_DYLIB_PATH=/opt/onnxruntime/lib/libonnxruntime.so
ENTRYPOINT ["cuda-entrypoint.sh"]

FROM nvcr.io/nvidia/cuda:13.3.0-cudnn-runtime-ubuntu24.04 AS embed-cuda13
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
COPY --from=search-builder /app/target/release/hash.txt /hash.txt
COPY <<'EOF' /usr/local/bin/start.sh
#!/usr/bin/env bash
set -uo pipefail
sig_code=0
cleanup() {
    local pids
    pids=$(jobs -p)
    if [[ -n "$pids" ]]; then
        kill -TERM $pids 2>/dev/null || true
    fi
}
on_signal() {
    sig_code=$1
    cleanup
}
trap 'on_signal 143' TERM
trap 'on_signal 130' INT

if (( sig_code )); then
    exit "$sig_code"
fi
server "$@" &
gateway &
if (( sig_code )); then
    cleanup
    wait
    exit "$sig_code"
fi

wait -n                      # 任一进程退出
code=$?
cleanup
wait
if (( sig_code )); then
    exit "$sig_code"
fi
exit "$code"
EOF
RUN chmod +x /usr/local/bin/start.sh
WORKDIR /app
RUN useradd -r -u 10001 appuser
USER appuser
ENV ORT_DYLIB_PATH=/opt/onnxruntime/lib/libonnxruntime.so \
    LEPTOS_SITE_ROOT=/site \
    LEPTOS_HASH_FILES=true \
    LEPTOS_HASH_FILE_NAME=/hash.txt
ENTRYPOINT ["start.sh"]

FROM nvcr.io/nvidia/cuda:12.9.2-cudnn-runtime-ubuntu24.04 AS search-cuda12
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates cuda-compat-12-9 && \
    rm -f /etc/ld.so.conf.d/*cuda*compat*.conf && \
    ldconfig && \
    rm -rf /var/lib/apt/lists/*
COPY --from=ort-cuda12 /opt/onnxruntime /opt/onnxruntime
COPY --from=search-builder /app/target/release/server /usr/local/bin/server
COPY --from=search-builder /app/target/release/gateway /usr/local/bin/gateway
COPY --from=search-builder /app/target/site /site
COPY --from=search-builder /app/target/release/hash.txt /hash.txt
COPY <<'EOF' /usr/local/bin/start.sh
#!/usr/bin/env bash
set -uo pipefail
sig_code=0
cleanup() {
    local pids
    pids=$(jobs -p)
    if [[ -n "$pids" ]]; then
        kill -TERM $pids 2>/dev/null || true
    fi
}
on_signal() {
    sig_code=$1
    cleanup
}
trap 'on_signal 143' TERM
trap 'on_signal 130' INT

use_compat="0"
case "${CUDA_COMPAT:-auto}" in
    always|1|true)
        use_compat="1"
        ;;
    never|0|false)
        use_compat="0"
        ;;
    auto|"")
        driver_ver=""
        if [[ -r /proc/driver/nvidia/version ]]; then
            driver_ver=$(sed -nE 's/^NVRM version:.*[[:space:]]([0-9]{3,}\.[0-9.]+).*/\1/p' /proc/driver/nvidia/version | head -n1 || true)
        fi
        if [[ -z "$driver_ver" ]]; then
            for lib in /usr/local/nvidia/lib64/libcuda.so.[0-9]* /usr/local/nvidia/lib/libcuda.so.[0-9]* /usr/lib/x86_64-linux-gnu/libcuda.so.[0-9]* /usr/lib64/libcuda.so.[0-9]*; do
                resolved=$(readlink -f "$lib" 2>/dev/null || printf '%s' "$lib")
                if [[ -e "$resolved" && "$resolved" =~ \.so\.([0-9]{3,}\.[0-9]+(\.[0-9]+)?)$ ]]; then
                    driver_ver="${BASH_REMATCH[1]}"
                    break
                fi
            done
        fi
        if [[ -n "$driver_ver" ]] && (( 10#${driver_ver%%.*} >= 525 && 10#${driver_ver%%.*} < 575 )); then
            use_compat="1"
        fi
        ;;
    *)
        echo "invalid CUDA_COMPAT=${CUDA_COMPAT} (expected auto|always|never)" >&2
        exit 2
        ;;
esac
if [[ "$use_compat" == "1" && -d /usr/local/cuda/compat ]]; then
    export LD_LIBRARY_PATH="/usr/local/cuda/compat${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

if (( sig_code )); then
    exit "$sig_code"
fi
server "$@" &
gateway &
if (( sig_code )); then
    cleanup
    wait
    exit "$sig_code"
fi

wait -n                      # any process exits
code=$?
cleanup
wait
if (( sig_code )); then
    exit "$sig_code"
fi
exit "$code"
EOF
RUN chmod +x /usr/local/bin/start.sh
WORKDIR /app
RUN useradd -r -u 10001 appuser
USER appuser
ENV ORT_DYLIB_PATH=/opt/onnxruntime/lib/libonnxruntime.so \
    LEPTOS_SITE_ROOT=/site \
    LEPTOS_HASH_FILES=true \
    LEPTOS_HASH_FILE_NAME=/hash.txt
ENTRYPOINT ["start.sh"]

FROM nvcr.io/nvidia/cuda:13.3.0-cudnn-runtime-ubuntu24.04 AS search-cuda13
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=ort-cuda13 /opt/onnxruntime /opt/onnxruntime
COPY --from=search-builder /app/target/release/server /usr/local/bin/server
COPY --from=search-builder /app/target/release/gateway /usr/local/bin/gateway
COPY --from=search-builder /app/target/site /site
COPY --from=search-builder /app/target/release/hash.txt /hash.txt
COPY <<'EOF' /usr/local/bin/start.sh
#!/usr/bin/env bash
set -uo pipefail
sig_code=0
cleanup() {
    local pids
    pids=$(jobs -p)
    if [[ -n "$pids" ]]; then
        kill -TERM $pids 2>/dev/null || true
    fi
}
on_signal() {
    sig_code=$1
    cleanup
}
trap 'on_signal 143' TERM
trap 'on_signal 130' INT

if (( sig_code )); then
    exit "$sig_code"
fi
server "$@" &
gateway &
if (( sig_code )); then
    cleanup
    wait
    exit "$sig_code"
fi

wait -n                      # any process exits
code=$?
cleanup
wait
if (( sig_code )); then
    exit "$sig_code"
fi
exit "$code"
EOF
RUN chmod +x /usr/local/bin/start.sh
WORKDIR /app
RUN useradd -r -u 10001 appuser
USER appuser
ENV ORT_DYLIB_PATH=/opt/onnxruntime/lib/libonnxruntime.so \
    LEPTOS_SITE_ROOT=/site \
    LEPTOS_HASH_FILES=true \
    LEPTOS_HASH_FILE_NAME=/hash.txt
ENTRYPOINT ["start.sh"]

############################################################
# img2webp runtimes
############################################################
FROM debian:bookworm-slim AS img2webp
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libglib2.0-0 libexpat1 \
    libjpeg62-turbo libpng16-16 libwebp7 libwebpmux3 libwebpdemux2 \
    libtiff6 libgif7 libexif12 librsvg2-2 libheif1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=vips-builder /usr/local/lib /usr/local/lib
RUN ldconfig
COPY --from=img2webp-builder /app/target/release/img2webp /usr/local/bin/img2webp
WORKDIR /app
RUN useradd -r -u 10001 appuser
USER appuser
ENTRYPOINT ["img2webp"]

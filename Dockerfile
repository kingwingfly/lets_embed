FROM rust:1.86-bookworm AS app-builder

WORKDIR /app

RUN curl -LO https://github.com/microsoft/onnxruntime/releases/download/v1.26.0/onnxruntime-linux-x64-gpu_cuda13-1.26.0.tgz && \
    tar xvf onnxruntime-linux-x64-gpu_cuda13-1.26.0.tgz

COPY . .
ENV SQLX_OFFLINE=true
RUN cargo build -p embed --release

FROM nvidia/cuda:13.3.0-cudnn-runtime-ubuntu24.04 AS runtime

COPY --from=app-builder /app/onnxruntime-linux-x64-gpu-1.26.0 /onnxruntime-linux-x64-gpu-1.26.0
COPY --from=app-builder /app/target/release/embed /usr/local/bin/embed

WORKDIR /app
RUN useradd -r -u 10001 appuser
USER appuser
ENV ORT_CUDA_VERSION=13 ORT_DYLIB_PATH=/onnxruntime-linux-x64-gpu-1.26.0/lib/libonnxruntime.so
ENTRYPOINT ["embed"]

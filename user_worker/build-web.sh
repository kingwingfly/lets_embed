#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_DIR="${SCRIPT_DIR}/web"
OUT_DIR="${SCRIPT_DIR}/assets/pkg"
TARGET_DIR="${CARGO_TARGET_DIR:-${WEB_DIR}/target}"

mkdir -p "${OUT_DIR}"

cargo build \
  --manifest-path "${WEB_DIR}/Cargo.toml" \
  --target wasm32-unknown-unknown \
  --release \
  --target-dir "${TARGET_DIR}" \
  "$@"

wasm-bindgen \
  --target web \
  --no-typescript \
  --out-dir "${OUT_DIR}" \
  --out-name user_worker_web \
  "${TARGET_DIR}/wasm32-unknown-unknown/release/user_worker_web.wasm"

echo "Built user_worker SPA bundle into ${OUT_DIR}"

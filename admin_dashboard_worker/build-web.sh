#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WEB_DIR="${SCRIPT_DIR}/web"
OUT_DIR="${SCRIPT_DIR}/assets/pkg"
TARGET_DIR="${CARGO_TARGET_DIR:-${SCRIPT_DIR}/../target}"

mkdir -p "${OUT_DIR}"

echo "[build-web] Building admin_web (Leptos CSR wasm32-unknown-unknown)..."
CARGO_TARGET_DIR="${TARGET_DIR}" cargo build \
  --manifest-path "${WEB_DIR}/Cargo.toml" \
  --target wasm32-unknown-unknown \
  --profile wasm-release

WASM_PATH="${TARGET_DIR}/wasm32-unknown-unknown/wasm-release/admin_web.wasm"

echo "[build-web] Running wasm-bindgen -> ${OUT_DIR}..."
wasm-bindgen \
  --target web \
  --no-typescript \
  --remove-name-section \
  --remove-producers-section \
  --out-dir "${OUT_DIR}" \
  --out-name admin_web \
  "${WASM_PATH}"

echo "[build-web] Done: $(ls -lh "${OUT_DIR}")"

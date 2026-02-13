#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root"

echo "== Toolchain =="
rustc --version || true
cargo --version || true

echo "== Cargo metadata =="
if ! cargo metadata --format-version 1 --no-deps >/tmp/precursor-cargo-metadata.json 2>/tmp/precursor-cargo-metadata.err; then
  cat /tmp/precursor-cargo-metadata.err
  echo "cargo metadata failed. Toolchain likely too old for this lockfile."
  exit 2
fi

echo "== rustfmt =="
cargo fmt --all --check

echo "== tests =="
cargo test --workspace

echo "== done =="

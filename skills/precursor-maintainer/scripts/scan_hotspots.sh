#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root"

echo "== Panic/unwrap/TODO hotspots =="
rg -n --no-heading "NOT IMPLEMENTED|TODO|panic!|unwrap\\(|expect\\(" src README.md RELEASE-CHECKLIST.md || true

echo
echo "== Rust file sizes =="
wc -l src/main.rs src/precursor/*.rs | sort -n

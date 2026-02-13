#!/usr/bin/env bash
set -euo pipefail

cargo_toml="${1:-Cargo.toml}"

current_version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$cargo_toml" | head -n1)"
if [ -z "$current_version" ]; then
  echo "unable to read package version from $cargo_toml" >&2
  exit 1
fi

IFS='.' read -r major minor patch <<EOF_VERSION
$current_version
EOF_VERSION

if [ -z "${major:-}" ] || [ -z "${minor:-}" ] || [ -z "${patch:-}" ]; then
  echo "version '$current_version' is not semver-like (x.y.z)" >&2
  exit 1
fi

new_patch=$((patch + 1))
new_version="${major}.${minor}.${new_patch}"

tmp_file="$(mktemp)"
awk -v new_version="$new_version" '
  BEGIN { replaced = 0 }
  /^version = "/ && replaced == 0 {
    print "version = \"" new_version "\""
    replaced = 1
    next
  }
  { print }
' "$cargo_toml" > "$tmp_file"
mv "$tmp_file" "$cargo_toml"

echo "$new_version"

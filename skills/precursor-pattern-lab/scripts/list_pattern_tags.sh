#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <pattern-file> [pattern-file ...]" >&2
  exit 1
fi

for pattern_file in "$@"; do
  if [ ! -f "$pattern_file" ]; then
    echo "error: file not found: $pattern_file" >&2
    exit 1
  fi
done

rg -o '\(\?<[^>]+>' "$@" \
  | sed -E 's/^\(\?<([^>]+)>$/\1/' \
  | sort -u

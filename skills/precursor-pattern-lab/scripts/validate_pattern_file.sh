#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <pattern-file>" >&2
  exit 1
fi

pattern_file="$1"
if [ ! -f "$pattern_file" ]; then
  echo "error: file not found: $pattern_file" >&2
  exit 1
fi

line_no=0
valid_lines=0
errors=0
declare -A seen

while IFS= read -r raw_line || [ -n "$raw_line" ]; do
  line_no=$((line_no + 1))
  line="$(printf '%s' "$raw_line" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"

  if [ -z "$line" ] || [[ "$line" =~ ^# ]]; then
    continue
  fi

  if ! printf '%s' "$line" | rg -q '\(\?<[^>]+>'; then
    echo "error:$line_no: missing named capture group: $line" >&2
    errors=$((errors + 1))
    continue
  fi

  while IFS= read -r cap; do
    [ -z "$cap" ] && continue
    if [ -n "${seen[$cap]:-}" ]; then
      echo "warn:$line_no: duplicate capture name '$cap' (first seen on line ${seen[$cap]})" >&2
    else
      seen[$cap]="$line_no"
    fi
  done < <(printf '%s' "$line" | rg -o '\(\?<[^>]+>' | sed -E 's/^\(\?<([^>]+)>$/\1/')

  valid_lines=$((valid_lines + 1))
done < "$pattern_file"

if [ "$errors" -gt 0 ]; then
  echo "validation failed: $errors error(s), $valid_lines valid rule line(s)" >&2
  exit 2
fi

echo "validation passed: $valid_lines valid rule line(s), ${#seen[@]} unique capture name(s)"

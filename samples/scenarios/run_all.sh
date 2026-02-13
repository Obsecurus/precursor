#!/usr/bin/env bash

set -euo pipefail

bin_path="${1:-precursor}"
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "== pre-protocol packet triage (lzjd) =="
"$bin_path" \
  -p "$root_dir/pre-protocol-packet-triage/patterns.pcre" \
  -m base64 \
  -t -d \
  --similarity-mode lzjd \
  -P \
  --protocol-hints \
  < "$root_dir/pre-protocol-packet-triage/payloads.b64"

echo
echo "== firmware fragment triage (lzjd) =="
"$bin_path" \
  -p "$root_dir/firmware-fragment-triage/patterns.pcre" \
  -m hex \
  -t \
  --similarity-mode lzjd \
  -P \
  < "$root_dir/firmware-fragment-triage/payloads.hex"

echo
echo "== ics modbus single-packet (lzjd) =="
"$bin_path" \
  -p "$root_dir/ics-modbus-single-packet/patterns.pcre" \
  -m hex \
  -t -d \
  --similarity-mode lzjd \
  -P \
  --protocol-hints \
  < "$root_dir/ics-modbus-single-packet/payloads.hex"

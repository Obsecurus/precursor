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
echo "== raw-binary blob triage (short flag -B) =="
printf '\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00' \
  | "$bin_path" '(?<elf_magic>^\x7fELF)' -B -t --similarity-mode lzjd -P

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

echo
echo "== log4shell pcap-derived exploit probe triage (lzjd) =="
"$bin_path" \
  -p "$root_dir/public-log4shell-pcap-derived/patterns.pcre" \
  -m string \
  -t -d \
  --similarity-mode lzjd \
  -P \
  --protocol-hints \
  < "$root_dir/public-log4shell-pcap-derived/payloads.string"

echo
echo "== sigma linux shell keyword triage (lzjd) =="
"$bin_path" \
  --sigma-rule "$root_dir/sigma-linux-shell-command-triage/sigma_rule.yml" \
  -m string \
  -t -d \
  --similarity-mode lzjd \
  --protocol-hints \
  < "$root_dir/sigma-linux-shell-command-triage/payloads.log"

echo
echo "== fox-it log4shell pcap replay triage (fbhash) =="
"$bin_path" \
  -p "$root_dir/public-log4shell-foxit-pcap/patterns.pcre" \
  -m string \
  -t -d \
  --similarity-mode fbhash \
  -P \
  --protocol-hints \
  < "$root_dir/public-log4shell-foxit-pcap/payloads.string"

echo
echo "== public firmware blob triage (binary folder mode) =="
"$bin_path" \
  -p "$root_dir/public-firmware-binwalk-magic/patterns.pcre" \
  -f "$root_dir/public-firmware-binwalk-magic/blobs" \
  --input-mode binary \
  -t -d \
  --similarity-mode lzjd \
  -P \
  --protocol-hints

echo
echo "== public zeek dns log triage (lzjd + json extract) =="
"$bin_path" \
  -p "$root_dir/public-zeek-dns-log-triage/patterns.pcre" \
  -m string \
  -j '.query' \
  -t -d \
  --similarity-mode lzjd \
  --protocol-hints \
  < "$root_dir/public-zeek-dns-log-triage/payloads.jsonl"

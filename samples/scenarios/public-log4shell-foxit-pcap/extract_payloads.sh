#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pcap_path="${1:-$root_dir/ldap-uri-params-ev0.pcap}"

if ! command -v tshark >/dev/null 2>&1; then
  echo "tshark is required to regenerate payloads.string from the PCAP" >&2
  exit 1
fi

tshark -r "$pcap_path" \
  -Y 'http.request' \
  -T fields \
  -e http.request.method \
  -e http.request.uri \
  -e http.user_agent \
  | awk -F '\t' 'NF >= 2 { method=$1; uri=$2; ua=$3; if (ua == "") ua="unknown"; printf "%s %s HTTP/1.1 Host: extracted.local User-Agent: %s\n", method, uri, ua }'

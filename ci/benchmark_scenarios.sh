#!/usr/bin/env bash

set -euo pipefail

bin_path="${1:-./target/release/precursor}"
output_path="${2:-benchmarks/latest.md}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repeat_factor="${PRECURSOR_BENCH_REPEAT:-200}"

if [ ! -x "$bin_path" ]; then
  echo "missing executable precursor binary: $bin_path" >&2
  exit 1
fi

mkdir -p "$(dirname "$output_path")"

run_case() {
  local case_name="$1"
  local pattern_file="$2"
  local input_mode="$3"
  local input_file="$4"
  local similarity_mode="$5"
  local extra_flags="${6:-}"
  local run_input="$input_file"

  local stdout_file
  local stderr_file
  stdout_file="$(mktemp)"
  stderr_file="$(mktemp)"
  local expanded_input
  expanded_input="$(mktemp)"

  if [ "$repeat_factor" -gt 1 ]; then
    : > "$expanded_input"
    for _ in $(seq 1 "$repeat_factor"); do
      cat "$input_file" >> "$expanded_input"
      printf '\n' >> "$expanded_input"
    done
    run_input="$expanded_input"
  fi

  # shellcheck disable=SC2086
  "$bin_path" -p "$pattern_file" -m "$input_mode" -t -d --similarity-mode "$similarity_mode" -s $extra_flags \
    < "$run_input" > "$stdout_file" 2> "$stderr_file"

  local reports
  reports="$(wc -l < "$stdout_file" | tr -d ' ')"
  local total_matches
  total_matches="$(rg -o '"TotalMatches": [0-9]+' "$stderr_file" | head -n1 | sed -E 's/.*: ([0-9]+)/\1/' || true)"
  local duration
  duration="$(rg -o '"DurationSeconds": "[^"]+"' "$stderr_file" | head -n1 | sed -E 's/.*"([0-9.]+)".*/\1/' || true)"

  if [ -z "$total_matches" ]; then
    total_matches="0"
  fi
  if [ -z "$duration" ]; then
    duration="n/a"
  fi

  printf '| %s | %s | %s | %s | %s |\n' \
    "$case_name" "$similarity_mode" "$reports" "$total_matches" "$duration"

  rm -f "$stdout_file" "$stderr_file" "$expanded_input"
}

{
  echo "# Scenario Benchmark Snapshot"
  echo
  echo "Date: $(date -u '+%Y-%m-%d %H:%M:%SZ')"
  echo "Binary: \`$bin_path\`"
  echo "Repeat factor: \`$repeat_factor\`"
  echo
  echo '| Case | Similarity | Reports | Matches | DurationSeconds |'
  echo '| --- | --- | ---: | ---: | ---: |'
  run_case \
    "Pre-protocol packet triage" \
    "$repo_root/samples/scenarios/pre-protocol-packet-triage/patterns.pcre" \
    "base64" \
    "$repo_root/samples/scenarios/pre-protocol-packet-triage/payloads.b64" \
    "tlsh"
  run_case \
    "Pre-protocol packet triage" \
    "$repo_root/samples/scenarios/pre-protocol-packet-triage/patterns.pcre" \
    "base64" \
    "$repo_root/samples/scenarios/pre-protocol-packet-triage/payloads.b64" \
    "lzjd"
  run_case \
    "Firmware fragment triage" \
    "$repo_root/samples/scenarios/firmware-fragment-triage/patterns.pcre" \
    "hex" \
    "$repo_root/samples/scenarios/firmware-fragment-triage/payloads.hex" \
    "lzjd"
  run_case \
    "ICS Modbus single-packet" \
    "$repo_root/samples/scenarios/ics-modbus-single-packet/patterns.pcre" \
    "hex" \
    "$repo_root/samples/scenarios/ics-modbus-single-packet/payloads.hex" \
    "lzjd" \
    "-P"
} > "$output_path"

if [ "${PRECURSOR_BENCH_INCLUDE_MRSHV2:-0}" = "1" ]; then
  {
    echo
    echo "## Optional MRSHv2"
    echo
    echo '| Case | Similarity | Reports | Matches | DurationSeconds |'
    echo '| --- | --- | ---: | ---: | ---: |'
    run_case \
      "Pre-protocol packet triage" \
      "$repo_root/samples/scenarios/pre-protocol-packet-triage/patterns.pcre" \
      "base64" \
      "$repo_root/samples/scenarios/pre-protocol-packet-triage/payloads.b64" \
      "mrshv2"
  } >> "$output_path"
fi

echo "wrote benchmark snapshot to $output_path"

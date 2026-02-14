# Precursor Memory

Last updated: February 13, 2026

## Product Snapshot
- Language: Rust
- Binary: `precursor` (`src/main.rs`)
- Core purpose: tag payloads with PCRE2 named-capture patterns, optionally compute similarity hashes (TLSH/LZJD/FBHash/feature-gated MRSHv2) and pairwise distances, emit JSON records to STDOUT and optional run stats to STDERR.

## Repository Map
- `src/main.rs`: CLI, ingest loop, matching pipeline, TLSH diff stage, stats/report output.
- `src/precursor/similarity.rs`: similarity backend selector and backend-agnostic hash/diff dispatch.
- `src/precursor/fbhash.rs`: in-tree FBHash-inspired chunk-vector similarity backend.
- `src/precursor/lzjd.rs`: in-tree LZJD-style hashing backend for pairwise similarity mode.
- `src/precursor/mrshv2.rs`: feature-gated MRSHv2 native adapter bindings and hash/diff wrapper.
- `src/precursor/util.rs`: payload decoding, regex builder, pattern file loader, utility functions and unit tests.
- `src/precursor/tlsh.rs`: TLSH wrapper enums/builders and hash/diff logic.
- `samples/scenarios/`: versioned packet/firmware/ICS corpus and scenario runner script.
- `site/`: GitHub Pages static demo content for `precursor.hashdb.io`.
- `patterns/`: rule packs and pattern definitions.
- `ci/` and `.github/workflows/`: multi-target build/release workflow.

## Execution Model
1. Parse args and read patterns from `-p` file or positional pattern.
2. Compile regexes once before processing input lines.
3. Read stdin lines (parallel) or files from `-f` directory.
4. Decode payload (`base64`/`string`/`hex`/`binary`) and optionally extract from JSON path.
5. Apply PCRE2 rules and collect matching capture names as tags.
6. For matched payloads, optionally compute selected similarity hashes and optional pairwise diffs.
7. Emit per-payload JSON to STDOUT and optional stats JSON to STDERR.

## Known Constraints
- Line-oriented stdin/file mode still expects text line boundaries; use `-z` or `-B` for arbitrary binary streams.
- Pairwise similarity diff is O(n^2) by number of matched payload hashes.

## Recently Landed Improvements
- Pattern regex compilation moved out of per-line hot path.
- File input now increments input counters consistently.
- Stats path handles empty vectors and zero-duration runs safely.
- Payload decoding and JSON extraction failures are now recoverable per-line errors.
- TLSH diffing/report output now handle incompatible hash types, lock poisoning, and output serialization failures without panicking.
- Similarity backend support now includes:
  - `tlsh` (existing)
  - `lzjd` (implemented)
  - `mrshv2` (implemented behind `similarity-mrshv2` + native adapter ABI)
  - `fbhash` (implemented in-tree for stream-friendly pairwise diffing)
- Protocol-hint export (`--protocol-hints`) now emits LLM-oriented candidate clusters to `stderr`.
- Single-packet protocol inference mode was added:
  - `--single-packet`
  - `--abstain-threshold`
  - `--protocol-top-k`
  - output fields: `protocol_label`, `protocol_confidence`, `protocol_abstained`, `protocol_candidates`
- Inference confidence can now be cluster-boosted from similarity neighbor counts when `--single-packet` and `--tlsh-diff` are both enabled.
- Blob mode is now implemented with `--input-blob` for one-record ingestion from stdin/file streams.
- Blob mode now decodes `base64`/`hex` directly from bytes without UTF-8 wrapper constraints.
- Raw-binary mode added via `--input-mode binary` and `-B/--input-binary`.
- Sigma ingest added via `--sigma-rule <PATH>` with condition gating support.
- Ingestion now handles file/line errors without panic in runtime paths.
- CLI integration tests now validate:
  - single-packet protocol fields
  - protocol-hint stderr JSON
  - multiline blob matching
- Scenario integration tests now validate:
  - pre-protocol packet corpus behavior
  - firmware-fragment inference behavior
  - ICS Modbus hint emission
  - public Log4Shell PCAP-derived probe behavior
  - Sigma shell-command rule behavior
  - public Zeek DNS log extraction behavior
  - fox-it Log4Shell PCAP replay extraction behavior
  - public binwalk firmware blob tag behavior
- README was rewritten to match actual CLI behavior and project positioning.
- Release checklist now reflects Precursor's actual release process.
- CI/CD now includes Dependabot plus auto patch-version bump and auto-tag workflows for dependency-driven releases.
- CI now includes MRSHv2 feature smoke coverage with a compiled mock native adapter.
- Benchmark harness and baseline snapshot added:
  - `ci/benchmark_scenarios.sh`
  - `benchmarks/baseline-2026-02-13.md`

## Current Priorities
1. Expand realistic payload corpora and broaden integration fixture coverage.
2. Extend inference for binary stream/firmware-first workflows (file magic, container formats, stream framing).
3. Evaluate optional regex acceleration backends (Hyperscan/Vectorscan/DPDK regexdev).
4. Evaluate library/CLI split (`src/lib.rs`) for embeddability.
5. Reduce stats-related overhead when `--stats` is disabled.

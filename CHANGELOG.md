0.2.3 - 2026-02-14
===================

## Fixed
- Cargo publish pipeline now succeeds on crates.io category validation:
  - replaced unsupported category slug `datascience` with `science` in `Cargo.toml`.
- Release reruns for the same tag are now safe:
  - `gh release upload` now uses clobber mode in both archive upload jobs.
- `publish-crates` crates.io API checks now include required request headers to avoid 403 responses.

0.2.2 - 2026-02-14
===================

## Added
- New GitHub Pages demo UX:
  - dark visual theme and improved stakeholder-facing narrative
  - interactive scenario explorer with command/output/stats/insights tabs
  - analyst refinement loop visualization driven by captured `--stats` snapshots
  - codex-guided LLM demo with measured step-4 validation output
- New site branding assets:
  - `site/precursor-mark.svg`
  - `site/favicon.svg`
  - refreshed README/site logo in `assets/logo/precursor-logo.svg`
- Demo data provenance docs:
  - `site/data/README.md`

## Changed
- README header and project positioning now align with packet/log/binary pre-protocol triage workflows.
- Pages content now links directly to scenario corpora and captured demo artifacts for reproducibility.

## Notes
- Local Claude CLI demo output is not bundled in this release snapshot because the local CLI auth state was unauthenticated during capture; runtime status is documented in `site/data/llm_claude_status.json`.

0.2.1 - 2026-02-14
===================

## Added
- Raw-binary ingestion mode:
  - `-B, --input-binary`
  - `--input-mode binary`
- Sigma keyword rule ingest:
  - `--sigma-rule <PATH>`
  - converts Sigma detection selectors into named-capture PCRE patterns.
  - applies Sigma `condition` expressions before emitting records.
- Regex-engine scaffold:
  - `--regex-engine pcre2|vectorscan`
  - `vectorscan` mode emits compatibility diagnostics and uses the current PCRE2 execution path.
- Public corpus scenarios:
  - Log4Shell PCAP-derived probe triage
  - fox-it Log4Shell PCAP replay triage
  - public binwalk firmware-blob triage
  - Sigma Linux shell suspicious-command triage
  - public Zeek DNS log triage
- FBHash backend implementation:
  - `--similarity-mode fbhash`
  - in-tree FBHash-inspired chunk-vector hash + pairwise diff path
- Strategy docs:
  - `SIGMA_INTEGRATION.md`
  - `HARDWARE_ACCELERATION.md`
  - `SIMILARITY_BACKENDS.md`
  - `STATS.md`

## Changed
- Blob-mode decoding for `base64` and `hex` now operates directly on bytes (no UTF-8 wrapper prerequisite).
- Scenario runner and GitHub Pages demo now include binary mode, Sigma ingest, and public corpus workflows.
- README and roadmap were updated for release-readiness and feature clarity.

## Fixed
- Added regression coverage for binary blob ingestion from stdin and input folders.
- Added regression coverage for `--stats` schema and backend-mode reporting.
- Added contract test for deterministic PCAP replay extraction script output.

## Known limitations
- Sigma ingest currently targets the `detection` selector space and does not yet implement full Sigma pipeline/backend transforms.
- FBHash currently uses an in-tree stream-friendly approximation and does not yet run a separate corpus-wide IDF indexing stage.
- MRSHv2 depends on a native adapter library when `similarity-mrshv2` is enabled.

0.2.0 - 2026-02-13
===================

## Added
- LZJD similarity backend support:
  - `--similarity-mode lzjd`
  - backend-agnostic `similarity_hash` output remains stable
- Feature-gated MRSHv2 native adapter backend:
  - `--similarity-mode mrshv2`
  - compile with `--features similarity-mrshv2`
  - link native adapter via `PRECURSOR_MRSHV2_LIB_DIR`/`PRECURSOR_MRSHV2_LIB_NAME`
- Single-packet protocol inference mode for matched payloads:
  - `-P, --single-packet`
  - `-A, --abstain-threshold <0.0-1.0>`
  - `-k, --protocol-top-k <N>`
- New per-record inference fields:
  - `protocol_label`
  - `protocol_confidence`
  - `protocol_abstained`
  - `protocol_candidates`
- Optional blob ingestion mode:
  - `-z, --input-blob` processes each file/stdin stream as a single payload record.
- Integration tests for CLI output contract:
  - protocol inference fields
  - protocol hint JSON emission
  - multiline blob matching behavior
- Scenario corpus and scenario integration coverage:
  - `samples/scenarios/` (packet triage, firmware fragments, ICS Modbus)
  - `tests/scenario_corpus_contract.rs`
- Scenario benchmark harness and baseline snapshot:
  - `ci/benchmark_scenarios.sh`
  - `benchmarks/baseline-2026-02-13.md`
- GitHub Pages site for demos:
  - `site/`
  - `.github/workflows/pages.yml`
- Repository roadmap: `ROADMAP.md`

## Changed
- Protocol hints now include inference context fields (`protocol_label`, `protocol_confidence`, `protocol_abstained`) when present.
- README and architecture diagram were updated to reflect current CLI behavior and data flow.
- Release workflow now exports tag version through a step output to avoid empty downstream version values.
- Release workflow now generates shell completions and man page once and includes them in release archives.

## Fixed
- Replaced panic-prone file ingestion `expect(...)` paths with recoverable error handling.

## Known limitations
- FBHash backend was scaffolded in 0.2.0 and implemented in 0.2.1.
- MRSHv2 depends on a native adapter library when `similarity-mrshv2` is enabled.

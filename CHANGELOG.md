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
- Blob mode supports raw bytes in `string` mode, and UTF-8 encoded `base64`/`hex` wrappers for encoded modes.
- FBHash backend mode remains scaffolded.
- MRSHv2 depends on a native adapter library when `similarity-mrshv2` is enabled.

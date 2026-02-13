# Repository Review

Date: February 13, 2026

## Resolved In This Iteration
- Empty-input stats panic path was hardened in `src/main.rs` (safe avg/p95 handling and zero-duration guards).
- Ingestion paths now handle malformed JSON/base64/hex without process abort in `src/main.rs` and `src/precursor/util.rs`.
- Regexes are now compiled once before line processing in `src/main.rs`.
- File-mode input counting now increments `Input.Count` in `src/main.rs`.
- TLSH/reporting paths now avoid panic on incompatible hash types, poisoned locks, and report serialization/flush failures in `src/main.rs` and `src/precursor/tlsh.rs`.
- Similarity backend plumbing (`--similarity-mode`) plus implemented `lzjd` mode and protocol hint export (`--protocol-hints`) were added in `src/main.rs`, `src/precursor/similarity.rs`, and `src/precursor/lzjd.rs`.
- MRSHv2 feature-gated native adapter backend was added in `src/precursor/mrshv2.rs` with build/CI integration in `build.rs`, `ci/build_mrshv2_mock.sh`, and `.github/workflows/ci.yml`.
- Scenario corpus + regression tests were added in `samples/scenarios/` and `tests/scenario_corpus_contract.rs`.
- Benchmark harness and baseline snapshot were added in `ci/benchmark_scenarios.sh` and `benchmarks/baseline-2026-02-13.md`.
- Static GitHub Pages demo site and deployment workflow were added in `site/` and `.github/workflows/pages.yml`.
- README drift was corrected in `README.md` and aligned with implemented flags.
- Release checklist was rewritten for actual `precursor` release flow in `RELEASE-CHECKLIST.md`.
- Automated dependency release plumbing was added via `.github/dependabot.yml`, `.github/workflows/auto-bump-version.yml`, and `.github/workflows/auto-tag-release.yml`.

## Medium
- `src/main.rs` still allocates and updates stats-tracking structures even when `--stats` is off; this adds avoidable hot-path overhead.
- Default `--input-mode base64` can surprise users on plain text streams when `-m string` is not explicitly provided.

## Low
- MRSHv2 currently relies on adapter ABI compatibility; production adapter validation against upstream MRSHv2 corpus still needs follow-up.

## Verification Note
- `cargo test --workspace` passes in this workspace.

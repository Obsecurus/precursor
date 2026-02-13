# Roadmap

Last updated: February 13, 2026

## Release focus: `0.2.x`

## Guiding priorities
- Keep Precursor fast and scriptable for payload triage.
- Improve protocol discovery workflows without hard protocol dependencies.
- Preserve stable JSON output fields for downstream tooling.

## Near-term milestones

### 1) Binary/blob depth improvements
Status: `in progress`
- Expand blob mode beyond UTF-8 wrappers for `base64`/`hex`.
- Add explicit raw-binary mode semantics for firmware and packet stream chunks.
- Added corpus fixtures for binary-like and mixed-encoding payloads in `samples/scenarios/`.

### 2) Similarity backend expansion
Status: `in progress`
- Implemented `lzjd` backend behind `--similarity-mode lzjd`.
- Implemented `mrshv2` backend path behind `--similarity-mode mrshv2` with feature gate + native adapter ABI (`similarity-mrshv2`).
- Prototype `fbhash` backend behind `--similarity-mode fbhash`.
- Keep output contract backend-agnostic via `similarity_hash`.

### 3) Inference quality hardening
Status: `in progress`
- Add more protocol-family heuristics for single-packet inference.
- Add ambiguity/abstention tests to reduce false confidence.
- Added regression corpus coverage for packet/firmware/ICS scenarios.

## Mid-term milestones

### 4) Library/CLI separation
Status: `planned`
- Introduce `src/lib.rs` for reusable pipeline components.
- Keep CLI as thin orchestration layer.
- Add integration tests that cover both library and CLI entry points.

### 5) Performance and scaling
Status: `in progress`
- Reduce overhead when `--stats` is disabled.
- Added scenario benchmark harness (`ci/benchmark_scenarios.sh`) and baseline snapshot.
- Improve large-cluster comparison ergonomics around O(n^2) diff behavior.

## Release criteria for `0.3.0`
- `lzjd` production-hardening completed (corpus validation + benchmark baseline).
- `mrshv2` native adapter path validated on CI and documented for production adapter wiring.
- Blob mode supports raw binary stream workflows beyond UTF-8 wrappers.
- Integration corpus expanded with realistic packet/firmware samples.
- Stable JSON schema documented with examples for all major modes.

## Backlog candidates
- Optional match-mask support before similarity hashing.
- Richer protocol hint output tuned for human + LLM triage loops.
- Packaging improvements for downstream distro ecosystems.

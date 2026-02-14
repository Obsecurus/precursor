# Roadmap

Last updated: February 14, 2026

## Release focus: `0.2.x`

## Guiding priorities
- Keep Precursor fast and scriptable for payload triage.
- Improve protocol discovery workflows without hard protocol dependencies.
- Preserve stable JSON output fields for downstream tooling.

## Near-term milestones

### 1) Binary/blob depth improvements
Status: `done`
- Blob mode now decodes `base64`/`hex` directly from bytes without UTF-8 wrapper requirements.
- Added explicit raw-binary mode semantics via `--input-mode binary` and `-B/--input-binary`.
- Added regression coverage for raw-binary stdin and folder workflows.

### 2) Similarity backend expansion
Status: `in progress`
- Implemented `lzjd` backend behind `--similarity-mode lzjd`.
- Implemented `mrshv2` backend path behind `--similarity-mode mrshv2` with feature gate + native adapter ABI (`similarity-mrshv2`).
- Implemented in-tree `fbhash` backend behind `--similarity-mode fbhash`.
- Next: evaluate optional corpus-indexed FBHash variant for large offline corpus workflows.
- Keep output contract backend-agnostic via `similarity_hash`.

### 3) Inference quality hardening
Status: `in progress`
- Add more protocol-family heuristics for single-packet inference.
- Add ambiguity/abstention tests to reduce false confidence.
- Added regression corpus coverage for packet/firmware/ICS/public-log scenarios.

### 4) Sigma-native triage workflows
Status: `in progress`
- Added `--sigma-rule` ingestion for Sigma detection selectors into named PCRE captures.
- Added `condition` parsing and gating (`and/or/not`, `N of`, `all of`, selector wildcards).
- Added scenario coverage for Linux shell suspicious-command triage from Sigma rule examples.
- Next: field/modifier parity for more Sigma selectors (`|contains|all`, CIDR modifiers, transforms).

## Mid-term milestones

### 5) Library/CLI separation
Status: `planned`
- Introduce `src/lib.rs` for reusable pipeline components.
- Keep CLI as thin orchestration layer.
- Add integration tests that cover both library and CLI entry points.

### 6) Performance and scaling
Status: `in progress`
- Reduce overhead when `--stats` is disabled.
- Added `--stats` schema regression tests and dedicated `STATS.md` reference docs.
- Added scenario benchmark harness (`ci/benchmark_scenarios.sh`) and baseline snapshot.
- Improve large-cluster comparison ergonomics around O(n^2) diff behavior.
- Evaluate optional regex acceleration engines (Hyperscan/Vectorscan or DPDK regexdev backends) behind feature flags.

## Release criteria for `0.3.0`
- `lzjd` production-hardening completed (corpus validation + benchmark baseline).
- `mrshv2` native adapter path validated on CI and documented for production adapter wiring.
- Blob mode supports raw binary stream workflows beyond UTF-8 wrappers.
- Sigma rule ingestion path validated for condition-driven triage.
- Integration corpus expanded with realistic packet/firmware/public-log samples.
- Stable JSON schema documented with examples for all major modes.

## Backlog candidates
- Optional match-mask support before similarity hashing.
- Richer protocol hint output tuned for human + LLM triage loops.
- Packaging improvements for downstream distro ecosystems.

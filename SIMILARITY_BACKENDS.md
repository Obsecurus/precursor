# Similarity Backend Feasibility

Last updated: February 13, 2026

## Goal

Determine whether Precursor should add MRSHv2 and/or FBHash support, and whether a newer algorithm should be prioritized first.

## Summary Recommendation

1. Keep `lzjd` as the first non-TLSH backend (now implemented in-tree in this repo).
2. Keep MRSHv2 in feature-gated native adapter mode and harden with production adapter coverage.
3. Treat FBHash as optional/experimental unless we commit to corpus-level indexing and TF-IDF state management.

## Evidence Snapshot

### MRSHv2
- Frank Breitinger's tools page still lists `mrsh_v2.0` (last update 2013-10-04), `mrsh_net` (2014-11-12), and `mrsh_cuckoo` (2015-04-10):
  - https://fbreitinger.de/?page_id=218
- A current mirror/development repo exists (`w4term3loon/mrsh`), with release `v1.0.0` dated October 13, 2025 and Apache-2.0 license:
  - https://github.com/w4term3loon/mrsh
  - (discovered via PyPI project linking and release metadata)
- Python bindings (`mrshw`) were released as `1.0.0` on October 13, 2025 and explicitly wrap the MRSH CLI:
  - https://pypi.org/project/mrshw/

### FBHash
- Rust implementation exists with recent release metadata (`0.1.5` latest release June 25, 2025), but low ecosystem traction (very low stars/forks):
  - https://github.com/erwinvaneijk/fbhash
- Repo README content confirms algorithm design is TF-IDF/cosine based over document chunks, which implies corpus-level state rather than simple per-record digesting.

### Recent Forensic Direction
- 2024 temporal Android malware evaluation reports fuzzy hashing remains useful and robust over long horizons (10-year detection rates over 80%), comparing multiple algorithm families:
  - https://doi.org/10.1016/j.fsidi.2024.301770
  - landing/details: https://pure.qub.ac.uk/en/publications/a-temporal-analysis-and-evaluation-of-fuzzy-hashing-algorithms-fo/
- 2025 Windows-system-binary dataset article includes TLSH, ssdeep, sdhash, and LZJD digests, indicating LZJD remains operationally relevant in recent forensic workflows:
  - https://doi.org/10.1016/j.dib.2025.111993
  - PubMed entry: https://pubmed.ncbi.nlm.nih.gov/40955418/
- Rust LZJD implementation is available as a maintained crate entry:
  - https://docs.rs/lzjd/latest/lzjd/

## Engineering Fit vs Current Precursor Pipeline

Precursor currently assumes:
- a per-payload hash representation (`similarity_hash`)
- pairwise diff function for in-memory comparisons

### MRSHv2 fit
- Good fit for file/blob similarity and fragment detection.
- Requires either:
  - C FFI integration, or
  - shelling out to CLI and parsing output (not preferred for production path).
- Complexity: medium-high.

### FBHash fit
- Weaker fit for current architecture because FBHash relies on corpus document-frequency context.
- A correct implementation needs:
  - corpus build stage
  - stored global DF model
  - vector representation per payload
  - cosine similarity, not just digest-distance semantics
- Complexity: high.

### LZJD fit
- Strong fit to current architecture.
- Pure Rust implementation path.
- Can be used for pairwise distance without external native dependencies.
- Complexity: medium.

## Proposed Implementation Plan

## Phase 1 (completed in repo)
- Added `lzjd` backend to `--similarity-mode`.
- Implemented:
  - hash creation from payload bytes
  - pairwise distance scoring
  - report output field continuity (`similarity_hash`, diff maps)
- Added mode-specific unit/integration tests.

## Phase 2 (in progress)
- Added `mrshv2` backend path behind Cargo feature:
  - `similarity-mrshv2`
- Added native C adapter ABI contract:
  - `ffi/mrshv2_adapter.h`
- Added CI smoke validation with a mock native adapter:
  - `ci/build_mrshv2_mock.sh`
  - `.github/workflows/ci.yml` (`mrshv2-ffi-smoke`)
- Remaining work:
  - wire adapter against production MRSHv2 core implementation
  - validate adapter semantics against a real MRSHv2 corpus

## Phase 3 (optional/experimental)
- Add FBHash in a separate mode family that explicitly supports corpus-state workflows:
  - `--similarity-mode fbhash`
  - plus corpus/index path inputs
- Do not force FBHash into the simple "single digest + pairwise diff" model.

## Release Criteria for Backend Expansion

Before enabling non-TLSH mode by default:
- deterministic fixtures for each mode
- runtime and memory benchmarks for line mode and blob mode
- docs that state minimum payload size and failure behavior
- clear provenance and license tracking for any external implementation

## Open Risks

- Supply-chain risk from low-adoption crates/repos: pin versions, verify source, and prefer reproducible builds.
- API-shape mismatch between digest-distance tools and corpus-vector tools.
- Native dependency complexity for MRSHv2 if static linking is required across platforms.

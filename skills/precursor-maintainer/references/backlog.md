# Backlog (Prioritized)

## P0
- Remove panic/unwrap from untrusted input paths and return structured per-line errors.
- Precompile regexes once before line iteration.
- Harden stats calculations for empty input and no-match cases.

## P1
- Introduce integration tests with realistic corpora under `samples/`.
- Fix release checklist drift and ensure release docs reference `precursor` only.
- Separate CLI orchestration from reusable library logic (`src/lib.rs`).

## P2
- Add binary/blob ingest mode and corresponding tests.
- Add tuning mode for TLSH algorithm/distance selection.
- Evaluate memory-efficient similarity indexing for large datasets.

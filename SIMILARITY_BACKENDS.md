# Similarity Backends

Last updated: February 14, 2026

## Current State

Precursor currently supports four similarity modes:

- `tlsh` (default build): mature fuzzy hash mode with minimum payload size constraints.
- `lzjd` (default build): in-tree LZJD-style sketching for stream-friendly pairwise diffing.
- `fbhash` (default build): in-tree FBHash-inspired chunk-vector hashing for pairwise cosine-style distance.
- `mrshv2` (feature-gated): native-adapter integration behind `--features similarity-mrshv2`.

## Practical Guidance

- Use `tlsh` when payloads are long enough and you need compatibility with existing TLSH workflows.
- Use `lzjd` when you need robust behavior across mixed text/binary payloads with no native dependencies.
- Use `fbhash` when chunk-pattern families are important (for example replay traffic variants) and you want an alternative lens to TLSH/LZJD.
- Use `mrshv2` when you already operate MRSHv2 infrastructure and can supply the native adapter library.

## Notes on FBHash Mode

The current `fbhash` mode is an in-tree, operationally focused implementation aligned to Precursor's per-record hash and pairwise diff model.
It does not yet implement full corpus-wide IDF state management as a separate indexing stage.
This keeps runtime ergonomics consistent with existing `-t/-d` workflows.

## MRSHv2 Adapter

`mrshv2` requires:

- build flag: `--features similarity-mrshv2`
- native adapter library linked via:
  - `PRECURSOR_MRSHV2_LIB_DIR`
  - optional `PRECURSOR_MRSHV2_LIB_NAME`

For CI/local smoke tests, use:

```bash
mock_dir="$(mktemp -d)"
ci/build_mrshv2_mock.sh "$mock_dir"
PRECURSOR_MRSHV2_LIB_DIR="$mock_dir" cargo test --workspace --features similarity-mrshv2
```

## Release Expectations

Before changing default recommendations:

- keep deterministic fixtures for each mode in `tests/` and `samples/scenarios/`
- benchmark throughput and memory by mode
- document constraints and failure behavior in `README.md` and `STATS.md`

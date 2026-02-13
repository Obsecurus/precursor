# Quality Gates

## Fast local gates
1. Run `skills/precursor-maintainer/scripts/scan_hotspots.sh`.
2. Run `cargo fmt --all --check`.
3. Run `cargo test --workspace`.

## If Cargo lockfile/toolchain mismatch blocks tests
- Record the exact error.
- Run static checks (`scan_hotspots.sh`) and line-level review.
- Avoid claiming runtime verification succeeded.

## Change-specific checks
- Ingest/decoder changes: test malformed base64, malformed hex, malformed JSON lines.
- Pattern pipeline changes: test empty pattern file, bad pattern syntax, high-volume input.
- TLSH changes: test small payload path (<49 bytes), distance threshold behavior, and `--tlsh-sim-only` output filtering.

# Benchmarks

This folder stores lightweight, reproducible benchmark snapshots based on the
versioned scenario corpus under `samples/scenarios/`.

## Generate a fresh snapshot

```bash
cargo build --release
ci/benchmark_scenarios.sh ./target/release/precursor benchmarks/latest.md
```

## Include optional MRSHv2 mode

Build with the MRSHv2 feature and native adapter first, then:

```bash
PRECURSOR_BENCH_INCLUDE_MRSHV2=1 \
  ci/benchmark_scenarios.sh ./target/release/precursor benchmarks/latest.md
```

## Notes

- These are smoke-level comparative numbers, not full microbenchmarks.
- Use them to detect meaningful regressions between commits/releases.

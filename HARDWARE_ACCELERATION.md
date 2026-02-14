# Regex Acceleration and Offload

Last updated: February 14, 2026

## Goal

Increase pattern matching throughput for high-volume payload streams while keeping
Precursor output semantics unchanged.

## Practical options

### 1) CPU SIMD acceleration (recommended first)

- **Hyperscan** / **Vectorscan** provide high-throughput regex matching.
- Best fit as an optional prefilter or alternate regex engine for compatible patterns.
- Important caveat: these engines intentionally do not support full PCRE syntax
  (for example, backreferences and some advanced constructs).

### 2) NIC/DPU/GPU-style regex offload (longer-term)

- DPDK `rte_regexdev` provides an abstraction for hardware regex acceleration devices.
- This path is feasible but requires device-specific integration and deployment complexity.
- Some historic offload products have uncertain lifecycle; validate long-term vendor support
  before committing production architecture.

## Suggested implementation plan

1. Add a regex engine abstraction in code (`pcre2` default, accelerated engine optional).
   - Implemented scaffold: `--regex-engine pcre2|vectorscan`.
   - Current `vectorscan` mode emits compatibility diagnostics and executes through PCRE2 fallback path.
2. Start with a safe compatibility subset:
   - compile simple/wildcard/Sigma-generated patterns into accelerated engine
   - fallback to PCRE2 for unsupported patterns
3. Add CI benchmarks that compare:
   - `pcre2` baseline
   - accelerated mode
   - mixed compatibility fallback mode
4. Expose engine selection in CLI:
   - `--regex-engine pcre2|vectorscan`

## Fit with Precursor

This aligns well with pre-protocol triage workloads:

- broad, high-recall pattern sets
- high packet/log volume
- need for deterministic JSON output contracts

Similarity hashing and protocol inference stages can remain unchanged while regex
front-end throughput is improved.

## References

- Hyperscan developer reference (PCRE subset and unsupported constructs):
  - https://intel.github.io/hyperscan/dev-reference/compilation.html
- Vectorscan project README (portable Hyperscan fork and architecture support):
  - https://github.com/VectorCamp/vectorscan
- DPDK regex device API (hardware regex abstraction layer):
  - https://doc.dpdk.org/guides/prog_guide/regexdev.html
- NVIDIA BlueField DOCA RegEx lifecycle discussion:
  - https://forums.developer.nvidia.com/t/bluefield-and-regex-support/303845

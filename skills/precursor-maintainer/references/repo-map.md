# Repo Map

## Runtime pipeline
- `src/main.rs`: orchestrates CLI parsing, ingest loops, match execution, TLSH diff, and output.
- `src/precursor/util.rs`: helpers for decoding payloads, reading pattern files, regex builder, and utility tests.
- `src/precursor/tlsh.rs`: TLSH abstraction over algorithm families and error struct.

## Patterns and examples
- `patterns/definitions`: shared named-pattern definitions.
- `patterns/*`: specialized rule packs (`fortinet`, `ics`, `suspicious`, etc.).
- `samples/`: intended for corpus data (currently almost empty).

## Release and CI
- `.github/workflows/ci.yml`: multi-platform build, test, fmt, docs checks.
- `.github/workflows/release.yml`: release artifact build and upload.
- `RELEASE-CHECKLIST.md`: needs cleanup from ripgrep leftovers.

## Documentation memory
- `ai/MEMORY.md`: stable project memory.
- `ai/PROMPT_STRATEGY.md`: recommended prompting patterns.
- `ai/REPO_REVIEW.md`: current risk register.

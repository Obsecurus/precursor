---
name: precursor-maintainer
description: Maintain and evolve the precursor Rust CLI for PCRE2/TLSH labeling and similarity workflows. Use when working in this repository on bug fixes, refactors, performance tuning, CI/release hygiene, CLI or JSON behavior changes, architecture reviews, or reliability hardening.
---

# Precursor Maintainer

## Quick Start
1. Read `ai/MEMORY.md` for current architecture and priorities.
2. Read `ai/REPO_REVIEW.md` for known risks before editing hot paths.
3. Load only relevant source files (`src/main.rs`, `src/precursor/*.rs`, workflow files) for the task.

## Workflow

### 1) Scope the change
- Confirm the user-visible behavior that must stay stable.
- Identify whether the task affects ingest, matching, TLSH comparison, stats, or release/CI.
- Prefer the smallest patch that resolves the target issue.

### 2) Baseline quickly
- Run `scripts/scan_hotspots.sh` to surface panic/unwrap/TODO hotspots.
- Run `scripts/run_checks.sh` when toolchain supports it.
- If checks cannot run, capture the blocking reason in the final report.

### 3) Implement safely
- Keep JSON shape stable unless a breaking change is requested.
- Replace panic paths on untrusted input with recoverable error handling.
- Avoid introducing per-line allocations or regex recompilation in hot loops.

### 4) Validate
- Re-run focused checks for touched behavior.
- Re-run `scripts/scan_hotspots.sh` if touching ingest or matching code.
- Update docs when CLI flags, output shape, or release flow changes.

### 5) Persist memory
- Update `ai/MEMORY.md` for architectural or process changes.
- Update `ai/REPO_REVIEW.md` when risks are fixed or new ones are discovered.

## References
- Use `references/repo-map.md` for file ownership and module boundaries.
- Use `references/quality-gates.md` for preferred verification sequence.
- Use `references/backlog.md` for prioritized roadmap candidates.

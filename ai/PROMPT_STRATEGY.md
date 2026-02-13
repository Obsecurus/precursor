# Prompt Strategy

## Objective
Drive faster, safer iteration on `precursor` by using narrow prompts with explicit acceptance checks.

## Default Agent Loop
1. Load only required context: `ai/MEMORY.md` plus target files.
2. Restate goal and non-goals in one short paragraph.
3. Propose smallest safe change plan.
4. Implement.
5. Run verification commands.
6. Report findings, risks, and follow-up options.

## Prompt Templates

### 1) Bug Fix Prompt
Use when behavior is wrong or unstable.

```text
Use $precursor-maintainer.
Goal: Fix <bug> in <file/path>.
Constraints: Keep CLI/output backward compatible; avoid broad refactors.
Validate with: <commands>.
Done when: <observable behavior>.
```

### 2) Performance Prompt
Use when latency/throughput is the main concern.

```text
Use $precursor-maintainer.
Goal: Improve <hot path> throughput.
Scope: only <files/modules>.
Measure: before/after using <dataset/metric>.
Guardrails: no correctness regressions; keep JSON schema stable.
```

### 3) Pattern Engineering Prompt
Use when creating or tuning pattern packs.

```text
Use $precursor-pattern-lab.
Goal: Detect/tag <behavior family>.
Inputs: <pattern file>, <positive samples>, <negative samples>.
Quality target: maximize precision, keep recall acceptable.
Deliver: updated pattern file + validation output + known limitations.
```

### 4) Architecture Prompt
Use when planning larger changes.

```text
Use $precursor-maintainer.
Task: Propose a staged plan for <capability>.
Include: migration steps, risk list, test strategy, and rollback point.
Avoid: changing public CLI semantics in phase 1.
```

### 5) Protocol Inference Prompt
Use when tuning `--single-packet` behavior.

```text
Use $precursor-maintainer.
Goal: Improve single-packet inference for <protocol family / payload type>.
Inputs: <sample payload set>, current `--abstain-threshold`, current patterns.
Deliver:
- heuristic changes with rationale,
- expected label/confidence shifts,
- tests for positive + ambiguous payloads.
Guardrails: keep existing JSON fields stable (`protocol_*` schema).
```

### 6) Scenario Regression Prompt
Use when validating changes against versioned corpus fixtures.

```text
Goal: Validate <change> against scenario corpus.
Run:
- cargo test --workspace
- cargo test --workspace --test scenario_corpus_contract
- ci/benchmark_scenarios.sh ./target/release/precursor benchmarks/latest.md
Check:
- JSON output contract unchanged
- no confidence regressions on firmware/ICS packet examples
- benchmark deltas called out with rationale
```

### 7) MRSHv2 Adapter Prompt
Use when changing native adapter compatibility.

```text
Goal: Keep MRSHv2 feature build stable and testable.
Build:
- mock_dir="$(mktemp -d)"
- ci/build_mrshv2_mock.sh "$mock_dir"
- PRECURSOR_MRSHV2_LIB_DIR="$mock_dir" LD_LIBRARY_PATH="$mock_dir:${LD_LIBRARY_PATH:-}" cargo test --workspace --features similarity-mrshv2
Done when:
- similarity hashes emit `mrshv2:` prefix in CLI tests
- CI path remains green for mrshv2-ffi-smoke
```

## Prompt Hygiene Rules
- Provide explicit file paths and expected outputs.
- Ask for one deployable step at a time when uncertainty is high.
- Demand line-referenced findings for reviews.
- Require a verification section in every response.

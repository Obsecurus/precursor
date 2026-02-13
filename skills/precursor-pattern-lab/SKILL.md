---
name: precursor-pattern-lab
description: Design, tune, and validate PCRE2 named-capture rule packs for precursor. Use when creating new detection tags, reducing false positives, reorganizing pattern files, or validating pattern quality before merging.
---

# Precursor Pattern Lab

## Quick Start
1. Load target rule file(s) under `patterns/`.
2. Read `references/pattern-authoring.md` for naming and quality conventions.
3. Run `scripts/validate_pattern_file.sh <pattern-file>` before proposing changes.

## Workflow

### 1) Define detection intent
- State what behavior is being tagged.
- Define expected true positives and likely false positives.
- Choose input encoding assumptions (`base64`, `string`, `hex`).

### 2) Author or revise patterns
- Use named capture groups because tag extraction uses capture names.
- Keep each line focused on one logical detection purpose.
- Prefer precise anchors and context constraints over broad `.*` greed.

### 3) Perform static validation
- Run `scripts/validate_pattern_file.sh` on modified files.
- Run `scripts/list_pattern_tags.sh` to inspect resulting tag inventory.
- Resolve malformed lines before runtime testing.

### 4) Evaluate on corpus
- Use positive and negative samples as described in `references/test-corpus-guidance.md`.
- Track precision problems and adjust pattern specificity first.
- Document known blind spots explicitly in the change summary.

### 5) Deliver merge-ready output
- Include updated pattern files.
- Include validation command outputs.
- Call out migration or naming impacts if tags were renamed.

## References
- Use `references/pattern-authoring.md` for capture naming and regex practices.
- Use `references/test-corpus-guidance.md` for repeatable eval setup.

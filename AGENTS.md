# AGENTS.md

## Mission
Keep `precursor` reliable and fast as a PCRE2 + TLSH CLI for payload labeling and similarity analysis.

## Project Memory
Read these files first when starting new work:
- `ai/MEMORY.md`
- `ai/PROMPT_STRATEGY.md`
- `ai/REPO_REVIEW.md`
- `ai/LLM_DISCOVERY_LOOP.md`

## Repo-Local Skills
- `precursor-maintainer`: Maintain and evolve the Rust CLI, CI, and release workflow. (file: `skills/precursor-maintainer/SKILL.md`)
- `precursor-pattern-lab`: Design and validate PCRE2 pattern packs and tagging rules. (file: `skills/precursor-pattern-lab/SKILL.md`)

## Working Rules
- Preserve output compatibility unless a breaking change is explicitly requested.
- Prefer returning structured errors over panics in ingestion and matching paths.
- Keep pattern rules centered on named capture groups; tags come from capture names.
- Update `ai/MEMORY.md` and `ai/REPO_REVIEW.md` when major behavior changes land.

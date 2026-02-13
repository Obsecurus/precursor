# Pattern Authoring Guide

## Tag naming
- Name captures in lowercase snake_case.
- Treat capture names as public tag IDs.
- Rename tags only when necessary; call out breaking changes.

## Pattern construction
- Use explicit boundaries where possible.
- Minimize broad `.*` prefixes/suffixes unless unavoidable.
- Keep per-line complexity reasonable to avoid catastrophic backtracking.
- Prefer one intent per rule line.

## Safety checks
- Ensure each non-empty rule line has at least one named capture group.
- Keep comments in separate lines if needed.
- Validate syntax before runtime execution.

## Practical tuning
- Start with high precision, then relax for recall if needed.
- Maintain a negative corpus to guard against regressions.
- Track additions/removals of tags with `list_pattern_tags.sh`.

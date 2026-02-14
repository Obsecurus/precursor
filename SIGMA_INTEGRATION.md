# Sigma Integration Notes

Last updated: February 14, 2026

## What is implemented now

Precursor can now ingest Sigma YAML detection selectors with:

- `--sigma-rule <PATH>`: load one or more Sigma rule files.
- Selector values under `detection` are converted to named PCRE captures.
- Sigma `condition` expressions are parsed and enforced before records are emitted.
- Basic field modifiers are mapped:
  - `|contains`
  - `|startswith`
  - `|endswith`
  - `|re`

Generated capture names are emitted in `tags` as:
- `sigma_<rule-id>_<selector>_<index>`
- `sigma_<rule-id>_<selector>_<field>_<index>` for nested field selections.

Rule-level fields are emitted when a Sigma rule condition passes:
- `sigma_rule_matches`
- `sigma_rule_ids`

## Current limits

- No support yet for Sigma pipelines, backend mappings, or field normalization layers.
- `condition` support currently covers selector references, `and/or/not`, and `N of` / `all of` forms.
- No support yet for advanced modifier combinations such as `|contains|all`, CIDR operators, and value transforms.

## Why this still matters

For payload/log triage, Sigma keyword selectors already provide high-signal pivots.
This is especially useful for:

- shell command telemetry
- pre-parser packet or payload strings
- rapid rule prototyping before full SIEM translation

## Next feature increments

1. Add explicit field extraction mapping (for JSON inputs, e.g. `.CommandLine`).
2. Add support for `|contains|all`, CIDR, and encoding modifiers.
3. Emit Sigma metadata (`title`, `id`, `level`) into report fields.
4. Add parity tests against a larger subset of SigmaHQ rules.

## References

- Sigma Linux suspicious shell commands rule:
  - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/builtin/lnx_shell_susp_commands.yml
- Sigma specification repository:
  - https://github.com/SigmaHQ/sigma-specification

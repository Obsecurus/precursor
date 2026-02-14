# Site Data Provenance

This folder contains captured output used by `site/app.js` for interactive demos on `precursor.hashdb.io`.

## Scenario captures

- `packet_triage.ndjson` + `packet_triage.stderr`
- `firmware_triage.ndjson` + `firmware_triage.stderr`
- `sigma_triage.ndjson` + `sigma_triage.stderr`
- `log4shell_triage.ndjson` + `log4shell_triage.stderr`

These are generated from versioned corpora in `samples/scenarios/`.

## Analyst loop captures

- `loop_step1.stderr`
- `loop_step2.stderr`
- `loop_step3.stderr`
- `loop_step4_codex.stderr`

Each file includes `--stats` JSON. Steps 3 and 4 also include protocol hint candidate JSON.

Step 4 validates an additional encoded-JNDI tag proposed from a local Codex CLI run.

## LLM demo artifacts

- `llm_demo_prompt.txt`: prompt payload used for local LLM run.
- `llm_codex_demo.json`: JSON output returned by local Codex CLI for the demo prompt.
- `llm_claude_status.json`: local Claude CLI auth status at capture time.

## Notes

- On this machine, the globally installed `precursor` command is older than the branch features; advanced demo captures were validated with `cargo run -- ...` from this repository.
- Keep this folder small and deterministic. Remove transient files before commit.

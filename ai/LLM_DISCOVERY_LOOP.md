# LLM Discovery Loop (Scaffold)

## Goal
Use Precursor's pre-protocol similarity clustering to bootstrap protocol awareness and rule discovery.

## Current hooks
- Similarity backend selector: `--similarity-mode <tlsh|lzjd|mrshv2|fbhash>`
- Hint export for LLM input: `--protocol-hints --protocol-hints-limit <N>`
- Single-packet protocol inference: `--single-packet --abstain-threshold <F> --protocol-top-k <N>`

## Suggested loop
1. Start with versioned corpora in `samples/scenarios/`, then run on raw payload streams with high-recall pattern gates.
2. Enable similarity diffing, hint export, and packet inference:
   - `-t -d --single-packet --protocol-hints --protocol-hints-limit 50`
3. Feed the protocol hint JSON to an LLM prompt that asks for:
   - candidate protocol families
   - likely field boundaries / delimiters
   - discriminating regex capture ideas
4. Also feed `protocol_candidates` from payload output to let the model compare top heuristic hypotheses vs cluster context.
5. Convert model output into proposed named-capture patterns.
6. Validate those patterns against positive/negative corpora.
7. Repeat until precision/recall targets are met.

## Prompt seed
```text
You are analyzing pre-protocol payload clusters.
Given this Precursor protocol hint JSON:
- propose likely protocol/message families,
- infer stable token/field structures,
- draft named-capture regexes for high-signal tags,
- list confidence and ambiguity for each proposal.
```

## Notes
- `tlsh` and `lzjd` are implemented in default builds.
- `mrshv2` is implemented behind `similarity-mrshv2` and native adapter linking.
- `fbhash` remains scaffolded.
- With `--tlsh-diff`, inference confidence can be boosted by similarity neighbor count.
- Keep generated regex tags stable and snake_case to preserve downstream compatibility.
- MRSHv2 mode requires a feature build plus native adapter linkage:
  - `--features similarity-mrshv2`
  - `PRECURSOR_MRSHV2_LIB_DIR=<path>`

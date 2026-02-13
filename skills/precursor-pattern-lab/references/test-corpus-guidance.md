# Test Corpus Guidance

## Corpus layout suggestion
- `samples/positive/<family>.txt`: lines expected to match at least one target tag.
- `samples/negative/<family>.txt`: lines expected to avoid those tags.
- Keep samples representative of production payload formats.

## Evaluation loop
1. Validate syntax and named captures.
2. Run tag inventory and verify expected names appear.
3. Execute runtime checks against positive/negative sets.
4. Record false positives/false negatives and iterate.

## Minimum evidence for pattern changes
- At least one positive sample per new tag.
- At least one negative sample that is close-but-should-not-match.
- Command transcript in PR notes for reproducibility.

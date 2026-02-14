# Stats Output Guide

`precursor --stats` emits a run summary JSON object to `stderr`.
This is designed for automation and dashboards while keeping payload records on `stdout`.

## Quick Example

```bash
cat payloads.b64 \
  | precursor -p patterns/new -m base64 -t -d --similarity-mode lzjd --stats \
  1>/tmp/records.ndjson 2>/tmp/stats.json
```

Inspect:

```bash
jq '.' /tmp/stats.json
```

## Top-Level Schema

- `---PRECURSOR_STATISTICS---`: marker string.
- `Input`: input volume and size metrics.
- `Match`: pattern and hash generation metrics.
- `Compare`: distance summary when enough pairwise comparisons exist.
- `Environment`: run-time settings snapshot.

## Field Notes

### `Input`

- `Count`: total payload candidates processed.
- `Unique`: unique payloads by `xxh3_64_sum`.
- `AvgSize`, `MinSize`, `MaxSize`, `P95Size`, `TotalSize`: size distribution.

### `Match`

- `Patterns`: number of compiled pattern expressions.
- `TotalMatches`: total named-capture hits.
- `Matches`: per-tag hit counts.
- `HashesGenerated`: similarity hashes generated for matched payloads.
- Size fields summarize only matched payloads.

### `Compare`

- `Similarities`, `AvgDistance`, `MinDistance`, `MaxDistance`, `P95Distance`.
- May be `null`/empty when insufficient pairwise distances are available.
  - Practical rule: provide at least 3 matched payloads to reliably populate this section.

### `Environment`

- Includes version and run-time selections:
  - `SimilarityMode`
  - `RegexEngine`
  - `InputMode`
  - `HashFunction`
  - `DistanceThreshold`
  - protocol inference options and Sigma count.

## Compatibility Notes

- Historical field names such as `tlsh_similarities` in record output remain for compatibility, even when running `lzjd` or `fbhash`.
- `HashFunction` reflects TLSH algorithm selection argument and is retained for compatibility; non-TLSH modes still report the selected similarity mode explicitly via `SimilarityMode`.

## Useful Queries

Total input and throughput:

```bash
jq '{count: .Input.Count, total: .Input.TotalSize, rate: .Environment.ProcessingRate}' /tmp/stats.json
```

Most frequent tags:

```bash
jq '.Match.Matches | sort_by(.Matches) | reverse | .[:10]' /tmp/stats.json
```

Distance snapshot:

```bash
jq '.Compare' /tmp/stats.json
```

# Scenario Corpus

This corpus is intentionally small and deterministic so it can be versioned,
tested, and benchmarked directly in this repository.

## Scenarios

1. `pre-protocol-packet-triage`
Purpose: cluster single packets before full parser selection.
Data:
- `payloads.b64`: mixed HTTP/TLS/SSH/DNS/Modbus payloads
- `patterns.pcre`: named-capture tags for cross-protocol triage

2. `firmware-fragment-triage`
Purpose: classify likely firmware or compressed fragments from arbitrary blobs.
Data:
- `payloads.hex`: ELF/PE/uImage/gzip-like fragments + one opaque sample
- `patterns.pcre`: file-magic style tags

3. `ics-modbus-single-packet`
Purpose: tag and cluster Modbus/TCP request/response messages from single packets.
Data:
- `payloads.hex`: short Modbus/TCP frames
- `patterns.pcre`: function code and exception tags

## Provenance

Samples are either:
- protocol-shape examples derived from public standards and protocol docs, or
- synthetic test vectors assembled to exercise Precursor behavior.

Reference docs used when assembling payload shapes:
- RFC 9112 (HTTP/1.1 messaging)
- RFC 4253 (SSH transport)
- RFC 8446 (TLS 1.3 record framing)
- RFC 1035 (DNS message format)
- Modbus Application Protocol Specification v1.1b3

## Quick run

```bash
samples/scenarios/run_all.sh ./target/release/precursor
```

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

4. `public-log4shell-pcap-derived`
Purpose: cluster evasive JNDI/LDAP exploit probes from a public PCAP corpus.
Data:
- `payloads.string`: line-oriented HTTP request samples with published Log4Shell obfuscation variants
- `patterns.pcre`: HTTP + JNDI + obfuscation tags
- `PROVENANCE.md`: source links and extraction notes

5. `sigma-linux-shell-command-triage`
Purpose: triage Linux shell command streams using Sigma rule semantics directly.
Data:
- `sigma_rule.yml`: Sigma keyword rule derived from `lnx_shell_susp_commands.yml`
- `payloads.log`: shell command examples to validate keyword captures and clustering
- `PROVENANCE.md`: source links

6. `public-zeek-dns-log-triage`
Purpose: classify DNS query telemetry from public Zeek JSON logs.
Data:
- `payloads.jsonl`: Zeek DNS events (public seed + schema-consistent local expansion)
- `patterns.pcre`: domain/c2-style indicator tags
- `PROVENANCE.md`: source links

7. `public-log4shell-foxit-pcap`
Purpose: triage a real public Log4Shell PCAP replay stream extracted from HTTP requests.
Data:
- `ldap-uri-params-ev0.pcap`: original public PCAP
- `extract_payloads.sh`: deterministic HTTP request extraction
- `payloads.string`: extracted replay lines for direct Precursor runs
- `patterns.pcre`: HTTP + JNDI + class-dropper tags
- `PROVENANCE.md`: source links and extraction notes

8. `public-firmware-binwalk-magic`
Purpose: tag real firmware/filesystem blob samples in binary folder mode.
Data:
- `blobs/*.bin`: gzip/romfs/squashfs/cramfs public samples
- `patterns.pcre`: file-magic tags for binary triage
- `PROVENANCE.md`: source links

## Provenance

Samples are either:
- protocol-shape examples derived from public standards and protocol docs, or
- synthetic test vectors assembled to exercise Precursor behavior, or
- public corpus-derived extracts with per-scenario provenance files.

Reference docs used when assembling payload shapes:
- RFC 9112 (HTTP/1.1 messaging)
- RFC 4253 (SSH transport)
- RFC 8446 (TLS 1.3 record framing)
- RFC 1035 (DNS message format)
- Modbus Application Protocol Specification v1.1b3
- SigmaHQ Linux shell suspicious command rule
- fox-it/log4shell-pcaps payload corpus
- public Zeek DNS log samples
- fox-it/log4shell-pcaps PCAP replay sample
- ReFirmLabs/binwalk test input vectors

## Quick run

```bash
samples/scenarios/run_all.sh ./target/release/precursor
```

## Optional tooling for regeneration

- `tshark` is required to regenerate `public-log4shell-foxit-pcap/payloads.string` from the bundled PCAP via `extract_payloads.sh`.
- Core scenario runs do not require `tshark`; only regeneration workflows do.

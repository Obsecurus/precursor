# Provenance

These payload shapes are taken from the publicly documented obfuscation examples in:
- https://github.com/fox-it/log4shell-pcaps

The source repository includes URI-encoded Log4Shell exploit probe variants and associated
public PCAP files (`log4j_payloads.pcap`, `log4j_payloads_2.pcap`).

This scenario stores line-oriented HTTP request strings using those published payload variants
so Precursor can run deterministic local tests without downloading large binary artifacts.

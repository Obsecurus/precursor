# Provenance: public-log4shell-foxit-pcap

## Source

- Corpus: fox-it/log4shell-pcaps
- PCAP file: `log4shell-ldap-pcaps/ldap-uri-params-ev0.pcap`
- Upstream URL: https://github.com/fox-it/log4shell-pcaps
- Raw file URL used: https://raw.githubusercontent.com/fox-it/log4shell-pcaps/main/log4shell-ldap-pcaps/ldap-uri-params-ev0.pcap

## Notes

- `payloads.string` is deterministically regenerated from HTTP request records in the PCAP via `extract_payloads.sh`.
- Extraction keeps method, URI, and user-agent fields to preserve exploit-shape context.
- This scenario intentionally demonstrates pre-parser payload triage from packet captures.

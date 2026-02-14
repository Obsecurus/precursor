# Provenance: public-firmware-binwalk-magic

## Source

- Corpus: ReFirmLabs/binwalk test input vectors
- Upstream URL: https://github.com/ReFirmLabs/binwalk
- Raw file URLs used:
  - https://raw.githubusercontent.com/ReFirmLabs/binwalk/master/tests/inputs/gzip.bin
  - https://raw.githubusercontent.com/ReFirmLabs/binwalk/master/tests/inputs/romfs.bin
  - https://raw.githubusercontent.com/ReFirmLabs/binwalk/master/tests/inputs/squashfs.bin
  - https://raw.githubusercontent.com/ReFirmLabs/binwalk/master/tests/inputs/cramfs.bin

## Notes

- These are small, real filesystem/container samples used by binwalk tests.
- Scenario runs Precursor in binary folder mode to tag file magic and cluster samples without format-specific parsers.

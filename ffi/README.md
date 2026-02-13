# MRSHv2 Native Adapter ABI

Precursor's optional MRSHv2 mode (`--features similarity-mrshv2`) links against
a native library that exports the ABI defined in `mrshv2_adapter.h`.

## Required symbols

- `precursor_mrshv2_hash`
- `precursor_mrshv2_diff`
- `precursor_mrshv2_free`
- `precursor_mrshv2_last_error`

## Build/test with mock adapter

```bash
mock_dir="$(mktemp -d)"
ci/build_mrshv2_mock.sh "$mock_dir"
PRECURSOR_MRSHV2_LIB_DIR="$mock_dir" LD_LIBRARY_PATH="$mock_dir:${LD_LIBRARY_PATH:-}" \
  cargo test --workspace --features similarity-mrshv2
```

## Production adapter notes

- Keep `precursor_mrshv2_diff` output normalized to `[0,100]` where `0` means identical.
- Return clear thread-local text from `precursor_mrshv2_last_error`.
- Preserve backward compatibility for symbol names and argument types.

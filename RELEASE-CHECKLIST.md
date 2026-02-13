# Release Checklist

## 1) Prepare

- Ensure local `main` is up to date with `origin/main`.
- Confirm `Cargo.toml` version is the intended release version.
- Review dependency updates (`cargo update`) and commit `Cargo.lock` changes if needed.
- Update `CHANGELOG.md` with release notes for this version.

## 2) Validate

- Confirm toolchain pin is available locally: `rustup toolchain install 1.86.0 --profile minimal`.
- Run formatting: `cargo fmt --all --check`.
- Run tests (unit + integration): `cargo test --workspace`.
- Build release binary: `cargo build --release`.
- Verify CLI assets script output: `ci/generate_cli_assets.sh /tmp/precursor-cli-assets ./target/release/precursor`.
- Verify CLI help renders: `./target/release/precursor --help`.
- Smoke test implemented similarity modes:
  - TLSH: `printf 'aGVsbG8=\n' | ./target/release/precursor '(?<h>hello)' -m base64 -t --similarity-mode tlsh`
  - LZJD: `printf 'GET / HTTP/1.1\n' | ./target/release/precursor '(?<g>GET)' -m string -t --similarity-mode lzjd`
- Smoke test MRSHv2 adapter mode:
  - `mock_dir="$(mktemp -d)" && ci/build_mrshv2_mock.sh "$mock_dir"`
  - `PRECURSOR_MRSHV2_LIB_DIR="$mock_dir" LD_LIBRARY_PATH="$mock_dir:${LD_LIBRARY_PATH:-}" cargo test --workspace --features similarity-mrshv2`
- Refresh benchmark snapshot:
  - `ci/benchmark_scenarios.sh ./target/release/precursor benchmarks/latest.md`

## 3) Tag and push

- Commit release prep changes.
- If releasing manually, create and sign tag: `git tag -s <x.y.z> -m "<x.y.z>"`.
- Push branch first, then push tag after CI on branch passes.
- If dependency updates were merged without a version bump:
  - `.github/workflows/auto-bump-version.yml` bumps patch version automatically.
  - `.github/workflows/auto-tag-release.yml` tags the new version automatically.

## 4) CI release

- Confirm GitHub Actions release workflow completed successfully.
- Confirm MRSHv2 feature smoke job passed in CI (`mrshv2-ffi-smoke`).
- Confirm archives/checksums were attached to the GitHub release draft.
- Promote draft release after artifact validation.

## 5) Post-release

- Verify install path(s) (`cargo install precursor` and release binaries).
- Verify GitHub Pages demo site deployment and custom domain (`precursor.hashdb.io`) health.
- Add next `TBD`/unreleased section to `CHANGELOG.md`.
- Announce release with notable changes and known limitations.

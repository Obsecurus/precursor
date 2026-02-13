#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <output-dir>" >&2
  exit 2
fi

out_dir="$1"
mkdir -p "$out_dir"
cc_bin="${CC:-cc}"
src="ffi/mrshv2_mock.c"
lib_base="precursor_mrshv2"

if [ ! -f "$src" ]; then
  echo "missing source file: $src" >&2
  exit 1
fi

case "$(uname -s)" in
  Darwin)
    lib_path="$out_dir/lib${lib_base}.dylib"
    "$cc_bin" -dynamiclib -O2 -fPIC -Iffi "$src" -o "$lib_path"
    ;;
  Linux)
    lib_path="$out_dir/lib${lib_base}.so"
    "$cc_bin" -shared -O2 -fPIC -Iffi "$src" -o "$lib_path"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    lib_path="$out_dir/${lib_base}.dll"
    "$cc_bin" -shared -O2 -Iffi "$src" -o "$lib_path"
    ;;
  *)
    echo "unsupported platform: $(uname -s)" >&2
    exit 1
    ;;
esac

echo "$lib_path"

#!/usr/bin/env bash
set -euo pipefail
tool_dir=$(cd -- "$(dirname -- "$0")" && pwd)
source_dir=${1:?candidate source root required}
build_dir=${2:?build output directory required}
mkdir -p "$build_dir"
yespower_dir="$source_dir/src/crypto/yespower-1.0.1"
cc=${CC:-cc}
common=(-O3 -std=c11 -I"$yespower_dir")
if [[ $(uname -s) == Darwin ]]; then common+=(-mmacosx-version-min=14.0); fi
rename=(-Dyespower=reference_yespower -Dyespower_tls=reference_yespower_tls
  -Dyespower_init_local=reference_yespower_init_local -Dyespower_free_local=reference_yespower_free_local)
# Preserve the recursive source inclusion in the original implementation.
mkdir -p "$build_dir/reference"
cp "$tool_dir/reference-yespower-opt.c" "$build_dir/reference/yespower-opt.c"
"$cc" "${common[@]}" "${rename[@]}" -c "$build_dir/reference/yespower-opt.c" -o "$build_dir/reference.o"
"$cc" "${common[@]}" -c "$yespower_dir/yespower-opt.c" -o "$build_dir/candidate.o"
"$cc" "${common[@]}" -c "$yespower_dir/sha256.c" -o "$build_dir/sha256.o"
"$cc" "${common[@]}" "$tool_dir/yespower-differential.c" "$build_dir/reference.o" "$build_dir/candidate.o" "$build_dir/sha256.o" -o "$build_dir/differential"
"$build_dir/differential" "$tool_dir/headers.txt"

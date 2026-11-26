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
sha_rename=(-DPBKDF2_SHA256=reference_PBKDF2_SHA256)
for prefix in SHA256 HMAC_SHA256; do
  for name in Init Update Final Buf; do
    sha_rename+=("-Dlibcperciva_${prefix}_${name}=reference_${prefix}_${name}")
  done
done
# Preserve the recursive source inclusion in the original implementation.
mkdir -p "$build_dir/reference"
cp "$tool_dir/reference-yespower-opt.c" "$build_dir/reference/yespower-opt.c"
"$cc" "${common[@]}" "${rename[@]}" "${sha_rename[@]}" -c "$build_dir/reference/yespower-opt.c" -o "$build_dir/reference.o"
"$cc" "${common[@]}" -c "$yespower_dir/yespower-opt.c" -o "$build_dir/candidate.o"
"$cc" "${common[@]}" -c "$yespower_dir/sha256.c" -o "$build_dir/sha256.o"
if [[ $(uname -s) == Darwin && $(uname -m) == arm64 ]]; then
  "$cc" "${common[@]}" -dM -E "$yespower_dir/sha256.c" > "$build_dir/sha-macros.txt"
  grep -q "#define YESPOWER_APPLE_SHA2" "$build_dir/sha-macros.txt"
fi
"$cc" "${common[@]}" "${sha_rename[@]}" -c "$tool_dir/reference-sha256.c" -o "$build_dir/reference-sha256.o"
"$cc" "${common[@]}" "$tool_dir/sha256-differential.c" "$build_dir/reference-sha256.o" "$build_dir/sha256.o" -o "$build_dir/check-sha"
"$build_dir/check-sha"
"$cc" "${common[@]}" "$tool_dir/yespower-differential.c" "$build_dir/reference.o" "$build_dir/reference-sha256.o" "$build_dir/candidate.o" "$build_dir/sha256.o" -o "$build_dir/differential"
"$build_dir/differential" "$tool_dir/headers.txt"

#!/usr/bin/env bash
set -euo pipefail

source_root="$1"
output="$2"
probe_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
mkdir -- "$output"
[[ "$(uname -s)" = Darwin && "$(uname -m)" = arm64 ]]
[[ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" != 1 ]]
cc="$(xcrun --sdk macosx --find clang++)"
sdk="$(xcrun --sdk macosx --show-sdk-path)"
[[ "$cc" = /* && -x "$cc" ]]
[[ "$sdk" = /* && -d "$sdk" ]]
[[ -r "$sdk/usr/include/sys/mount.h" ]]
{
    uname -sm
    sw_vers
    "$cc" --version
    xcrun --sdk macosx --show-sdk-version
    sysctl -n hw.memsize
} > "$output/native-environment.txt"
python3 -B "$probe_dir/prepare-headers.py" "$source_root" "$output/include-overlay" \
    > "$output/source-provenance.txt" 2> "$output/preflight.log"
"$cc" -isysroot "$sdk" -arch arm64 -std=c++20 -O2 \
    -I "$output/include-overlay" -I "$source_root/src" "$probe_dir/blockmap-geometry.cpp" \
    -o "$output/blockmap-geometry" > "$output/build.log" 2>&1
[[ "$(xcrun lipo -archs "$output/blockmap-geometry")" = arm64 ]]
shasum -a 256 "$output/blockmap-geometry" > "$output/binary.sha256"
"$output/blockmap-geometry" "$output" > "$output/result.json" 2> "$output/run.log"

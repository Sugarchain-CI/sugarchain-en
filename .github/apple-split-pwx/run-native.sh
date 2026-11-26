#!/usr/bin/env bash
set -euo pipefail
umask 077

tools_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_dir=$(cd -- "${1:?Exact source checkout required}" && pwd)
work=${2:?Fresh Apple proof evidence directory required}

test "$(uname -s)" = Darwin
test "$(uname -m)" = arm64
test "$(sysctl -in sysctl.proc_translated 2>/dev/null || true)" != 1
/usr/sbin/sysctl -n machdep.cpu.brand_string | grep -Eq '^Apple M1( \(Virtual\))?$'
test "$(git -C "$source_dir" rev-parse HEAD)" = 9c502574b652804905d2533d51742ca91f694532
test "$(git -C "$source_dir" rev-parse 'HEAD^{tree}')" = f44aa1b47f9701996046bbb396106f1d5c365e66
test "$(git -C "$source_dir" rev-parse HEAD:src/crypto/yespower-1.0.1)" = 71ad4500c80d458bb32851d12162c23413bf6560
git -C "$source_dir" diff --exit-code HEAD -- src/crypto/yespower-1.0.1 src/primitives/block.h
mkdir "$work"

clang=$(xcrun --find clang)
if ! sdk=$(xcrun --sdk macosx --show-sdk-path) || [[ "$sdk" != /* || ! -d "$sdk" || ! -r "$sdk/usr/include/errno.h" ]]; then
    printf '%s\n' 'The native macOS SDK headers could not be located.' >&2
    exit 1
fi
sdk_version=$(xcrun --sdk macosx --show-sdk-version)
flags=(-arch arm64 -mcpu=apple-m1 -O3 -flto=thin -DNDEBUG -mmacosx-version-min=14.0 -isysroot "$sdk")
build_flags=()
for value in "${flags[@]}"; do
    build_flags+=("--cflag=$value")
done
{
    sw_vers
    /usr/sbin/sysctl machdep.cpu.brand_string hw.logicalcpu hw.memsize hw.pagesize
    "$clang" --version
    printf 'macOS SDK path: %s\nmacOS SDK version: %s\n' "$sdk" "$sdk_version"
    git -C "$source_dir" rev-parse HEAD 'HEAD^{tree}'
    printf 'Native probe flags: %s\n' "${flags[*]}"
    shasum -a 256 "$tools_dir/../apple-paired-proof/headers-3072.bin"
} > "$work/environment.txt"
"$clang" "${flags[@]}" -dM -E -x c /dev/null > "$work/compiler-macros.txt"
grep -Fx '#define __ARM_FEATURE_SHA2 1' "$work/compiler-macros.txt"
grep -Fx '#define __aarch64__ 1' "$work/compiler-macros.txt"
grep -Fx '#define __APPLE__ 1' "$work/compiler-macros.txt"
"$clang" "${flags[@]}" -### -x c /dev/null > "$work/compiler-target.txt" 2>&1

python3 -B "$tools_dir/prepare-build.py" --source "$source_dir" --output "$work/build" --cc "$clang" \
    "${build_flags[@]}" > "$work/build.log" 2>&1
binary="$work/build/split_yespower_probe"
test "$(lipo -archs "$binary")" = arm64
shasum -a 256 "$binary" > "$work/binary.sha256"
xcrun nm -n "$binary" > "$work/symbols.txt"
xcrun otool -tvV "$binary" > "$work/disassembly.txt"
python3 -B "$tools_dir/inspect-native.py" "$work/disassembly.txt" --binary "$binary" \
    --output "$work/native-mixer-evidence.txt"
shape_status=$(python3 -B -c 'import json, sys; print(json.load(open(sys.argv[1]))["status"])' "$work/native-mixer-evidence.txt")
if [[ "$shape_status" == codegen_only ]]; then
    printf '%s\n' 'Native mixer evidence is inconclusive. The disassembly was retained and timing was skipped.'
    exit 0
fi
test "$shape_status" = verified
python3 -B "$tools_dir/../apple-fixed-proof/measure-native.py" --split-pwx --binary "$binary" \
    --shape "$work/native-mixer-evidence.txt" \
    --headers "$tools_dir/../apple-paired-proof/headers-3072.bin" --output "$work/evidence"

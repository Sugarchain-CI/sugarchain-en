#!/usr/bin/env bash
set -euo pipefail
umask 077

tools_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_dir=$(cd -- "${1:?Exact source checkout required}" && pwd)
work=${2:?Fresh Apple proof evidence directory required}

test "$(uname -s)" = Darwin
test "$(uname -m)" = arm64
test "$(sysctl -in sysctl.proc_translated 2>/dev/null || true)" != 1
test "$(git -C "$source_dir" rev-parse HEAD)" = 9c502574b652804905d2533d51742ca91f694532
test "$(git -C "$source_dir" rev-parse 'HEAD^{tree}')" = f44aa1b47f9701996046bbb396106f1d5c365e66
test "$(git -C "$source_dir" rev-parse HEAD:src/crypto/yespower-1.0.1)" = 71ad4500c80d458bb32851d12162c23413bf6560
git -C "$source_dir" diff --exit-code HEAD -- src/crypto/yespower-1.0.1 src/primitives/block.h
mkdir "$work"

clang=$(xcrun --find clang)
flags=(-arch arm64 -mcpu=apple-m1 -O3 -flto=thin -DNDEBUG -mmacosx-version-min=14.0)
build_flags=()
for value in "${flags[@]}"; do
    build_flags+=("--cflag=$value")
done
{
    sw_vers
    /usr/sbin/sysctl machdep.cpu.brand_string hw.logicalcpu hw.memsize hw.pagesize
    "$clang" --version
    xcrun --show-sdk-version
    git -C "$source_dir" rev-parse HEAD 'HEAD^{tree}'
    printf 'Native probe flags: %s\n' "${flags[*]}"
    shasum -a 256 "$tools_dir/headers-3072.bin"
} > "$work/environment.txt"
"$clang" "${flags[@]}" -dM -E -x c /dev/null > "$work/compiler-macros.txt"
grep -Fx '#define __ARM_FEATURE_SHA2 1' "$work/compiler-macros.txt"
grep -Fx '#define __aarch64__ 1' "$work/compiler-macros.txt"
grep -Fx '#define __APPLE__ 1' "$work/compiler-macros.txt"
"$clang" "${flags[@]}" -### -x c /dev/null > "$work/compiler-target.txt" 2>&1

python3 -B "$tools_dir/prepare-build.py" --source "$source_dir" --output "$work/build" --cc "$clang" \
    "${build_flags[@]}" > "$work/build.log" 2>&1
binary="$work/build/paired_yespower_probe"
test "$(lipo -archs "$binary")" = arm64
shasum -a 256 "$binary" > "$work/binary.sha256"
xcrun nm -n "$binary" > "$work/symbols.txt"
grep -E ' [_[:alnum:]]*paired_smix2_rows([._[:alnum:]]*)?$' "$work/symbols.txt" > "$work/pair-core-symbol.txt"
xcrun otool -tvV "$binary" > "$work/disassembly.txt"
python3 -B "$tools_dir/inspect-native-pair.py" "$binary" --disassembly "$work/disassembly.txt" \
    > "$work/pair-core-opcodes.txt"
python3 -B "$tools_dir/measure-native.py" --binary "$binary" --headers "$tools_dir/headers-3072.bin" \
    --output "$work/evidence"

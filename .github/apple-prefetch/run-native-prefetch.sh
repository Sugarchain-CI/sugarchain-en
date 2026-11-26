#!/usr/bin/env bash
set -euo pipefail
umask 077

tool_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_dir=$(cd -- "${1:?Exact candidate source checkout required}" && pwd)
fixture=${2:?Pinned Mainnet header fixture required}
work=${3:?New work directory required}

test "$(uname -s)" = Darwin
test "$(uname -m)" = arm64
test "$(/usr/sbin/sysctl -n sysctl.proc_translated 2>/dev/null || printf 0)" = 0
test "$(git -C "$source_dir" rev-parse HEAD)" = 81934405da9cdfeca55c2a07997b881c22993bc6
git -C "$source_dir" diff --exit-code HEAD -- src/crypto/yespower-1.0.1
mkdir "$work"
mkdir "$work/evidence" "$work/variant-source"
mkdir -p "$work/variant-source/src/crypto"
baseline="$source_dir/src/crypto/yespower-1.0.1"
variant="$work/variant-source/src/crypto/yespower-1.0.1"
cp -R "$baseline" "$variant"
{
    sw_vers
    /usr/sbin/sysctl machdep.cpu.brand_string hw.logicalcpu hw.pagesize hw.cachelinesize
    xcrun clang --version
    git -C "$source_dir" rev-parse HEAD HEAD^{tree}
    shasum -a 256 "$tool_dir/apple-yespower-prefetch.patch" "$fixture"
} > "$work/evidence/environment.txt"
patch -f -p1 -d "$work/variant-source" < "$tool_dir/apple-yespower-prefetch.patch" \
    > "$work/evidence/patch.log" 2>&1

flags=(-arch arm64 -mcpu=apple-m1 -O3 -flto=thin -DNDEBUG -Werror -mmacosx-version-min=14.0)
reference_names=(-Dyespower=reference_yespower -Dyespower_tls=reference_yespower_tls
    -Dyespower_init_local=reference_yespower_init_local -Dyespower_free_local=reference_yespower_free_local)
{
    xcrun clang "${flags[@]}" -### -I"$baseline" -c "$baseline/yespower-opt.c" \
        > "$work/evidence/compiler-target.txt" 2>&1
    xcrun clang "${flags[@]}" -I"$baseline" "$tool_dir/measure-proofs.c" \
        "$baseline/yespower-opt.c" "$baseline/sha256.c" -o "$work/baseline"
    python3 "$tool_dir/check-arm64-opcodes.py" "$work/baseline" baseline \
        > "$work/evidence/baseline-opcodes.json"
    xcrun clang "${flags[@]}" "${reference_names[@]}" -I"$baseline" \
        -c "$baseline/yespower-opt.c" -o "$work/reference.o"
    for distance in 512 1024; do
        option="-DYESPOWER_APPLE_PREFETCH_BLOCKS=$((distance / 64))"
        xcrun clang "${flags[@]}" "$option" -I"$variant" "$tool_dir/measure-proofs.c" \
            "$variant/yespower-opt.c" "$variant/sha256.c" -o "$work/prefetch-$distance"
        xcrun clang "${flags[@]}" "$option" -I"$variant" "$tool_dir/yespower-differential.c" \
            "$work/reference.o" "$variant/yespower-opt.c" "$variant/sha256.c" \
            -o "$work/differential-$distance"
        python3 "$tool_dir/check-arm64-opcodes.py" "$work/prefetch-$distance" prefetch \
            > "$work/evidence/prefetch-$distance-opcodes.json"
    done
} > "$work/evidence/build.log" 2>&1

for distance in 512 1024; do
    "$work/differential-$distance" "$tool_dir/headers.txt" \
        > "$work/evidence/differential-$distance.log" 2>&1
done
python3 "$tool_dir/measure-paired.py" "$fixture" "$work"

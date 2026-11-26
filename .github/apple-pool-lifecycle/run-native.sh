#!/usr/bin/env bash
set -euo pipefail
umask 077

tools_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_dir=$(cd -- "${1:?Exact source checkout required}" && pwd)
work=${2:?Fresh evidence directory required}
mkdir "$work"

{
    test "$(uname -s)" = Darwin
    test "$(uname -m)" = arm64
    test "$(sysctl -in sysctl.proc_translated 2>/dev/null || true)" != 1
    clang=$(xcrun --sdk macosx --find clang++)
    sdk=$(xcrun --sdk macosx --show-sdk-path)
    [[ "$sdk" = /* ]]
    test -d "$sdk"
    test -r "$sdk/usr/include/sys/mman.h"
    compiler_version=$("$clang" --version)
    printf '%s\n' "$compiler_version"
    grep -Eq '^Apple clang version 17\.' <<< "$compiler_version"
    xcrun --sdk macosx --show-sdk-version
    printf 'macOS SDK: %s\n' "$sdk"
    sw_vers
    git -C "$source_dir" rev-parse HEAD 'HEAD^{tree}'
} > "$work/environment.log" 2>&1

python3 -B "$tools_dir/prepare.py" --source "$source_dir" --output "$work/stage" > "$work/stage.log" 2>&1
stage="$work/stage"
common=(-std=c++20 -arch arm64 -isysroot "$sdk" -mmacosx-version-min=14.0 -Wall -Wextra -Werror -I "$stage/src" -I "$source_dir/src")
{
    "$clang" "${common[@]}" -E -P -x c++ "$stage/pool-baseline.h" > "$stage/baseline.ii"
    "$clang" "${common[@]}" -E -P -x c++ "$stage/src/support/allocators/pool.h" > "$stage/macro-off.ii"
    cmp "$stage/baseline.ii" "$stage/macro-off.ii"
    shasum -a 256 "$stage/baseline.ii" "$stage/macro-off.ii"
    printf '%s\n' 'Assertions enabled; macro-off output byte-identical.'
} > "$work/macro-off.log" 2>&1
"$clang" "${common[@]}" -O1 -g -DSUGARCHAIN_FILE_BACKED_POOL_DIAGNOSTIC \
    "$stage/pool-lifecycle.cpp" -o "$stage/pool-lifecycle" > "$work/build.log" 2>&1
{
    test "$(lipo -archs "$stage/pool-lifecycle")" = arm64
    shasum -a 256 "$stage/pool-lifecycle"
} > "$work/binary.log" 2>&1
python3 -B "$tools_dir/run-cases.py" --binary "$stage/pool-lifecycle" --output "$work/cases" \
    > "$work/cases.log" 2>&1

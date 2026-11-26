#!/usr/bin/env bash
set -euo pipefail
umask 077

platform=${1:?Native platform required}
source_dir=${2:?Canonical source directory required}
probe_dir=${3:?Overlay input directory required}
work=${4:?Output directory required}
crypto="$source_dir/src/crypto/yespower-1.0.1"

case "$platform" in
    apple-arm64)
        test "$(uname -s)" = Darwin
        test "$(uname -m)" = arm64
        test "$(/usr/sbin/sysctl -n sysctl.proc_translated 2>/dev/null || printf 0)" = 0
        cc=(xcrun clang)
        cxx=(xcrun clang++)
        flags=(-arch arm64 -mcpu=apple-m1 -O3 -flto=thin -DNDEBUG -mmacosx-version-min=14.0)
        link=(-pthread)
        executable="$work/queue-proofs"
        ;;
    windows-x64)
        test "${MSYSTEM:-}" = UCRT64
        test "$(uname -m)" = x86_64
        test "$(gcc -dumpmachine)" = x86_64-w64-mingw32
        cc=(gcc)
        cxx=(g++)
        flags=(-O2 -DNDEBUG)
        link=(-pthread -static)
        executable="$work/queue-proofs.exe"
        ;;
    *) exit 2 ;;
esac

mkdir -p "$work"
{
    uname -a
    "${cc[@]}" --version
    "${cxx[@]}" --version
    cat "$work/inputs.json"
    printf 'Compiler flags: %s\n' "${flags[*]}"
} > "$work/compiler.txt"

if ! (
    set -x
    "${cc[@]}" "${flags[@]}" -std=gnu11 -I"$crypto" -c "$crypto/yespower-opt.c" -o "$work/yespower.o" &&
    "${cc[@]}" "${flags[@]}" -std=gnu11 -I"$crypto" -c "$crypto/sha256.c" -o "$work/sha256.o" &&
    "${cxx[@]}" "${flags[@]}" -std=c++20 -I"$crypto" -I"$work" "$probe_dir/queue-proofs.cpp" \
        "$work/yespower.o" "$work/sha256.o" "${link[@]}" -o "$executable"
) > "$work/build.log" 2>&1; then
    tail -n 55 "$work/build.log"
    exit 1
fi

if [[ "$platform" = apple-arm64 ]]; then
    python3 "$probe_dir/check-arm64-opcodes.py" "$executable" baseline \
        > "$work/apple-blockmix-opcodes.json"
else
    objdump -f "$executable" > "$work/windows-pe.txt"
    grep -q 'file format pei-x86-64' "$work/windows-pe.txt"
fi

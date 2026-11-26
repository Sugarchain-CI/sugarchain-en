#!/usr/bin/env bash
set -euo pipefail

probe_root=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(git -C "$probe_root" rev-parse --show-toplevel)
output=$1
mkdir -p -- "$output"/{bin,evidence,obj,tmp,reference,abi,pages}
export TMPDIR="$output/tmp"

reference_commit=81934405da9cdfeca55c2a07997b881c22993bc6
git -C "$repo_root" merge-base --is-ancestor "$reference_commit" HEAD
git -C "$repo_root" rev-parse HEAD >"$output/evidence/source-commit.txt"
printf '%s\n' "$reference_commit" >"$output/evidence/reference-commit.txt"
hasher="$repo_root/src/crypto/yespower-1.0.1"
(
    cd -- "$hasher"
    sha256sum --check <<'CHECKSUMS'
0e8a50d495a3588270c196c6aeaab884840b223f89de4e71bd99e453ce3c417c  yespower-opt.c
5233e9888b1f87d57333534cd06aec43f2c43e987ca20c6846732f15d1c0e94c  yespower-platform.c
0a2e19c497788d451fa0faf04b8f5771b7c547df1169d41ef1564a80cfb3ef87  sha256.c
CHECKSUMS
)
for tree in reference abi pages; do
    cp -- "$hasher"/{yespower-opt.c,yespower-platform.c,yespower.h,sha256.c,sha256.h,sha256-dispatch.h,sysendian.h,insecure_memzero.h} "$output/$tree/"
done
cp -- "$probe_root/page-probe-allocator.c" "$output/pages/yespower-platform.c"
cp -- "$probe_root/page-probe.h" "$output/pages/"
python3 - "$output/abi/yespower-opt.c" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text()
functions = (
    ("blockmix", "void"), ("blockmix_xor", "uint32_t"), ("blockmix_xor_save", "uint32_t"),
    ("smix1", "void"), ("smix2", "void"), ("smix", "void"),
)
for name, return_type in functions:
    signature = f"static {return_type} {name}("
    if source.count(signature) != 1:
        raise ValueError(f"Unexpected reference signature {name}")
    source = source.replace(signature, f"static __attribute__((sysv_abi,noinline)) {return_type} {name}(")
path.write_text(source)
PY

compiler=x86_64-w64-mingw32-gcc-posix
cxx=x86_64-w64-mingw32-g++-posix
objdump=x86_64-w64-mingw32-objdump
"$compiler" --version >"$output/evidence/toolchain.txt"
[[ "$("$compiler" -dumpversion)" =~ ^13([.-]|$) ]]
for tree in reference abi pages; do
    defs=()
    if [[ "$tree" == pages ]]; then
        defs=(-DSC_PAGE_PROBE)
    fi
    "$compiler" -std=gnu11 -O2 -DNDEBUG -mno-red-zone -c "$output/$tree/yespower-opt.c" -o "$output/obj/$tree.obj"
    "$objdump" -dr -Mintel "$output/obj/$tree.obj" >"$output/evidence/$tree.asm"
    "$compiler" -std=gnu11 -O2 -DNDEBUG -c "$output/$tree/sha256.c" -o "$output/obj/$tree-sha.obj"
    "$cxx" -std=c++20 -O2 -DNDEBUG -static -pthread -I"$output/$tree" "${defs[@]}" "$probe_root/proof-probe.cpp" \
        "$output/obj/$tree.obj" "$output/obj/$tree-sha.obj" -o "$output/bin/$tree.exe"
    "$objdump" -p "$output/bin/$tree.exe" >"$output/evidence/$tree-pe.txt"
done
(
    cd -- "$output/bin"
    sha256sum -- reference.exe abi.exe pages.exe | tee SHA256SUMS
)

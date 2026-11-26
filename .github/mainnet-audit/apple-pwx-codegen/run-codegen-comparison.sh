#!/usr/bin/env bash
set -euo pipefail
umask 077

tool_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_dir=${1:?En.7 baseline source checkout required}
fixture=${2:?Pinned compressed mainnet blocks required}
work=${3:?New working directory required}
test "$(uname -s)" = Darwin
test "$(uname -m)" = arm64
test "$(/usr/sbin/sysctl -n sysctl.proc_translated 2>/dev/null || printf 0)" = 0
test "$(git -C "$source_dir" rev-parse HEAD)" = 496f41971274712a98f45d1f0d49c796788aaf49
git -C "$source_dir" diff --quiet
mkdir "$work"
mkdir "$work/evidence"
{
  sw_vers
  /usr/sbin/sysctl machdep.cpu.brand_string hw.logicalcpu hw.memsize
  xcrun clang --version
  git -C "$source_dir" rev-parse HEAD HEAD^{tree}
  shasum -a 256 "$tool_dir/prepare-codegen-variants.py"
} > "$work/evidence/environment.txt"
python3 "$tool_dir/prepare-codegen-variants.py" "$source_dir" "$work"

python3 - "$fixture" "$work/headers.bin" <<'PY'
import gzip
import hashlib
import struct
import sys
from pathlib import Path

archive = Path(sys.argv[1]).read_bytes()
assert hashlib.sha256(archive).hexdigest() == "eb0a6130b5a561bed197918face18106711715ba8e0c7862f5ad83b541b3082d"
blocks = gzip.decompress(archive)
assert hashlib.sha256(blocks).hexdigest() == "d3ab941f31aa5d1a6c6781d02d7212cdea95db75bafb054743a4adf3a82563d4"
headers = bytearray()
offset = 0
for _ in range(256):
    assert blocks[offset:offset + 4] == bytes.fromhex("9feb4b9d")
    size = struct.unpack_from('<I', blocks, offset + 4)[0]
    offset += 8
    assert size >= 80 and offset + size <= len(blocks)
    headers += blocks[offset:offset + 80]
    offset += size
Path(sys.argv[2]).write_bytes(headers)
PY

flags=(-O3 -flto=thin -DNDEBUG -Werror -mmacosx-version-min=14.0)
for variant in baseline unzip index combined; do
  crypto="$work/variants/$variant"
  xcrun clang "${flags[@]}" -I"$crypto" "$tool_dir/yespower-timed.c" \
    "$crypto/yespower-opt.c" "$crypto/sha256.c" -o "$work/timed-$variant"
  xcrun clang -O3 -DNDEBUG -Werror -mmacosx-version-min=14.0 -I"$crypto" \
    -S "$crypto/yespower-opt.c" -o "$work/codegen-$variant.s"
done
python3 "$tool_dir/compare-codegen.py" "$work"

rename=(-Dyespower=reference_yespower -Dyespower_tls=reference_yespower_tls
  -Dyespower_init_local=reference_yespower_init_local -Dyespower_free_local=reference_yespower_free_local)
baseline="$work/variants/baseline"
xcrun clang "${flags[@]}" "${rename[@]}" -I"$baseline" -c \
  "$baseline/yespower-opt.c" -o "$work/baseline.o"
for variant in unzip index combined; do
  crypto="$work/variants/$variant"
  xcrun clang "${flags[@]}" -I"$crypto" "$tool_dir/yespower-differential.c" \
    "$work/baseline.o" "$crypto/yespower-opt.c" "$crypto/sha256.c" -o "$work/differential-$variant"
  "$work/differential-$variant" "$tool_dir/headers.txt" | tee "$work/evidence/differential-$variant.log"
done

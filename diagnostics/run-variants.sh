#!/usr/bin/env bash
set -euo pipefail
source_dir=${1:?Exact baseline source checkout}
patch=${2:?Candidate patch}
work=${3:?New work directory}
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
test "$(uname -s)" = Darwin
test "$(uname -m)" = arm64
test "$(sysctl -n sysctl.proc_translated 2>/dev/null || printf 0)" = 0
mkdir -p "$work/evidence" "$work/bin" "$work/variants"
crypto="$source_dir/src/crypto/yespower-1.0.1"
cp -R "$crypto" "$work/variants/scalar"
git -C "$source_dir" apply --include=src/crypto/yespower-1.0.1/yespower-opt.c "$patch"
python3 "$here/prepare-variants.py" "$crypto" "$work/variants"
python3 - "$here/testnet7-fixture.json" "$work/headers.bin" <<'PY'
import hashlib, json, pathlib, sys
p = pathlib.Path(sys.argv[1])
assert hashlib.sha256(p.read_bytes()).hexdigest() == '7ce81c9bafb6d66ae263eb7848cf0db4eebb5f54f52474adc3abbbb49f507f25'
d = json.loads(p.read_text())
assert d['blocks'] == len(d['raw_blocks']) == 102
pathlib.Path(sys.argv[2]).write_bytes(b''.join(bytes.fromhex(block)[:80] for block in d['raw_blocks']))
PY
{
  sw_vers
  uname -sm
  sysctl machdep.cpu.brand_string hw.logicalcpu hw.memsize
  xcrun clang --version
  xcrun clang -### -O3 -c -x c /dev/null
  xcrun clang -### -O3 -target aarch64-apple-darwin -c -x c /dev/null
} > "$work/evidence/host-target.txt" 2>&1
for name in scalar neon cpu-m1 tune-m1 narrow prefetch narrow-prefetch scalar-pwx; do
  variant=$name
  flags=()
  case "$name" in
    cpu-m1) variant=neon; flags+=(-mcpu=apple-m1) ;;
    tune-m1) variant=neon; flags+=(-mtune=apple-m1) ;;
  esac
  crypto="$work/variants/$variant"
  /usr/bin/clang -O3 -DNDEBUG "${flags[@]}" -I "$crypto" "$here/yespower-timed.c" \
    "$crypto/yespower-opt.c" "$crypto/sha256.c" -o "$work/bin/$name"
  /usr/bin/clang -### -O3 "${flags[@]}" -c -x c /dev/null > "$work/evidence/$name-target.txt" 2>&1
  /usr/bin/clang -O3 "${flags[@]}" -I "$crypto" -S "$crypto/yespower-opt.c" -o "$work/evidence/$name.s"
done
python3 "$here/run-variants.py" "$work"

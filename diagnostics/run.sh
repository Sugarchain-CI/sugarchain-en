#!/usr/bin/env bash
set -euo pipefail
source_dir=$1
work=$2
here=$(cd -- "$(dirname -- "$0")" && pwd)
test "$(uname -m)" = arm64
test "$(sysctl -n sysctl.proc_translated 2>/dev/null || printf 0)" = 0
mkdir -p "$work/evidence" "$work/bin" "$work/reference"
crypto="$source_dir/src/crypto/yespower-1.0.1"
cp "$crypto/sha256.c" "$work/reference/sha256.c"
cp "$here/reference-yespower-opt.c" "$work/reference/yespower-opt.c"
cc=/usr/bin/clang
common=(-O3 -std=c11 -mmacosx-version-min=14.0 -I"$crypto")
"$cc" "${common[@]}" "$here/yespower-timed.c" "$crypto/yespower-opt.c" "$crypto/sha256.c" -o "$work/bin/neon"
git -C "$source_dir" apply "$here/../candidate.patch"
"$cc" "${common[@]}" "$here/yespower-timed.c" "$crypto/yespower-opt.c" "$crypto/sha256.c" -o "$work/bin/neon-sha2"
"$cc" "${common[@]}" -dM -E "$crypto/sha256.c" > "$work/evidence/macros.txt"
grep -q '#define YESPOWER_APPLE_SHA2' "$work/evidence/macros.txt"
rename=(-DPBKDF2_SHA256=reference_PBKDF2_SHA256)
for prefix in SHA256 HMAC_SHA256; do
  for name in Init Update Final Buf; do rename+=("-Dlibcperciva_${prefix}_${name}=reference_${prefix}_${name}"); done
done
"$cc" "${common[@]}" "${rename[@]}" -c "$work/reference/sha256.c" -o "$work/reference-sha256.o"
"$cc" "${common[@]}" "${rename[@]}" -Dyespower=reference_yespower -Dyespower_tls=reference_yespower_tls -Dyespower_init_local=reference_yespower_init_local -Dyespower_free_local=reference_yespower_free_local -c "$work/reference/yespower-opt.c" -o "$work/reference-yespower.o"
"$cc" "${common[@]}" -c "$crypto/sha256.c" -o "$work/sha256.o"
"$cc" "${common[@]}" -c "$crypto/yespower-opt.c" -o "$work/yespower.o"
"$cc" "${common[@]}" "$here/sha256-differential.c" "$work/reference-sha256.o" "$work/sha256.o" -o "$work/check-sha"
"$work/check-sha" > "$work/evidence/sha-checks.log"
"$cc" "${common[@]}" "$here/yespower-differential.c" "$work/reference-sha256.o" "$work/reference-yespower.o" "$work/sha256.o" "$work/yespower.o" -o "$work/check-yespower"
python3 "$here/prepare-differential.py" "$here/testnet7-fixture.json" "$work/headers.txt"
"$work/check-yespower" "$work/headers.txt" > "$work/evidence/yespower-checks.log"
python3 - "$here/testnet7-fixture.json" "$work/headers.bin" <<'PY'
import pathlib, json, hashlib, sys
p=pathlib.Path(sys.argv[1]); assert hashlib.sha256(p.read_bytes()).hexdigest()=='7ce81c9bafb6d66ae263eb7848cf0db4eebb5f54f52474adc3abbbb49f507f25'
d=json.loads(p.read_text()); assert len(d['raw_blocks'])==102
pathlib.Path(sys.argv[2]).write_bytes(b''.join(bytes.fromhex(x)[:80] for x in d['raw_blocks']))
PY
python3 "$here/compare.py" "$work"

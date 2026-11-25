#!/usr/bin/env bash
set -euo pipefail
source_dir=${1:?Source checkout}
patch=${2:?Candidate patch}
work=${3:?New work directory}
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
test "$(uname -s)" = Darwin
test "$(uname -m)" = arm64
test "$(sysctl -n sysctl.proc_translated 2>/dev/null || printf 0)" = 0
mkdir -p "$work/evidence"
python3 - "$here/testnet7-fixture.json" "$work/headers.bin" <<'PY'
import hashlib, json, pathlib, sys
p = pathlib.Path(sys.argv[1])
assert hashlib.sha256(p.read_bytes()).hexdigest() == '7ce81c9bafb6d66ae263eb7848cf0db4eebb5f54f52474adc3abbbb49f507f25'
d = json.loads(p.read_text())
assert d['blocks'] == len(d['raw_blocks']) == 102
headers = b''.join(bytes.fromhex(block)[:80] for block in d['raw_blocks'])
assert len(headers) == 8160
pathlib.Path(sys.argv[2]).write_bytes(headers)
PY
{
  sw_vers
  uname -sm
  sysctl machdep.cpu.brand_string hw.logicalcpu hw.memsize
  xcrun clang --version
} > "$work/evidence/host.txt"
for mode in baseline candidate; do
  if [[ "$mode" == candidate ]]; then
    git -C "$source_dir" apply --include=src/crypto/yespower-1.0.1/yespower-opt.c "$patch"
  fi
  crypto="$source_dir/src/crypto/yespower-1.0.1"
  /usr/bin/clang -O3 -DNDEBUG -I "$crypto" "$here/yespower-fixture.c" \
    "$crypto/yespower-opt.c" "$crypto/sha256.c" -o "$work/$mode"
  "$work/$mode" "$work/headers.bin" "$work/evidence/$mode.hashes" > "$work/evidence/$mode.json"
done
cmp "$work/evidence/baseline.hashes" "$work/evidence/candidate.hashes"
python3 - "$work/evidence" <<'PY'
import json, pathlib, statistics, sys
p = pathlib.Path(sys.argv[1])
d = {name: json.loads((p / (name + '.json')).read_text()) for name in ('baseline', 'candidate')}
b, c = (statistics.median(d[name]['seconds']) for name in ('baseline', 'candidate'))
d.update(baseline_median=b, candidate_median=c, speedup=b/c, identical_hashes=True)
(p / 'comparison.json').write_text(json.dumps(d, indent=2) + '\n')
print(f'102 Testnet7 Yespower headers: baseline {b:.6f}s, candidate {c:.6f}s, speedup {b/c:.3f}x; all 102 hashes identical')
PY

import hashlib
import json
import statistics
import subprocess
import sys
from pathlib import Path


work = Path(sys.argv[1])
headers = work / "headers.bin"
output = work / "hashes.bin"
expected_count = 256
samples = {"baseline": [], "paired": []}
reference = None
for trial in range(6):
    order = ("baseline", "paired") if trial % 2 == 0 else ("paired", "baseline")
    for mode in order:
        result = subprocess.run(
            [str(work / f"timed-{mode}"), str(headers), str(output)],
            capture_output=True, text=True, check=True, timeout=20,
        )
        data = json.loads(result.stdout)
        assert data["headers"] == expected_count
        actual = output.read_bytes()
        assert len(actual) == 32 * expected_count
        if reference is None:
            reference = actual
        if actual != reference:
            raise RuntimeError(f"Proof output comparison failed in trial {trial + 1}, {mode}")
        samples[mode].append({"trial": trial + 1, "order": order.index(mode) + 1, **data["samples"][0]})

medians = {
    mode: {kind: statistics.median(sample[kind] for sample in results) for kind in ("wall", "cpu")}
    for mode, results in samples.items()
}
record = {
    "headers": expected_count,
    "headers_sha256": hashlib.sha256(headers.read_bytes()).hexdigest(),
    "identical_proofs_sha256": hashlib.sha256(reference).hexdigest(),
    "samples": samples,
    "medians": medians,
}
(work / "evidence" / "paired-comparison.json").write_text(json.dumps(record, indent=2) + "\n")
for mode, timing in medians.items():
    print(f'{mode}: median wall {timing["wall"]:.6f} s, median CPU {timing["cpu"]:.6f} s')

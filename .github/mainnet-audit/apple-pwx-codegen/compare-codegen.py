"""Compare every variant using eight balanced rounds and fixed mainnet headers."""

import hashlib
import json
from pathlib import Path
import re
import statistics
import subprocess
import sys


work = Path(sys.argv[1])
headers = work / "headers.bin"
output = work / "hashes.bin"
evidence = work / "evidence"
names = ["baseline", "unzip", "index", "combined"]
samples = {name: [] for name in names}
reference = None
for trial in range(8):
    rotation = trial % len(names)
    order = names[rotation:] + names[:rotation]
    if trial >= len(names):
        order.reverse()
    for mode in order:
        result = subprocess.run([str(work / f"timed-{mode}"), str(headers), str(output)],
                                capture_output=True, text=True, check=True, timeout=20)
        data = json.loads(result.stdout)
        assert data["headers"] == 256
        actual = output.read_bytes()
        assert len(actual) == 32 * 256
        if reference is None:
            reference = actual
        if actual != reference:
            raise RuntimeError(f"Proof output comparison failed in trial {trial + 1}, {mode}")
        samples[mode].append({"trial": trial + 1, "position": order.index(mode) + 1, **data["samples"][0]})

medians = {
    mode: {kind: statistics.median(sample[kind] for sample in results) for kind in ("wall", "cpu")}
    for mode, results in samples.items()
}
paired_comparison = {}
codegen = {}
for mode in names:
    improvements = {kind: [(b[kind] - c[kind]) * 100 / b[kind]
                           for b, c in zip(samples["baseline"], samples[mode])]
                    for kind in ("wall", "cpu")}
    paired_comparison[mode] = {
        kind: {"median_reduction_percent": statistics.median(values),
               "faster_pairs": sum(value > 0 for value in values)}
        for kind, values in improvements.items()
    }
    asm = (work / f"codegen-{mode}.s").read_text().split("_blockmix_1_0:", 1)[-1]
    codegen[mode] = {instr: len(re.findall(r"^\s*" + instr + r"[.\s]", asm, re.MULTILINE))
                     for instr in ("ext", "zip1", "zip2", "uzp1", "uzp2", "ubfx", "umlal")}
record = {"headers": 256, "headers_sha256": hashlib.sha256(headers.read_bytes()).hexdigest(),
          "identical_proofs_sha256": hashlib.sha256(reference).hexdigest(), "samples": samples,
          "medians": medians, "paired": paired_comparison, "assembly_opcode_counts": codegen}
(evidence / "codegen-comparison.json").write_text(json.dumps(record, indent=2) + "\n")
for mode, timing in medians.items():
    comparison = paired_comparison[mode]["cpu"]
    print(f'{mode}: median wall {timing["wall"]:.6f} s, median CPU {timing["cpu"]:.6f} s, '
          f'{comparison["median_reduction_percent"]:.2f}% median paired CPU reduction, '
          f'{comparison["faster_pairs"]}/8 faster')

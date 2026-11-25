#!/usr/bin/env python3
"""Run every predeclared variant in rotating order; retain every observation."""
import hashlib
import json
import pathlib
import statistics
import subprocess
import sys

work = pathlib.Path(sys.argv[1])
names = ['scalar', 'neon', 'cpu-m1', 'tune-m1', 'narrow', 'prefetch', 'narrow-prefetch', 'scalar-pwx']
rows = {name: [] for name in names}
reference = None
for repeat in range(5):
    order = names[repeat:] + names[:repeat]
    for name in order:
        hashes = work / 'evidence' / (name + '-' + str(repeat) + '.hashes')
        proc = subprocess.run([str(work / 'bin' / name), str(work / 'headers.bin'), str(hashes)], text=True, capture_output=True, check=True)
        d = json.loads(proc.stdout)
        actual = hashes.read_bytes()
        assert len(actual) == 102 * 32
        if reference is None:
            reference = actual
        assert actual == reference, (name, repeat, 'proof mismatch')
        rows[name].append({'round': repeat, 'order': order.index(name), **d['samples'][0]})
        (work / 'evidence' / 'samples.json').write_text(json.dumps(rows, indent=2) + '\n')
summary = {'samples': rows, 'proof_sha256': hashlib.sha256(reference).hexdigest(), 'all_102_hashes_identical': True,
           'medians': {name: {kind: statistics.median(row[kind] for row in data) for kind in ('wall', 'cpu')} for name, data in rows.items()}}
(work / 'evidence' / 'comparison.json').write_text(json.dumps(summary, indent=2) + '\n')
for name, d in summary['medians'].items():
    print(f'{name}: wall {d["wall"]:.6f}s, process CPU {d["cpu"]:.6f}s')

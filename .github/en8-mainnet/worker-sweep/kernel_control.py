#!/usr/bin/env python3
"""Measure a pinned, previously verified proof kernel on the node test host."""

import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys


EXPECTED = {
    "baseline": "6b89243c4101b8d9f82877c56b6c50512f7bde5be30a1b4ca9ccc6e8d6ceb8df",
    "headers.bin": "b6457be0260ab00479ad4333cdfb387ff38bd0eab2d747c84593ecdc5db8de44",
}
PROOFS = "0cc32fea1ef9ec5a61ef44a17d9ba9720f6ee3554ffa0ee14befaff16091628c"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    root, output = map(Path, sys.argv[1:])
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("The control requires native Apple Silicon")
    for name, expected in EXPECTED.items():
        if sha(root / name) != expected:
            raise RuntimeError(f"Pinned {name} checksum differs")
    binary = root / "baseline"
    binary.chmod(0o700)
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(binary)], check=True)
    proof_file = output.with_suffix(".proofs")
    trial = subprocess.run([str(binary), str(root / "headers.bin"), str(proof_file)],
                           capture_output=True, text=True, check=True, timeout=75)
    result = json.loads(trial.stdout)
    if result["headers"] != 8192 or result["workers"] != 8 or sha(proof_file) != PROOFS:
        raise RuntimeError("Proof count or complete proof output differs")
    result.update(binary_sha256=EXPECTED["baseline"], proof_sha256=PROOFS,
                  role="Same-host micro control; different compiler and entry point from the packaged node")
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Score fixed-order native Yespower prefetch micro trials."""

import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys


ARCHIVE_SHA = "1d6b46da12f732190804a276b0c457d3c0ff923733ba29294f826eea971664ce"
HEADERS_SHA = "f64a65677abdfa525b67d9a09291868fbfd1f9fb0d4089cdfafc3b2718dd07dd"
GENESIS = "7d5eaec2dbb75f99feadfa524c78b7cabc1d8c8204f79d4f3a83381b811b0adc"
COUNT = 8192
MIN_SAVING = 0.08
VARIANTS = ("prefetch-512", "prefetch-1024")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def block_hash(header):
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()


def verify_headers(file):
    archived = file.read_bytes()
    if sha(archived) != ARCHIVE_SHA:
        raise ValueError("Unexpected compressed fixture bytes")
    complete = gzip.decompress(archived)
    if sha(complete) != HEADERS_SHA or len(complete) != 100000 * 80:
        raise ValueError("Unexpected Mainnet header fixture")
    subset = complete[:COUNT * 80]
    previous = bytes.fromhex(GENESIS)[::-1]
    for offset in range(0, len(subset), 80):
        header = subset[offset:offset + 80]
        if header[4:36] != previous:
            raise ValueError("Mainnet fixture link failed")
        previous = block_hash(header)
    return subset


def verify_proofs(headers, proofs):
    if len(proofs) != COUNT * 32:
        raise ValueError("Incorrect proof output length")
    for i in range(COUNT):
        compact = int.from_bytes(headers[i * 80 + 72:i * 80 + 76], "little")
        exponent, mantissa = compact >> 24, compact & 0x007fffff
        if compact & 0x00800000:
            raise ValueError("Negative compact target in fixture")
        shift = 8 * (exponent - 3)
        target = mantissa << shift if shift >= 0 else mantissa >> -shift
        proof = int.from_bytes(proofs[i * 32:i * 32 + 32], "little")
        if not 0 < target < 2**256 or proof > target:
            raise ValueError(f"Proof failed the Mainnet header target at height {i+1}")


def run(fixture, work):
    headers = verify_headers(fixture)
    headers_file = work / "headers.bin"
    headers_file.write_bytes(headers)
    evidence = work / "evidence"
    report = evidence / "paired.json"
    record = {
        "header_count": COUNT, "workers": 8, "fixture_sha256": HEADERS_SHA,
        "tested_prefix_sha256": sha(headers),
        "required_fractional_improvement": MIN_SAVING,
        "program_sha256": {name: sha((work / name).read_bytes()) for name in ("baseline", *VARIANTS)},
        "trials": [], "comparisons": {},
    }
    baseline_proof_sha = None
    for variant in VARIANTS:
        trial_rows = []
        order = ("baseline", variant, variant, "baseline")
        for case, name in enumerate(order, 1):
            stem = f"{variant}-{case}-{name}"
            output = evidence / f"{stem}.proofs"
            row = {"variant": variant, "case": case, "binary": name}
            try:
                result = subprocess.run(
                    [work / name, headers_file, output],
                    capture_output=True, text=True, check=True, timeout=75,
                )
                row.update(json.loads(result.stdout))
                proofs = output.read_bytes()
                verify_proofs(headers, proofs)
                digest = sha(proofs)
                row["proofs_sha256"] = digest
                if baseline_proof_sha is None and name == "baseline":
                    baseline_proof_sha = digest
                if digest != baseline_proof_sha:
                    raise ValueError("Full proof output differs from baseline")
                row["status"] = "pass"
            except (subprocess.SubprocessError, OSError, ValueError) as error:
                row.update(status="fail", error=str(error)[:400])
            trial_rows.append(row)
            record["trials"].append(row)
            report.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
            print(f"{stem} {row['status']} wall={row.get('wall')} cpu={row.get('cpu')}", flush=True)

        if all(row["status"] == "pass" for row in trial_rows):
            comparisons = [
                {metric: 1 - trial_rows[candidate][metric] / trial_rows[baseline][metric]
                 for metric in ("wall", "cpu")}
                for baseline, candidate in ((0, 1), (3, 2))
            ]
            record["comparisons"][variant] = {
                "pairs": comparisons,
                "passes_screen": all(value >= MIN_SAVING for pair in comparisons for value in pair.values()),
            }
        else:
            record["comparisons"][variant] = {"status": "failed_trial"}
        report.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    if any(row["status"] != "pass" for row in record["trials"]):
        raise SystemExit("One or more proof trials failed. The results are retained.")


if __name__ == "__main__":
    run(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())

#!/usr/bin/env python3
"""Compare generic and fixed-parameter full proofs on native Apple ARM64."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import subprocess
import time


HEADERS = 3072
HEADER_SHA = "dc7a666edf2992bc2c3821a8819b93c7008f057eae04d2da36f66c0ef1b87a02"
PROOF_SHA = "ccaef882fe8bcf619cd0137f33ae98cef051593f8569984444a22586def913a2"
WORKERS = (1, 3, 8)
ARMS = ("generic", "fixed")
PAIRS = (ARMS, ARMS[::-1])
METRICS = ("cpu_seconds", "wall_seconds")
COMPUTE_LIMIT = 140


def require(ok, detail):
    if not ok:
        raise ValueError(detail)


def evaluate(trials):
    rows = {(row["workers"], row["round"], row["arm"]): row for row in trials}
    require(len(rows) == len(trials) == 12, "Incomplete or duplicated fixed trial matrix")
    comparisons = []
    for workers in WORKERS:
        maximum = 1.0 if workers == 8 else 0.95
        for round_number in range(1, len(PAIRS) + 1):
            generic = rows[workers, round_number, "generic"]
            fixed = rows[workers, round_number, "fixed"]
            for metric in METRICS:
                comparisons.append({"workers": workers, "round": round_number, "metric": metric,
                                    "fixed_over_generic": fixed[metric] / generic[metric],
                                    "required_maximum": maximum})
    return {"eligible_for_node_followup": all(row["fixed_over_generic"] <= row["required_maximum"] for row in comparisons),
            "comparisons": comparisons}


def run(args):
    shape_bytes = args.shape.read_bytes()
    native_shape = json.loads(shape_bytes)
    require(native_shape.get("status") == "verified", "Native mixer specialization is unproven")
    headers = args.headers.read_bytes()
    require(len(headers) == HEADERS * 80 and hashlib.sha256(headers).hexdigest() == HEADER_SHA,
            "Authentic header fixture differs from its reference")
    args.output.mkdir()
    differential = args.output / "headers-check.bin"
    with differential.open("xb") as stream:
        stream.write(headers[:128 * 80])
    report = {"status": "in_progress", "scope": "native full proof microbenchmark",
              "fixture_sha256": HEADER_SHA, "expected_output_sha256": PROOF_SHA, "fixed_workers": WORKERS,
              "arms_by_round": PAIRS, "header_count_per_trial": HEADERS, "compute_limit_seconds": COMPUTE_LIMIT,
              "native_shape_sha256": hashlib.sha256(shape_bytes).hexdigest(), "trials": []}
    start = time.monotonic()

    def invoke(stem, arguments, cap):
        remaining = COMPUTE_LIMIT - (time.monotonic() - start)
        if remaining <= 0:
            raise TimeoutError("The fixed native compute budget expired")
        out = args.output / f"{stem}.stdout"
        with out.open("xb") as stdout, (args.output / f"{stem}.stderr").open("xb") as stderr:
            subprocess.run([str(args.binary), *arguments], stdout=stdout, stderr=stderr, check=True,
                           timeout=min(cap, remaining))
        require(out.stat().st_size <= 65536, f"Unexpected diagnostic output size: {stem}")
        return out

    try:
        check = invoke("differential-check", ["check", str(differential)], 36)
        differential_result = json.loads(check.read_bytes())
        require(differential_result == {"status": "verified", "authentic_headers": 128,
                                        "deterministic_headers": 32, "individual_error_cases": 4, "valid_fallback_cases": 3},
                "Incomplete authentic, deterministic or malformed-input differential coverage")
        report["differential_check"] = differential_result
        for workers in WORKERS:
            for round_number, modes in enumerate(PAIRS, 1):
                for arm in modes:
                    stem = f"w{workers}-round{round_number}-{arm}"
                    out = invoke(stem, ["bench", arm, str(args.headers), "1", str(workers)], 30)
                    row = json.loads(out.read_bytes())
                    require(row["arm"] == arm and row["workers"] == workers and row["headers"] == HEADERS and
                            row["repeats"] == 1 and row["proof_digest"] == PROOF_SHA,
                            f"Trial result or independent proof SHA-256 differs: {stem}")
                    require(all(math.isfinite(row[metric]) and row[metric] > 0 for metric in METRICS),
                            f"Invalid full proof timing: {stem}")
                    report["trials"].append({**row, "round": round_number, "stdout": out.name})
        report["decision"] = evaluate(report["trials"])
        report["status"] = "recorded"
    except Exception as error:
        report["status"] = "inconclusive" if isinstance(error, (subprocess.TimeoutExpired, TimeoutError)) else "failed"
        report["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        report["elapsed_seconds"] = time.monotonic() - start
        with (args.output / "result.json").open("x", encoding="utf-8") as result:
            json.dump(report, result, sort_keys=True, indent=2)
            result.write("\n")
    print(f"Recorded 12 full-proof trials. Node follow-up eligible = {report['decision']['eligible_for_node_followup']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "headers", "output", "shape"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    run(parser.parse_args())


if __name__ == "__main__":
    main()

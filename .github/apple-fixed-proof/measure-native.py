#!/usr/bin/env python3
"""Compare generic and fixed-parameter full proofs on native Apple ARM64."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import time


HEADERS = 3072
HEADER_SHA = "dc7a666edf2992bc2c3821a8819b93c7008f057eae04d2da36f66c0ef1b87a02"
PROOF_SHA = "ccaef882fe8bcf619cd0137f33ae98cef051593f8569984444a22586def913a2"
WORKERS = (1, 3, 8)
ARMS = ("generic", "fixed")
PAIRS = (ARMS, ARMS[::-1])
METRICS = ("worker_cpu_total_ns", "wall_ns")
COMPUTE_LIMIT = 140
PROOF_CPU_WALL_DIVISOR = 16


def require(ok, detail):
    if not ok:
        raise ValueError(detail)


def wait_for_owned_child(command, stdout, stderr, timeout):
    """Spawn and reap exactly one child. No other wait consumes its rusage."""
    actions = [(os.POSIX_SPAWN_DUP2, stdout.fileno(), 1), (os.POSIX_SPAWN_DUP2, stderr.fileno(), 2)]
    start = time.monotonic_ns()
    deadline = start + int(timeout * 1_000_000_000)
    pid = os.posix_spawn(command[0], command, os.environ, file_actions=actions)
    reaped = False
    timed_out = False
    try:
        while True:
            observed, status, usage = os.wait4(pid, os.WNOHANG)
            if observed == pid:
                reaped = True
                break
            remaining = deadline - time.monotonic_ns()
            if remaining <= 0:
                timed_out = True
                break
            time.sleep(min(0.01, remaining / 1_000_000_000))
    finally:
        if not reaped:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            observed, status, usage = os.wait4(pid, 0)
    require(observed == pid, "CPU exit receipt does not belong to the spawned child")
    return {"source": "wait4", "pid": pid, "exit_code": os.waitstatus_to_exitcode(status),
            "timed_out": timed_out, "elapsed_ns": time.monotonic_ns() - start,
            "user_cpu_ns": round(usage.ru_utime * 1_000_000_000),
            "system_cpu_ns": round(usage.ru_stime * 1_000_000_000)}


def verify_cpu_accounting(row, receipt, workers, *, cpu_bound):
    required = ("thread_clock_resolution_ns", "wall_clock_resolution_ns", "wall_ns",
                "main_thread_cpu_ns", "worker_cpu_total_ns")
    require(all(type(row.get(name)) is int and row[name] >= 0 for name in required), "Malformed CPU clock readings")
    thread_tick = row["thread_clock_resolution_ns"]
    wall_tick = row["wall_clock_resolution_ns"]
    wall = row["wall_ns"]
    require(0 < thread_tick <= 1_000_000 and 0 < wall_tick <= 1_000_000 and wall >= 10 * wall_tick,
            "Benchmark did not resolve the clock interval")
    samples = row.get("worker_cpu_ns")
    require(isinstance(samples, list) and len(samples) == workers and
            all(type(value) is int and value >= thread_tick for value in samples), "Invalid individual proof worker CPU time")
    require(sum(samples) == row["worker_cpu_total_ns"], "Proof worker CPU total differs from its samples")
    diagnostic = row.get("diagnostic_process_cpu_ns")
    require("diagnostic_process_cpu_ns" in row and (diagnostic is None or type(diagnostic) is int),
            "Malformed diagnostic process time")
    # 2 ms allows exit-accounting rounding and cross-clock skew. The
    # resolution-dependent term covers each reported worker and the caller.
    tolerance = max(2_000_000, (workers + 2) * (thread_tick + wall_tick))
    caller = row["main_thread_cpu_ns"]
    require(all(sample <= wall + tolerance for sample in (*samples, caller)), "Thread CPU exceeds its monotonic interval")
    require(wall <= receipt["elapsed_ns"] + tolerance, "Child proof interval exceeds parent-observed duration")
    exit_cpu = receipt["user_cpu_ns"] + receipt["system_cpu_ns"]
    require(receipt["source"] == "wait4" and receipt["exit_code"] == 0 and not receipt["timed_out"] and
            min(receipt["user_cpu_ns"], receipt["system_cpu_ns"]) >= 0 and exit_cpu + tolerance >= sum(samples) + caller,
            "Worker CPU exceeds independent whole-child exit accounting")
    if cpu_bound:
        require(min(samples) >= 10 * thread_tick and sum(samples) * PROOF_CPU_WALL_DIVISOR >= wall,
                "Implausibly little worker CPU for a completed proof workload")


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
              "native_shape_sha256": hashlib.sha256(shape_bytes).hexdigest(),
              "cpu_metric": "sum of pre-exit worker proof-loop CPU intervals",
              "minimum_cpu_fraction_of_wall": 1 / PROOF_CPU_WALL_DIVISOR, "trials": []}
    start = time.monotonic()

    def invoke(stem, arguments, cap):
        remaining = COMPUTE_LIMIT - (time.monotonic() - start)
        if remaining <= 0:
            raise TimeoutError("The fixed native compute budget expired")
        out = args.output / f"{stem}.stdout"
        receipt_path = args.output / f"{stem}.rusage.json"
        with out.open("xb") as stdout, (args.output / f"{stem}.stderr").open("xb") as stderr:
            receipt = wait_for_owned_child([str(args.binary.resolve(strict=True)), *arguments], stdout, stderr, min(cap, remaining))
        receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
        if receipt["timed_out"]:
            raise TimeoutError(f"Native probe timed out: {stem}")
        require(receipt["exit_code"] == 0, f"Native probe exited {receipt['exit_code']}: {stem}")
        require(out.stat().st_size <= 65536, f"Unexpected diagnostic output size: {stem}")
        return out, receipt, receipt_path

    try:
        check, _, check_receipt = invoke("differential-check", ["check", str(differential)], 36)
        differential_result = json.loads(check.read_bytes())
        require(differential_result == {"status": "verified", "authentic_headers": 128,
                                        "deterministic_headers": 32, "individual_error_cases": 4, "valid_fallback_cases": 3},
                "Incomplete authentic, deterministic or malformed-input differential coverage")
        report["differential_check"] = differential_result
        report["differential_exit_accounting"] = check_receipt.name
        for workers in WORKERS:
            for round_number, modes in enumerate(PAIRS, 1):
                for arm in modes:
                    stem = f"w{workers}-round{round_number}-{arm}"
                    out, receipt, receipt_path = invoke(stem, ["bench", arm, str(args.headers), "1", str(workers)], 30)
                    row = json.loads(out.read_bytes())
                    require(row["arm"] == arm and row["workers"] == workers and row["headers"] == HEADERS and
                            row["repeats"] == 1 and row["proof_digest"] == PROOF_SHA,
                            f"Trial result or independent proof SHA-256 differs: {stem}")
                    verify_cpu_accounting(row, receipt, workers, cpu_bound=True)
                    report["trials"].append({**row, "round": round_number, "stdout": out.name,
                                             "exit_accounting": receipt_path.name})
        report["decision"] = evaluate(report["trials"])
        report["status"] = "recorded"
    except Exception as error:
        report["status"] = "inconclusive" if isinstance(error, TimeoutError) else "failed"
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

#!/usr/bin/env python3
"""Pair native Windows ConnectTip rereads across two pinned release artifacts."""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
from types import SimpleNamespace
import time
from urllib.request import ProxyHandler, build_opener, install_opener

import mainnet_body_reread as screen

BASELINE_SOURCE = "8cae65e954ee78a1b40879c968ef2049d170930e"
BASELINE_TREE = "a9b417f9093256338b09e095c42f8cb114040a65"
BASELINE_BINARY = {
    "msvcrt": "b0a10dc30299a2fac0f4426f6d195a639afac2dfa73cefecbc25b86e1ce0d00b",
    "ucrt": "64ceba489eeffce7acce3c6ec92996b5f47cc63fd347b14fdaeacdb580ecdecf",
}
ORDER = (
    ("baseline", "held-gap"), ("candidate", "held-gap"),
    ("candidate", "held-gap"), ("baseline", "held-gap"),
    ("baseline", "in-order"), ("candidate", "in-order"),
)
PROTOCOL_TIMEOUT = 80
RESTART_TIMEOUT = 18
HASH_LINE = re.compile(r"([0-9a-f]{64}) [ *](.+)")


def digest(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def release_input(folder, expected_source, expected_tree, known_binary=None):
    root = folder.resolve(strict=True)
    names = ("release-source-sha.txt", "release-source-tree.txt", "bin/sugarchaind.exe")
    records = {}
    for line in (root / "SHA256SUMS.release-inputs").read_text(encoding="utf-8").splitlines():
        entry = HASH_LINE.fullmatch(line)
        if entry and entry[2] in names:
            screen.require(entry[2] not in records, f"Duplicate release input entry for {entry[2]}")
            records[entry[2]] = entry[1]
    screen.require(set(records) == set(names), "Expected checksums for the release SHA, tree and daemon")
    for name in names:
        screen.require(digest(root / name) == records[name], f"Release input checksum differs for {name}")
    source = (root / names[0]).read_text(encoding="utf-8").strip()
    tree = (root / names[1]).read_text(encoding="utf-8").strip()
    screen.require(source == expected_source and tree == expected_tree, "Unexpected native release source or source tree")
    binary_hash = records[names[2]]
    screen.require(known_binary is None or binary_hash == known_binary, "Unexpected retained baseline daemon for this CRT")
    return {"source": source, "tree": tree, "binary_sha256": binary_hash, "binary": str(root / names[2])}


class WindowsResources(screen.Resources):
    """Keep the original resource samples and optionally preserve raw CPU cycles."""

    def __init__(self):
        super().__init__()
        self.snapshots = []
        self.process_cycles = getattr(self.kernel, "QueryProcessCycleTime", None)
        if self.process_cycles:
            self.process_cycles.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_ulonglong)]
            self.process_cycles.restype = wintypes.BOOL

    def sample(self, proc):
        cpu, rss = super().sample(proc)
        row = {"pid": proc.pid, "cpu_seconds": cpu, "rss_bytes": rss, "cycles": None}
        if self.process_cycles:
            cycles = ctypes.c_ulonglong()
            if self.process_cycles(wintypes.HANDLE(int(proc._handle)), ctypes.byref(cycles)):
                row["cycles"] = cycles.value
            else:
                row["cycle_error"] = ctypes.get_last_error()
        self.snapshots.append(row)
        return cpu, rss


def case_cycles(before, after):
    if before["cycles"] is None or after["cycles"] is None:
        return None
    delta = after["cycles"] - before["cycles"]
    return delta if delta > 0 else None


def positive_ratio(candidate, baseline):
    if candidate is None or baseline is None or min(candidate, baseline) <= 0:
        return None
    return candidate / baseline


def paired(baseline, candidate):
    old, new = baseline["measurement"], candidate["measurement"]
    old_read, new_read = old["result"], new["result"]
    return {
        "baseline_trial": baseline["trial"], "candidate_trial": candidate["trial"],
        "disk_rereads_per_case": old_read["disk_rereads"],
        "baseline_reread_load_ms": old_read["reread_load_ms_sum"],
        "candidate_reread_load_ms": new_read["reread_load_ms_sum"],
        "reread_load_delta_ms": round(new_read["reread_load_ms_sum"] - old_read["reread_load_ms_sum"], 3),
        "reread_load_ratio": positive_ratio(new_read["reread_load_ms_sum"], old_read["reread_load_ms_sum"]),
        "per_event_log_resolution_ms": old_read["log_timing_resolution_ms"],
        "controlled_wall_ratio_including_barriers": positive_ratio(
            new["controlled_wall_seconds_including_barriers"], old["controlled_wall_seconds_including_barriers"],
        ),
        "reported_process_cpu_ratio_when_nonzero": positive_ratio(
            new["node_cpu_seconds_including_barriers"], old["node_cpu_seconds_including_barriers"],
        ),
        "raw_process_cycle_ratio_when_available": positive_ratio(candidate["process_cycles"], baseline["process_cycles"]),
    }


def verify_case(measurement, mode, fixture, body_bytes):
    checked = measurement["result"]
    rereads = screen.HEIGHT if mode == "held-gap" else 0
    tip = {"height": screen.HEIGHT, "tip": fixture["tip"], "utxo_hash": screen.UTXO_SHA, "utxo_count": screen.UTXO_COUNT}
    screen.require(measurement["state"] == measurement["offline_restart_state"] == tip,
                   "Mainnet tip and UTXO parity must hold in each arm and after restart")
    screen.require(measurement["mode"] == mode and measurement["primed_headers"] == screen.HEIGHT
                   and measurement["unique_bodies_sent"] == screen.HEIGHT and measurement["body_bytes_sent"] == body_bytes
                   and measurement["barrier_count"] == screen.HEIGHT // screen.GROUP,
                   "Unexpected native delivery workload")
    screen.require(checked["confirmed_ingress_count"] == screen.HEIGHT and checked["connect_tip_records"] == screen.HEIGHT
                   and checked["disk_rereads"] == rereads and checked["direct_memory_blocks"] == screen.HEIGHT - rereads,
                   "Expected the existing in-order and held-gap ConnectTip read counts to remain equal")
    names = ("reread_load_ms_sum", "all_load_ms_sum", "connect_block_ms_sum")
    screen.require(all(math.isfinite(checked[name]) and checked[name] >= 0 for name in names), "Invalid native phase timings")


def make_fixture(archive, fixture_info):
    fixture, headers, blocks = screen.get_fixture(archive, fixture_info)
    hashes = [bytes.fromhex(fixture["genesis"])[::-1]] + [screen.hash256(header) for header in headers]
    frames = [screen.message(b"block", block) for block in blocks]
    batch = screen.make_batch("submitheader", [header.hex() for header in headers])
    return (fixture, headers, hashes, frames, batch, sum(map(len, blocks))), screen.block_geometry(blocks)


def run(args):
    screen.require(platform.system() == "Windows" and platform.machine().lower() in {"amd64", "x86_64"},
                   "Use a native Windows x86-64 runner")
    install_opener(build_opener(ProxyHandler({})))
    inputs = {
        "baseline": release_input(args.baseline, BASELINE_SOURCE, BASELINE_TREE, BASELINE_BINARY[args.crt]),
        "candidate": release_input(args.candidate, args.candidate_source, args.candidate_tree),
    }
    screen.require(inputs["baseline"]["binary_sha256"] != inputs["candidate"]["binary_sha256"]
                   and inputs["candidate"]["source"] != BASELINE_SOURCE, "Distinct baseline and candidate inputs are required")
    data, geometry = make_fixture(args.fixture, args.fixture_info)
    fixture = data[0]
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    output = root / "result.json"
    report = {
        "status": "in_progress", "crt": args.crt, "inputs": inputs, "order": ORDER,
        "host": {"platform": platform.platform(), "machine": platform.machine(), "logical_cpus": os.cpu_count(),
                 "processor": os.environ.get("PROCESSOR_IDENTIFIER"), "runner_image": os.environ.get("ImageVersion")},
        "fixture": fixture, "geometry": geometry, "requested_ceiling": screen.REQUEST_LIMIT,
        "protocol_timeout_seconds": PROTOCOL_TIMEOUT, "restart_timeout_seconds": RESTART_TIMEOUT,
        "samples": [],
    }
    screen.persist(output, report)
    try:
        resources = WindowsResources()
        screen.PROTOCOL_TIMEOUT = PROTOCOL_TIMEOUT
        screen.RESTART_TIMEOUT = RESTART_TIMEOUT
        for index, (role, mode) in enumerate(ORDER, 1):
            case = {"trial": index, "binary_role": role, "mode": mode, "status": "in_progress"}
            report["samples"].append(case)
            screen.persist(output, report)
            variant = SimpleNamespace(binary=Path(inputs[role]["binary"]), gui=False)
            directory = root / f"{index:02d}-{role}-{mode}"
            resources.snapshots.clear()
            started = time.monotonic()
            measurement = screen.run_case(variant, mode, directory, data, resources)
            case["measurement"] = measurement
            case["native_phase_resource_samples"] = resources.snapshots.copy()
            case["case_wall_including_priming_restart_seconds"] = time.monotonic() - started
            screen.require(len(resources.snapshots) == 2 and resources.snapshots[0]["pid"] == resources.snapshots[1]["pid"],
                           "Two body-phase snapshots from the same process are required")
            case["process_cycles"] = case_cycles(*resources.snapshots)
            verify_case(measurement, mode, fixture, data[-1])
            case["status"] = "verified"
            screen.persist(output, report)
        samples = report["samples"]
        report["held_gap_pairs"] = [paired(samples[a], samples[b]) for a, b in ((0, 1), (3, 2))]
        report["in_order_control"] = paired(samples[4], samples[5])
        report["status"] = "verified"
    except Exception as error:
        if report["samples"] and report["samples"][-1]["status"] == "in_progress":
            report["samples"][-1]["status"] = "failed"
        report.update(status="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        screen.persist(output, report)
    print(json.dumps({"status": report["status"], "crt": args.crt,
                      "held_gap_pairs": report["held_gap_pairs"], "in_order_control": report["in_order_control"]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crt", choices=tuple(BASELINE_BINARY), required=True)
    for option in ("baseline", "candidate", "fixture", "fixture-info", "output"):
        parser.add_argument(f"--{option}", type=Path, required=True)
    parser.add_argument("--candidate-source", required=True)
    parser.add_argument("--candidate-tree", required=True)
    args = parser.parse_args()
    if not all(re.fullmatch("[0-9a-f]{40}", value) for value in (args.candidate_source, args.candidate_tree)):
        parser.error("Supply the full exact candidate source SHA and tree hash")
    run(args)


if __name__ == "__main__":
    main()

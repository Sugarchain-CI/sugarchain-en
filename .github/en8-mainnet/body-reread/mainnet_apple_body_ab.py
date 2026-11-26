#!/usr/bin/env python3
"""Compare native Apple Silicon block storage using two signed Mainnet packages."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import time
from types import SimpleNamespace
from urllib.request import ProxyHandler, build_opener, install_opener

import mainnet_body_reread as body

BASELINE_SOURCE = "9c502574b652804905d2533d51742ca91f694532"
BASELINE_TREE = "f44aa1b47f9701996046bbb396106f1d5c365e66"
PACKAGE = "sugarchain-en-31.1.2-macos-arm64"
ARCHIVE_MEMBERS = {
    f"{PACKAGE}-cli.tar.gz", f"{PACKAGE}.zip",
    "release-source-sha.txt", "release-source-tree.txt", "regtest-benchmark.json",
}
MODES = ("held-gap", "in-order")
ORDER = tuple((mode, role) for mode in MODES for role in ("baseline", "candidate", "candidate", "baseline"))
PROTOCOL_TIMEOUT = 45
RESTART_TIMEOUT = 15
HASH_LINE = re.compile(r"([0-9a-f]{64}) [ *](.+)")
UNDO = re.compile(r" - Write undo data: ([0-9.]+)ms ")
CONNECT = re.compile(r" - Connect block: ([0-9.]+)ms ")
CHAINSTATE = re.compile(r" - Writing chainstate: ([0-9.]+)ms ")
BLOCK_COMMIT = re.compile(r"FlushStateToDisk: write block and undo data to disk completed \(([0-9.]+)ms\)")
INDEX_COMMIT = re.compile(r"FlushStateToDisk: write block index to disk completed \(([0-9.]+)ms\)")


def digest(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def check_package(folder, expected_source, expected_tree):
    root = folder.resolve(strict=True)
    manifest = root / "package.sha256"
    files = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = HASH_LINE.fullmatch(line)
        body.require(match is not None, "Malformed Apple release package manifest")
        sha, name = match.groups()
        body.require(name in ARCHIVE_MEMBERS and name not in files, f"Unexpected package member {name}")
        files[name] = sha
    body.require(files.keys() == ARCHIVE_MEMBERS, "Incomplete Apple release package manifest")
    for name, sha in files.items():
        body.require(digest(root / name) == sha, f"Package checksum differs for {name}")
    source = (root / "release-source-sha.txt").read_text(encoding="utf-8").strip()
    tree = (root / "release-source-tree.txt").read_text(encoding="utf-8").strip()
    body.require((source, tree) == (expected_source, expected_tree), "Unexpected exact-source package identity")
    return {
        "source": source, "tree": tree, "manifest_sha256": digest(manifest), "package_members": files,
    }


def prepare_binary(folder, destination, gui):
    destination.mkdir()
    if gui:
        archive = folder / f"{PACKAGE}.zip"
        app = destination / "Sugarchain-Qt.app"
        subprocess.run(["ditto", "-x", "-k", str(archive), str(destination)], check=True, timeout=45)
        subprocess.run(["codesign", "--verify", "--strict", "--deep", str(app)], check=True, timeout=15)
        binary = app / "Contents/MacOS/Sugarchain-Qt"
    else:
        archive = folder / f"{PACKAGE}-cli.tar.gz"
        subprocess.run(["tar", "-xzf", str(archive), "-C", str(destination)], check=True, timeout=30)
        binary = destination / f"{PACKAGE}-cli/bin/sugarchaind"
        subprocess.run(["codesign", "--verify", "--strict", str(binary)], check=True, timeout=15)
    architecture = subprocess.check_output(["lipo", "-archs", str(binary)], text=True, timeout=10).strip()
    body.require(architecture == "arm64", f"Expected a thin arm64 runtime for {binary.name}")
    with binary.open("rb") as handle:
        body.require(handle.read(8) == bytes.fromhex("cffaedfe0c000001"), f"Invalid arm64 Mach-O for {binary.name}")
    return {"archive": archive.name, "binary": str(binary), "binary_sha256": digest(binary)}


def fixture_data(archive, info):
    fixture, headers, blocks = body.get_fixture(archive, info)
    hashes = [bytes.fromhex(fixture["genesis"])[::-1], *(body.hash256(header) for header in headers)]
    frames = [body.message(b"block", block) for block in blocks]
    prime = body.make_batch("submitheader", [header.hex() for header in headers])
    return (fixture, headers, hashes, frames, prime, sum(map(len, blocks))), body.block_geometry(blocks)


def check_workload(measurement, mode, fixture, bytes_sent):
    tip = {
        "height": body.HEIGHT, "tip": fixture["tip"],
        "utxo_hash": body.UTXO_SHA, "utxo_count": body.UTXO_COUNT,
    }
    body.require(measurement["state"] == measurement["offline_restart_state"] == tip,
                 "Mainnet tip and UTXO parity must hold before and after restart")
    body.require(measurement["mode"] == mode and measurement["primed_headers"] == measurement["unique_bodies_sent"] == body.HEIGHT,
                 "Unexpected Mainnet header or block count")
    body.require(measurement["barrier_count"] == body.HEIGHT // body.GROUP and measurement["body_bytes_sent"] == bytes_sent,
                 "Unexpected delivery barriers or body payload size")
    stats = measurement["result"]
    expected_rereads = body.HEIGHT if mode == "held-gap" else 0
    body.require(stats["confirmed_ingress_count"] == stats["connect_tip_records"] == body.HEIGHT
                 and stats["disk_rereads"] == expected_rereads
                 and stats["direct_memory_blocks"] == body.HEIGHT - expected_rereads,
                 "ConnectTip did not observe the required block read profile")


def log_timing(pattern, lines):
    values = []
    for line in lines:
        match = pattern.search(line)
        if match:
            values.append(float(match[1]))
    return {"events": len(values), "sum_ms": round(sum(values), 3)}


def storage_timing(debug):
    lines = debug.read_text(encoding="utf-8", errors="replace").splitlines()
    first = next((index for index, line in enumerate(lines) if body.INGRESS.search(line)), None)
    last = next((index for index in range(len(lines) - 1, -1, -1) if CONNECT.search(lines[index])), None)
    stop = next((index for index, line in enumerate(lines) if "Shutdown in progress..." in line), None)
    body.require(None not in (first, last, stop) and first < last < stop, "Missing body/tail/shutdown log boundaries")

    active = lines[first:last + 1]
    undo = log_timing(UNDO, active)
    chainstate = log_timing(CHAINSTATE, active)
    connect = log_timing(CONNECT, active)
    body.require(undo["events"] == chainstate["events"] == connect["events"] == body.HEIGHT,
                 "Expected one undo, chainstate and complete ConnectTip timer per fixture block")
    timings = {
        "undo_record": undo, "chainstate_inside_connect_tip": chainstate, "connect_tip_complete": connect,
    }
    for scope, section in (
        ("body", active), ("verification_tail", lines[last + 1:stop]), ("shutdown", lines[stop:]),
    ):
        timings[f"{scope}_block_undo_flush"] = log_timing(BLOCK_COMMIT, section)
        timings[f"{scope}_block_index_flush"] = log_timing(INDEX_COMMIT, section)
    return timings


def summarize_pair(baseline, candidate):
    old, new = baseline["measurement"], candidate["measurement"]
    return {
        "baseline_trial": baseline["trial"], "candidate_trial": candidate["trial"],
        "wall_seconds_candidate_minus_baseline": (
            new["controlled_wall_seconds_including_barriers"] - old["controlled_wall_seconds_including_barriers"]
        ),
        "cpu_seconds_candidate_minus_baseline": (
            new["node_cpu_seconds_including_barriers"] - old["node_cpu_seconds_including_barriers"]
        ),
        "log_timer_ms_candidate_minus_baseline": {
            key: round(new["storage_timing"][key]["sum_ms"] - timing["sum_ms"], 3)
            for key, timing in old["storage_timing"].items()
        },
    }


def run(args):
    body.require(platform.system() == "Darwin" and platform.machine() == "arm64", "Use a native Apple Silicon runner")
    body.check_host()
    install_opener(build_opener(ProxyHandler({})))
    body.require((args.candidate_source, args.candidate_tree) != (BASELINE_SOURCE, BASELINE_TREE)
                 and args.candidate_source != BASELINE_SOURCE and args.candidate_tree != BASELINE_TREE,
                 "Distinct baseline and candidate source identities are required")
    profiles = {
        "baseline": (args.baseline.resolve(strict=True), BASELINE_SOURCE, BASELINE_TREE),
        "candidate": (args.candidate.resolve(strict=True), args.candidate_source, args.candidate_tree),
    }
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    report_path = root / "result.json"
    data, geometry = fixture_data(args.fixture, args.fixture_info)
    report = {
        "status": "in_progress", "interface": "gui" if args.gui else "cli", "order": ORDER,
        "host": {"platform": platform.platform(), "logical_cpus": os.cpu_count(), "runner_image": os.environ.get("ImageVersion")},
        "fixture": data[0], "block_geometry": geometry, "group": body.GROUP, "request_limit": body.REQUEST_LIMIT,
        "protocol_timeout_seconds": PROTOCOL_TIMEOUT, "restart_timeout_seconds": RESTART_TIMEOUT,
        "sampled_cpu_source": "Darwin ps process CPU time and resident KiB",
        "log_timer_resolution_ms": 0.01, "standalone_block_append_timer": None,
        "inputs": {}, "samples": [],
    }
    body.persist(report_path, report)
    try:
        for role, (folder, source, tree) in profiles.items():
            metadata = check_package(folder, source, tree)
            metadata.update(prepare_binary(folder, root / f"package-{role}", args.gui))
            report["inputs"][role] = metadata
        body.require(report["inputs"]["baseline"]["binary_sha256"] != report["inputs"]["candidate"]["binary_sha256"],
                     "Both arms resolved to the same release binary")
        resources = body.Resources()
        body.PROTOCOL_TIMEOUT = PROTOCOL_TIMEOUT
        body.RESTART_TIMEOUT = RESTART_TIMEOUT
        for trial, (mode, role) in enumerate(ORDER, 1):
            case = {"trial": trial, "mode": mode, "role": role, "status": "in_progress"}
            report["samples"].append(case)
            body.persist(report_path, report)
            directory = root / f"{trial:02d}-{mode}-{role}"
            variant = SimpleNamespace(binary=Path(report["inputs"][role]["binary"]), gui=args.gui)
            start = time.monotonic()
            measured = body.run_case(variant, mode, directory, data, resources)
            case["case_wall_seconds_including_restarts"] = time.monotonic() - start
            case["measurement"] = measured
            check_workload(measured, mode, data[0], data[-1])
            measured["storage_timing"] = storage_timing(directory / "debug.log")
            case["status"] = "verified"
            body.persist(report_path, report)
        report["pairs"] = {}
        for mode in MODES:
            a, b, c, d = [case for case in report["samples"] if case["mode"] == mode]
            report["pairs"][mode] = [summarize_pair(a, b), summarize_pair(d, c)]
        report["status"] = "verified"
    except Exception as error:
        if report["samples"] and report["samples"][-1]["status"] == "in_progress":
            report["samples"][-1]["status"] = "failed"
        report.update(status="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        body.persist(report_path, report)
    print(f"{report['interface']} verified {len(report['samples'])} trials: {report_path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("baseline", "candidate", "fixture", "fixture-info", "output"):
        parser.add_argument(f"--{argument}", type=Path, required=True)
    parser.add_argument("--candidate-source", required=True)
    parser.add_argument("--candidate-tree", required=True)
    parser.add_argument("--gui", action="store_true")
    args = parser.parse_args()
    if not all(re.fullmatch(r"[0-9a-f]{40}", sha) for sha in (args.candidate_source, args.candidate_tree)):
        parser.error("Supply the full exact candidate source commit and tree hashes")
    run(args)


if __name__ == "__main__":
    main()

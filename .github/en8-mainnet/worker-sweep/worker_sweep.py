#!/usr/bin/env python3
"""Screen Apple Silicon worker settings on one pinned Mainnet PRESYNC executable."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tarfile
import time
from types import SimpleNamespace

from mainnet_probe import check_host
from presync_sweep import DarwinUsage, GENESIS, prepare_wire, read_fixture, save, timed_presync


SOURCE_SHA = "81934405da9cdfeca55c2a07997b881c22993bc6"
SOURCE_TREE = "b921f383b962f3c27164c9b2f9740e1a235e142d"
ARTIFACT_RUN = 45799308927
PACKAGE_STEM = "sugarchain-en-31.1.2-macos-arm64-cli"
PACKAGE_SHA = "785d6ad2b55fc9659539d742bcd9af9b2e4547181d8cc6ad4e4435c7783f2921"
BINARY_SHA = "c74b00f508a4336227aec345e174412372422604b3890eca9d7c4c9fecb95231"
ARCHIVE_SHA = "1d6b46da12f732190804a276b0c457d3c0ff923733ba29294f826eea971664ce"
FULL_FIXTURE_SHA = "f64a65677abdfa525b67d9a09291868fbfd1f9fb0d4089cdfafc3b2718dd07dd"
FULL_FIXTURE_TIP = "b62290c6914adee9b29326b8a4567114fff1f9013acb9c3b6ff68612a2947f99"
HEADER_COUNT = 50_000
PREFIX_SHA = "56067df408db5d0b1607671ad91c6a2bb267b69c95d7bd66ed2e0786f6f7b2b8"
PREFIX_TIP = "89014795f54676c2a4db8663d114e7c818950f4b3fe45c6d2de63ab9cc0aa945"
ORDER = (8, 3, 3, 8, 8, 4, 4, 8, 8, 6, 6, 8)
MIN_GAIN = 0.05
CASE_SECONDS = 180
CASE_SOFT_SECONDS = 155
RUN_SECONDS = 27 * 60


def sha(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def unpack_verified_binary(bundle, output):
    archive = bundle / f"{PACKAGE_STEM}.tar.gz"
    if ((bundle / "release-source-sha.txt").read_text().strip() != SOURCE_SHA
            or (bundle / "release-source-tree.txt").read_text().strip() != SOURCE_TREE
            or sha(archive) != PACKAGE_SHA):
        raise ValueError("Package source or archive hash differs from the pinned artifact")
    executable = output / "sugarchaind"
    with tarfile.open(archive, "r:gz") as tar:
        member = tar.getmember(f"{PACKAGE_STEM}/bin/sugarchaind")
        if not member.isfile():
            raise ValueError("Pinned package does not contain a regular daemon executable")
        with tar.extractfile(member) as source, executable.open("xb") as target:
            shutil.copyfileobj(source, target)
    if sha(executable) != BINARY_SHA:
        raise ValueError("Extracted daemon differs from the exact approved source artifact")
    executable.chmod(0o700)
    arches = subprocess.check_output(["/usr/bin/lipo", "-archs", str(executable)], text=True).strip()
    if arches != "arm64":
        raise ValueError(f"Unexpected executable architecture: {arches}")
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(executable)], check=True)
    return executable


def run_case(binary, prefix, directory, workers):
    if sha(binary) != BINARY_SHA:
        raise ValueError("Daemon digest changed before the trial")
    headers = read_fixture(prefix, PREFIX_SHA, PREFIX_TIP)
    if len(headers) != HEADER_COUNT:
        raise ValueError("Unexpected timed prefix length")
    locators, frames = prepare_wire(headers)
    usage = DarwinUsage()
    timings, checkpoints = [], []
    trial_path = directory / "trial.json"
    record = {
        "status": "running", "configured_workers": workers,
        "parpow_argument": None if workers == 8 else workers,
        "binary_sha256": BINARY_SHA, "checkpoints": checkpoints, "message_wall_seconds": timings,
    }
    save(trial_path, record)
    def checkpoint(row):
        checkpoints.append(row)
        save(trial_path, record)
    try:
        record.update(timed_presync(
            SimpleNamespace(binary=binary, gui=False), directory / "datadir", locators, frames,
            "default" if workers == 8 else workers, usage, timeout=CASE_SOFT_SECONDS,
            timings=timings, progress=checkpoint,
        ))
        record["status"] = "pass"
        record["cpu_seconds"] = record["user_cpu_seconds"] + record["system_cpu_seconds"]
    except (OSError, RuntimeError, ValueError) as error:
        record.update(status="fail", error=f"{type(error).__name__}: {error}")
    finally:
        save(trial_path, record)
    return 0 if record["status"] == "pass" else 1


def compare(trials):
    grouped = []
    for group, workers in enumerate((3, 4, 6)):
        block = trials[group * 4:group * 4 + 4]
        pairs = []
        for offset in (0, 2):
            pair = block[offset:offset + 2]
            if len(pair) != 2 or any(trial["status"] != "pass" for trial in pair):
                continue
            baseline = next(row for row in pair if row["configured_workers"] == 8)
            candidate = next(row for row in pair if row["configured_workers"] == workers)
            wall = 1 - candidate["wall_seconds"] / baseline["wall_seconds"]
            cpu = 1 - candidate["cpu_seconds"] / baseline["cpu_seconds"]
            pairs.append({
                "baseline_trial": baseline["trial"], "candidate_trial": candidate["trial"],
                "wall_reduction_fraction": wall, "cpu_reduction_fraction": cpu,
                "qualifies": wall >= MIN_GAIN and cpu >= MIN_GAIN,
            })
        group_result = {
            "workers": workers, "paired_results": pairs, "complete": len(pairs) == 2,
            "qualifies": len(pairs) == 2 and all(item["qualifies"] for item in pairs),
        }
        grouped.append(group_result)
    return grouped


def launch(binary, prefix, directory, workers, ordinal):
    directory.mkdir()
    start = time.monotonic()
    deadline = start + CASE_SECONDS
    running = subprocess.Popen(
        [sys.executable, "-B", str(Path(__file__).resolve()), "trial",
         str(binary), str(prefix), str(directory), str(workers)],
        start_new_session=True,
    )
    timed_out = False
    try:
        running.wait(timeout=max(0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(running.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        running.wait(timeout=2)
    trial_path = directory / "trial.json"
    row = json.loads(trial_path.read_text()) if trial_path.is_file() else {}
    row.update(trial=ordinal, configured_workers=workers, process_exit_code=running.returncode,
               total_case_wall_seconds=time.monotonic() - start)
    if timed_out:
        row["status"] = "timeout"
    elif running.returncode != 0 or row.get("status") != "pass":
        row["status"] = "fail"
    save(trial_path, row)
    return row


def sweep(options):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("A native Apple Silicon host is required")
    check_host()
    deadline = time.monotonic() + RUN_SECONDS
    output = options.output.resolve()
    output.mkdir(parents=True)
    result_path = output / "result.json"
    executable = unpack_verified_binary(options.artifact, output)
    if sha(options.headers) != ARCHIVE_SHA:
        raise ValueError("The pinned 100,000-header archive differs")
    fixture = read_fixture(options.headers, FULL_FIXTURE_SHA, FULL_FIXTURE_TIP)
    if len(fixture) != 100_000:
        raise ValueError("Unexpected source header count")
    prefix = output / "headers-50000.bin"
    prefix.write_bytes(b"".join(fixture[:HEADER_COUNT]))
    if sha(prefix) != PREFIX_SHA:
        raise ValueError("The pinned 50,000-header prefix differs")
    trials = []
    report = {
        "scope": "One exact Arm64 CLI source artifact, native Mainnet localhost PRESYNC",
        "source": {"commit": SOURCE_SHA, "tree": SOURCE_TREE, "upstream_run": ARTIFACT_RUN,
                   "package_sha256": PACKAGE_SHA, "daemon_sha256": BINARY_SHA},
        "host": {"platform": platform.platform(), "machine": platform.machine(), "logical_cpus": os.cpu_count(),
                 "runner_image_version": os.environ.get("ImageVersion")},
        "fixture": {"source_archive_sha256": ARCHIVE_SHA, "source_raw_sha256": FULL_FIXTURE_SHA,
                    "timed_prefix_sha256": PREFIX_SHA, "last_height": HEADER_COUNT, "tip": PREFIX_TIP},
        "expected_state": {"chain": "main", "blocks": 0, "active_headers": 0,
                           "presynced_headers": HEADER_COUNT, "genesis": GENESIS},
        "trial_timeout_seconds": CASE_SECONDS, "run_timeout_seconds": RUN_SECONDS,
        "order": ORDER, "pair_minimum_wall_and_cpu_reduction": MIN_GAIN, "trials": trials, "complete": False,
    }
    save(result_path, report)
    for index, setting in enumerate(ORDER, 1):
        if time.monotonic() + CASE_SECONDS > deadline:
            report["incomplete_reason"] = "Insufficient time for the next complete trial within the run deadline"
            break
        print(f"Apple CLI trial {index}/{len(ORDER)}: {setting} workers", flush=True)
        trial = launch(executable, prefix, output / f"{index:02d}-workers-{setting}", setting, index)
        trials.append(trial)
        print(f"Trial {index}: {trial['status']}", flush=True)
        report["worker_settings"] = compare(trials)
        save(result_path, report)
    report["complete"] = len(trials) == len(ORDER) and all(trial["status"] == "pass" for trial in trials)
    save(result_path, report)
    if not report["complete"]:
        raise SystemExit("Worker sweep incomplete. Partial results retained.")


def main():
    if len(sys.argv) == 6 and sys.argv[1] == "trial":
        raise SystemExit(run_case(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), int(sys.argv[5])))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--headers", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    sweep(parser.parse_args())


if __name__ == "__main__":
    main()

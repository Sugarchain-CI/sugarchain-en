#!/usr/bin/env python3
"""Compare two native Apple Silicon packages over fixed Mainnet PRESYNC."""

import argparse
import hashlib
import os
from pathlib import Path
import platform
import subprocess
from types import SimpleNamespace

from presync_sweep import (
    BATCH, CONFIRM_HEADERS, DarwinUsage, GENESIS, check_host, prepare_wire,
    read_fixture, save, timed_presync,
)


FIXTURE_SHA256 = "f64a65677abdfa525b67d9a09291868fbfd1f9fb0d4089cdfafc3b2718dd07dd"
ARCHIVE_SHA256 = "1d6b46da12f732190804a276b0c457d3c0ff923733ba29294f826eea971664ce"
FIXTURE_TIP = "b62290c6914adee9b29326b8a4567114fff1f9013acb9c3b6ff68612a2947f99"
TRIAL_TIMEOUT_SECONDS = 480
ORDER = ("baseline", "candidate", "candidate", "baseline")


def digest(path):
    with path.open("rb") as binary:
        return hashlib.file_digest(binary, "sha256").hexdigest()


def binary_provenance(path, expected):
    path = path.resolve(strict=True)
    architectures = subprocess.run(
        ["/usr/bin/lipo", "-archs", str(path)],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    if "arm64" not in architectures:
        raise ValueError(f"The package has no native arm64 executable: {path}")
    checksum = digest(path)
    if expected is not None and checksum != expected:
        raise ValueError(f"The binary SHA-256 does not match the pinned digest: {path}")
    return {"path": str(path), "sha256": checksum, "architectures": architectures}


def summarize_pairs(trials):
    pairs = []
    for start in (0, 2):
        pair = trials[start:start + 2]
        result = {"trials": [trial["trial"] for trial in pair], "status": "incomplete"}
        if len(pair) == 2 and all(trial["status"] == "pass" for trial in pair):
            by_role = {trial["role"]: trial for trial in pair}
            baseline = by_role["baseline"]
            candidate = by_role["candidate"]
            base_cpu = baseline["user_cpu_seconds"] + baseline["system_cpu_seconds"]
            new_cpu = candidate["user_cpu_seconds"] + candidate["system_cpu_seconds"]
            result.update(
                status="pass",
                wall_seconds_change_percent=100 * (candidate["wall_seconds"] / baseline["wall_seconds"] - 1),
                cpu_seconds_change_percent=100 * (new_cpu / base_cpu - 1),
            )
        pairs.append(result)
    return pairs


def run(options):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("A native Apple Silicon host is required")
    check_host()
    programs = {
        "baseline": binary_provenance(options.baseline, options.baseline_sha256),
        "candidate": binary_provenance(options.candidate, options.candidate_sha256),
    }
    if programs["baseline"]["sha256"] == programs["candidate"]["sha256"]:
        raise ValueError("The baseline and candidate are identical binaries")
    if options.headers.suffix == ".gz" and digest(options.headers) != ARCHIVE_SHA256:
        raise ValueError("The compressed Mainnet fixture SHA-256 does not match")
    fixture = read_fixture(options.headers, FIXTURE_SHA256, FIXTURE_TIP)
    if len(fixture) != CONFIRM_HEADERS:
        raise ValueError("The paired comparison requires exactly 100000 Mainnet headers")
    locators, frames = prepare_wire(fixture)

    usage = DarwinUsage()
    options.output.parent.mkdir(parents=True, exist_ok=True)
    work = options.work or options.output.with_name(f"{options.output.stem}-work")
    work = work.resolve()
    work.mkdir(parents=True)
    result = {
        "mode": "native Apple Silicon Mainnet localhost PRESYNC with stock minimum chainwork",
        "interface": "gui" if options.gui else "cli",
        "binary": programs,
        "host": {"platform": platform.platform(), "machine": platform.machine(),
                 "logical_cpus": os.cpu_count(), "runner_image_version": os.environ.get("ImageVersion")},
        "mac_timebase": {"numer": usage.timebase.numer, "denom": usage.timebase.denom},
        "fixture": {"headers": len(fixture), "headers_per_message": BATCH, "first_height": 1,
                    "last_height": len(fixture), "genesis": GENESIS, "tip": FIXTURE_TIP,
                    "headers_sha256": FIXTURE_SHA256, "archive_sha256": ARCHIVE_SHA256},
        "expected_state": {"chain": "main", "blocks": 0, "active_headers": 0, "presynced_headers": len(fixture)},
        "order": ORDER,
        "trial_timeout_seconds": TRIAL_TIMEOUT_SECONDS,
        "trials": [],
    }
    save(options.output, result)
    for ordinal, role in enumerate(ORDER, 1):
        case = work / f"{ordinal:02d}-{role}"
        times = []
        trial = {
            "trial": ordinal, "pair": (ordinal + 1) // 2, "role": role,
            "binary_sha256": programs[role]["sha256"], "case_directory": str(case),
            "status": "running",
        }
        result["trials"].append(trial)
        save(options.output, result)
        args = SimpleNamespace(binary=Path(programs[role]["path"]), gui=options.gui)
        try:
            trial.update(timed_presync(args, case, locators, frames, "default", usage,
                                       timeout=TRIAL_TIMEOUT_SECONDS, timings=times))
            trial["status"] = "pass"
            print(f"{result['interface']} {ordinal}/4 {role}: {trial['wall_seconds']:.3f} s, "
                  f"{trial['mean_cpu_cores']:.3f} mean CPU cores", flush=True)
        except (OSError, RuntimeError, ValueError) as error:
            trial.update(status="fail", error=str(error)[:400])
            print(f"{result['interface']} {ordinal}/4 {role}: failed after {len(times) * BATCH} headers", flush=True)
        finally:
            trial["message_wall_seconds"] = times
            trial["confirmed_through_height"] = len(times) * BATCH
            result["pairs"] = summarize_pairs(result["trials"])
            save(options.output, result)

    if any(trial["status"] != "pass" for trial in result["trials"]):
        raise SystemExit("One or more paired Mainnet trials failed. All recorded trials were retained.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--headers", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--baseline-sha256")
    parser.add_argument("--candidate-sha256")
    parser.add_argument("--gui", action="store_true")
    run(parser.parse_args())

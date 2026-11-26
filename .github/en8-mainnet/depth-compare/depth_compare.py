#!/usr/bin/env python3
"""Compare exact Apple Silicon packages with the fixed Mainnet PRESYNC depth protocol."""

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


BASELINE_SOURCE = "81934405da9cdfeca55c2a07997b881c22993bc6"
BASELINE_TREE = "b921f383b962f3c27164c9b2f9740e1a235e142d"
CANDIDATE_SOURCE = "061dc30c21824155cb4a9c1c5d3bbf13c9ad790e"
CANDIDATE_TREE = "d91caa8495829d24de5b8d47f23e35f98c0b48a2"
BASELINE_RUN = 45799308927
PACKAGE_STEM = "sugarchain-en-31.1.2-macos-arm64"
GUI_PATH = Path("Sugarchain-Qt.app/Contents/MacOS/Sugarchain-Qt")
BASELINE_PACKAGE_SHA = {
    "cli": "785d6ad2b55fc9659539d742bcd9af9b2e4547181d8cc6ad4e4435c7783f2921",
    "gui": "2cd60e96b78376f54928b7a5c384103306bc96a1b4821d319a13ec7921172648",
}
BASELINE_BINARY_SHA = {
    "cli": "c74b00f508a4336227aec345e174412372422604b3890eca9d7c4c9fecb95231",
    "gui": "6472d19580f362706c8ebe2641692ee378f3a5ba2cc19d3563313fff53b4ff91",
}
ARCHIVE_SHA = "1d6b46da12f732190804a276b0c457d3c0ff923733ba29294f826eea971664ce"
FULL_FIXTURE_SHA = "f64a65677abdfa525b67d9a09291868fbfd1f9fb0d4089cdfafc3b2718dd07dd"
FULL_FIXTURE_TIP = "b62290c6914adee9b29326b8a4567114fff1f9013acb9c3b6ff68612a2947f99"
HEADER_COUNT = 50_000
PREFIX_SHA = "56067df408db5d0b1607671ad91c6a2bb267b69c95d7bd66ed2e0786f6f7b2b8"
PREFIX_TIP = "89014795f54676c2a4db8663d114e7c818950f4b3fe45c6d2de63ab9cc0aa945"
ORDER = (("baseline", 8), ("baseline", 3), ("candidate", 3),
         ("candidate", 3), ("baseline", 3), ("baseline", 8))
WALL_MAX_RATIO = 0.92
CPU_MAX_RATIO = 1.03
CASE_SECONDS = 180
CASE_SOFT_SECONDS = 155
RUN_SECONDS = 19 * 60


def sha(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def read_package_manifest(path):
    files = {}
    for line in path.read_text(encoding="ascii").splitlines():
        checksum, name = line.split(maxsplit=1)
        name = name.lstrip("*")
        if len(checksum) != 64 or not all(c in "0123456789abcdef" for c in checksum) or name in files:
            raise ValueError("Invalid package manifest entry")
        files[name] = checksum
    return files


def unpack_verified_binary(bundle, destination, role, interface):
    expected_source, expected_tree = (BASELINE_SOURCE, BASELINE_TREE) if role == "baseline" else (
        CANDIDATE_SOURCE, CANDIDATE_TREE
    )
    archive = bundle / (f"{PACKAGE_STEM}-cli.tar.gz" if interface == "cli" else f"{PACKAGE_STEM}.zip")
    manifest_path = bundle / "package.sha256"
    manifest = read_package_manifest(manifest_path)
    source_file = bundle / "release-source-sha.txt"
    tree_file = bundle / "release-source-tree.txt"
    actual_archive_sha = sha(archive)
    for path, checksum in [(archive, actual_archive_sha), (source_file, sha(source_file)), (tree_file, sha(tree_file))]:
        if manifest.get(path.name) != checksum:
            raise ValueError(f"{role} package manifest does not verify {path.name}")
    if source_file.read_text().strip() != expected_source or tree_file.read_text().strip() != expected_tree:
        raise ValueError(f"{role} package source commit or tree differs")
    if role == "baseline" and actual_archive_sha != BASELINE_PACKAGE_SHA[interface]:
        raise ValueError("Baseline archive differs from the pinned native artifact")
    destination.mkdir()
    if interface == "cli":
        binary = destination / "sugarchaind"
        with tarfile.open(archive, "r:gz") as tar:
            member = tar.getmember(f"{PACKAGE_STEM}-cli/bin/sugarchaind")
            if not member.isfile():
                raise ValueError("CLI archive must contain a regular daemon executable")
            with tar.extractfile(member) as source, binary.open("xb") as target:
                shutil.copyfileobj(source, target)
        binary.chmod(0o700)
    else:
        subprocess.run(["/usr/bin/ditto", "-x", "-k", str(archive), str(destination)], check=True)
        binary = destination / GUI_PATH
        subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(destination / GUI_PATH.parts[0])], check=True)
    binary = binary.resolve(strict=True)
    actual_binary_sha = sha(binary)
    if role == "baseline" and actual_binary_sha != BASELINE_BINARY_SHA[interface]:
        raise ValueError("Baseline binary differs from the pinned native artifact")
    if subprocess.check_output(["/usr/bin/lipo", "-archs", str(binary)], text=True).strip() != "arm64":
        raise ValueError(f"Expected native Arm64 executable for {role}")
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(binary)], check=True)
    return {
        "path": str(binary), "interface": interface, "architecture": "arm64",
        "source_sha": expected_source, "source_tree": expected_tree,
        "archive_sha256": actual_archive_sha, "binary_sha256": actual_binary_sha,
        "manifest_sha256": sha(manifest_path),
    }


def run_trial(config_path):
    config = json.loads(config_path.read_text())
    binary, prefix = Path(config["path"]), Path(config["prefix"])
    if sha(binary) != config["binary_sha256"]:
        raise ValueError("Executable digest changed before the trial")
    headers = read_fixture(prefix, PREFIX_SHA, PREFIX_TIP)
    if len(headers) != HEADER_COUNT:
        raise ValueError("Unexpected Mainnet prefix length")
    locators, frames = prepare_wire(headers)
    usage = DarwinUsage()
    timings, checkpoints = [], []
    trial_path = config_path.parent / "trial.json"
    record = {
        "status": "running", "interface": config["interface"], "role": config["role"], "workers": config["workers"],
        "binary_sha256": config["binary_sha256"], "checkpoints": checkpoints, "message_wall_seconds": timings,
    }
    save(trial_path, record)
    def checkpoint(row):
        checkpoints.append(row)
        save(trial_path, record)
    try:
        record.update(timed_presync(
            SimpleNamespace(binary=binary, gui=config["interface"] == "gui"),
            config_path.parent / "datadir", locators, frames, "default" if config["workers"] == 8 else 3,
            usage, timeout=CASE_SOFT_SECONDS, timings=timings, progress=checkpoint,
        ))
        record["status"] = "pass"
        record["cpu_seconds"] = record["user_cpu_seconds"] + record["system_cpu_seconds"]
    except (OSError, RuntimeError, ValueError) as error:
        record.update(status="fail", error=f"{type(error).__name__}: {error}")
    finally:
        save(trial_path, record)
    return 0 if record["status"] == "pass" else 1


def compare(trials):
    def pair(baseline_index, candidate_index):
        if max(baseline_index, candidate_index) >= len(trials):
            return None
        baseline, candidate = trials[baseline_index], trials[candidate_index]
        if baseline["status"] != "pass" or candidate["status"] != "pass":
            return None
        wall_ratio = candidate["wall_seconds"] / baseline["wall_seconds"]
        cpu_ratio = candidate["cpu_seconds"] / baseline["cpu_seconds"]
        return {
            "baseline_trial": baseline["trial"], "candidate_trial": candidate["trial"],
            "wall_time_ratio": wall_ratio, "cpu_time_ratio": cpu_ratio,
            "wall_reduction_fraction": 1 - wall_ratio, "cpu_change_fraction": cpu_ratio - 1,
            "baseline_mean_active_cores": baseline["mean_cpu_cores"],
            "candidate_mean_active_cores": candidate["mean_cpu_cores"],
        }

    brackets = [pair(0, 2), pair(5, 3)]
    for result in brackets:
        if result:
            result["passes_predeclared_gate"] = (
                result["wall_time_ratio"] <= WALL_MAX_RATIO and result["cpu_time_ratio"] <= CPU_MAX_RATIO
            )
    return {
        "candidate3_vs_baseline8": brackets,
        "candidate3_vs_baseline3_depth_isolation": [pair(1, 2), pair(4, 3)],
        "passes_predeclared_gate": all(row and row["passes_predeclared_gate"] for row in brackets),
    }


def launch(program, prefix, directory, role, workers, ordinal):
    directory.mkdir()
    config_path = directory / "config.json"
    save(config_path, {**program, "prefix": str(prefix), "role": role, "workers": workers})
    started = time.monotonic()
    proc = subprocess.Popen(
        [sys.executable, "-B", str(Path(__file__).resolve()), "trial", str(config_path)], start_new_session=True,
    )
    timed_out = False
    try:
        proc.wait(timeout=max(0, CASE_SECONDS - (time.monotonic() - started)))
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=2)
    trial_path = directory / "trial.json"
    result = json.loads(trial_path.read_text()) if trial_path.is_file() else {}
    result.update(trial=ordinal, role=role, workers=workers, process_exit_code=proc.returncode,
                  total_case_wall_seconds=time.monotonic() - started)
    if timed_out:
        result["status"] = "timeout"
    elif proc.returncode != 0 or result.get("status") != "pass":
        result["status"] = "fail"
    save(trial_path, result)
    return result


def run(options):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("A native Apple Silicon host is required")
    check_host()
    deadline = time.monotonic() + RUN_SECONDS
    output = options.output.resolve()
    output.mkdir(parents=True)
    result_path = output / "result.json"
    programs = {
        "baseline": unpack_verified_binary(options.baseline_artifact, output / "baseline", "baseline", options.interface),
        "candidate": unpack_verified_binary(options.candidate_artifact, output / "candidate", "candidate", options.interface),
    }
    if programs["baseline"]["binary_sha256"] == programs["candidate"]["binary_sha256"]:
        raise ValueError("Candidate must use the new source binary")
    if sha(options.headers) != ARCHIVE_SHA:
        raise ValueError("Pinned Mainnet header archive differs")
    fixture = read_fixture(options.headers, FULL_FIXTURE_SHA, FULL_FIXTURE_TIP)
    if len(fixture) != 100_000:
        raise ValueError("Unexpected source header count")
    prefix = output / "headers-50000.bin"
    prefix.write_bytes(b"".join(fixture[:HEADER_COUNT]))
    if sha(prefix) != PREFIX_SHA:
        raise ValueError("Pinned 50,000-header prefix differs")
    trials = []
    report = {
        "scope": "Exact native Arm64 packages, localhost Mainnet PRESYNC with stock minimum chainwork",
        "interface": options.interface, "baseline_run": BASELINE_RUN, "programs": programs,
        "host": {"platform": platform.platform(), "machine": platform.machine(), "logical_cpus": os.cpu_count(),
                 "runner_image_version": os.environ.get("ImageVersion")},
        "fixture": {"archive_sha256": ARCHIVE_SHA, "raw_sha256": FULL_FIXTURE_SHA, "prefix_sha256": PREFIX_SHA,
                    "first_height": 1, "last_height": HEADER_COUNT, "tip": PREFIX_TIP},
        "expected_state": {"chain": "main", "blocks": 0, "active_headers": 0,
                           "presynced_headers": HEADER_COUNT, "genesis": GENESIS},
        "order": ORDER, "trial_timeout_seconds": CASE_SECONDS, "run_timeout_seconds": RUN_SECONDS,
        "predeclared_gate": {"candidate3_vs_baseline8_max_wall_ratio": WALL_MAX_RATIO,
                             "candidate3_vs_baseline8_max_cpu_ratio": CPU_MAX_RATIO, "required_pairs": 2},
        "trials": trials, "complete": False,
    }
    save(result_path, report)
    for index, (role, workers) in enumerate(ORDER, 1):
        if time.monotonic() + CASE_SECONDS > deadline:
            report["incomplete_reason"] = "Insufficient time for the next full trial before the run deadline"
            break
        print(f"{options.interface} {index}/{len(ORDER)}: {role} {workers} workers", flush=True)
        trial = launch(programs[role], prefix, output / f"{index:02d}-{role}{workers}", role, workers, index)
        trials.append(trial)
        if trial["status"] == "pass":
            print(f"{trial['wall_seconds']:.3f}s wall and {trial['cpu_seconds']:.3f}s CPU", flush=True)
        else:
            print(f"{trial['status']}: {trial.get('error', 'see trial evidence')}", flush=True)
        report["comparisons"] = compare(trials)
        save(result_path, report)
    report["complete"] = len(trials) == len(ORDER) and all(trial["status"] == "pass" for trial in trials)
    save(result_path, report)
    if not report["complete"]:
        raise SystemExit("The comparison is incomplete. Partial trial evidence was retained.")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "trial":
        raise SystemExit(run_trial(Path(sys.argv[2])))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-artifact", required=True, type=Path)
    parser.add_argument("--candidate-artifact", required=True, type=Path)
    parser.add_argument("--interface", required=True, choices=("cli", "gui"))
    parser.add_argument("--headers", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    run(parser.parse_args())


if __name__ == "__main__":
    main()

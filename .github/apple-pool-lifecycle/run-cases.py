#!/usr/bin/env python3
"""Run and preserve five bounded allocator lifecycle cases."""

import argparse
import json
from pathlib import Path
import subprocess
import time

CHECKSUM = "52a221686470aeda"
LIFECYCLE_FLAGS = (
    "fd_mode_0600", "unlinked", "cloexec", "shared_readback", "owned_through_borrowers",
    "fd_closed", "mapping_released", "no_temp_paths",
)
CASES = (
    ("refusal-missing", "file", 0), ("refusal-bad-size", "bad-size", 0),
    ("heap", "heap", 0), ("file", "file", 16 << 20), ("mixed", "mixed", 512 << 10),
)


class Inconclusive(RuntimeError):
    pass


def require(ok, detail):
    if not ok:
        raise ValueError(detail)


def check_case(name, mode, reserved, code, events):
    if name.startswith("refusal-"):
        expected_stage = "private_directory" if name == "refusal-missing" else "arena_arguments"
        require(code == 2 and len(events) == 1 and events[0]["status"] == "file_refused" and
                events[0]["stage"] == expected_stage and events[0]["native_errno"] > 0,
                f"{name} did not refuse before starting allocation")
        return {"status": "verified_refusal", **{k: events[0][k] for k in ("stage", "native_errno")}}
    if reserved and code == 2 and len(events) == 1 and events[0]["status"] == "file_refused":
        raise Inconclusive(f"{name} refused at {events[0]['stage']} (errno {events[0]['native_errno']})")
    require(code == 0 and len(events) == (2 if reserved else 1), f"{name} incomplete native lifecycle events")
    run = events[0]
    expected_mapped = {"heap": 0, "file": 7, "mixed": 2}[mode]
    require(run["status"] == "verified" and run["mode"] == mode and run["nodes"] == 8192 and
            run["pressure_mib"] == 0 and run["checksum"] == CHECKSUM and run["total_pool_chunks"] == 7 and
            run["arena_chunks"] == expected_mapped and run["anonymous_chunks"] == 7 - expected_mapped and
            run["all_pool_chunks_file_backed"] is (mode == "file"), f"{name} failed object integrity or backing-count checks")
    result = {key: run[key] for key in ("status", "nodes", "checksum", "total_pool_chunks", "arena_chunks", "anonymous_chunks")}
    if reserved:
        lifetime = events[1]
        require(lifetime["status"] == "lifecycle_verified" and lifetime["reserved_bytes"] == reserved and
                lifetime["physical_bytes"] >= reserved and all(lifetime[key] is True for key in LIFECYCLE_FLAGS),
                f"{name} failed APFS reservation or lifetime checks")
        result["native_lifecycle"] = lifetime
    return result


def run(binary, work):
    work.mkdir(mode=0o700)
    deadline = time.monotonic() + 75
    report = {"status": "in_progress", "scope": "8192-object native allocator lifecycle", "cases": []}
    try:
        for name, mode, reserved in CASES:
            scratch = work / f"scratch-{name}"
            if name != "refusal-missing":
                scratch.mkdir(mode=0o700)
            stdout, stderr = (work / f"{name}.{stream}.log" for stream in ("stdout", "stderr"))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(name, 75)
            with stdout.open("xb") as output, stderr.open("xb") as errors:
                process = subprocess.run([str(binary), mode, str(scratch)], stdout=output, stderr=errors,
                                         timeout=min(20, remaining), check=False)
            require(stdout.stat().st_size <= 8192, f"Unexpected lifecycle output size: {name}")
            require(not scratch.exists() or not any(scratch.iterdir()), f"Unexpected scratch pathname left by {name}")
            events = [json.loads(line) for line in stdout.read_bytes().splitlines()]
            result = check_case(name, mode, reserved, process.returncode, events)
            report["cases"].append({"case": name, **result})
        report["status"] = "verified"
    except Exception as error:
        report["status"] = "capacity_inconclusive" if isinstance(error, (Inconclusive, subprocess.TimeoutExpired)) else "failed"
        report["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        with (work / "result.json").open("x", encoding="utf-8") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
    print("Verified native file arena lifecycle, matching object integrity, and refusal paths.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.binary.resolve(strict=True), args.output.resolve())


if __name__ == "__main__":
    main()

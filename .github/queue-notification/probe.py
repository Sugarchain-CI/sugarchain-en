#!/usr/bin/env python3
"""Stage immutable native probe inputs and run the preregistered ABBA cases."""

import argparse
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import subprocess


SOURCE = "81934405da9cdfeca55c2a07997b881c22993bc6"
SPLIT_SOURCE = "356380b3cd87f754d67c1f14d4de567ae8590243"
HEADER_PATH = "src/util/ordered_check_window.h"
SINGLE_SHA = "818d7b60a606bc7b0c8c42094f135ef62cc3cee32d4fc2887d8c635a7a1c0b31"
SPLIT_SHA = "7dc11417f896d399c6cc433d6a1dae2c9bf0a0d764c5213d32ae27f3b9da7613"
FIXTURE_SHA = "b6457be0260ab00479ad4333cdfb387ff38bd0eab2d747c84593ecdc5db8de44"
PROOF_SHA = "0cc32fea1ef9ec5a61ef44a17d9ba9720f6ee3554ffa0ee14befaff16091628c"
COUNT = 8192
PARTICIPANTS = 8


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def rename_header(header, namespace):
    original_guard = b"BITCOIN_UTIL_ORDERED_CHECK_WINDOW_H"
    require(
        header.count(b"namespace util {") == 1
        and header.count(b"// namespace util") == 1
        and header.count(original_guard) == 3,
        "Unknown queue header shape",
    )
    return (
        header.replace(b"namespace util {", f"namespace {namespace} {{".encode())
        .replace(b"// namespace util", f"// namespace {namespace}".encode())
        .replace(original_guard, f"QUEUE_PROBE_{namespace.upper()}_H".encode())
    )


def git(cwd, *args):
    return subprocess.check_output(["git", "-C", str(cwd), *args])


def prepare(source, probe, work):
    work.mkdir(parents=True, exist_ok=False)
    require(git(source, "rev-parse", "HEAD").strip().decode() == SOURCE, "Unexpected canonical source commit")
    git(source, "diff", "--quiet", "HEAD", "--", HEADER_PATH, "src/crypto/yespower-1.0.1")
    single = git(source, "show", f"HEAD:{HEADER_PATH}")
    split = (probe / "ordered-check-window-split.h").read_bytes().replace(b"\r\n", b"\n")
    require(digest(single) == SINGLE_SHA, "Unexpected baseline header SHA-256")
    require(digest(split) == SPLIT_SHA, "Unexpected candidate header SHA-256")
    with gzip.open(probe / "headers-8192.bin.gz", "rb") as stream:
        fixture = stream.read(COUNT * 80 + 1)
    require(len(fixture) == COUNT * 80 and digest(fixture) == FIXTURE_SHA, "Unexpected Mainnet fixture")
    (work / "single-cv.h").write_bytes(rename_header(single, "single_cv"))
    (work / "split-cv.h").write_bytes(rename_header(split, "split_cv"))
    (work / "headers.bin").write_bytes(fixture)
    save(work / "inputs.json", {
        "canonical_source": SOURCE,
        "canonical_tree": git(source, "rev-parse", "HEAD^{tree}").strip().decode(),
        "single_header_sha256": SINGLE_SHA,
        "split_header_source": SPLIT_SOURCE,
        "split_header_sha256": SPLIT_SHA,
        "fixture_sha256": FIXTURE_SHA,
        "expected_ordered_proof_sha256": PROOF_SHA,
    })


def host_metadata(expected):
    system, machine = platform.system(), platform.machine().lower()
    if expected == "apple-arm64":
        require(system == "Darwin" and machine == "arm64", "A native Apple ARM64 process is required")
        translated = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "sysctl.proc_translated"], capture_output=True, text=True, check=False,
        )
        require(translated.returncode != 0 or translated.stdout.strip() == "0", "Rosetta is unavailable for this test")
        cpu = subprocess.check_output(["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
    elif expected == "windows-x64":
        require(system == "Windows" and machine in {"amd64", "x86_64"}, "A native Windows x64 process is required")
        from ctypes import POINTER, WinDLL, byref, c_int, c_uint16, c_void_p
        kernel = WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = c_void_p
        kernel.IsWow64Process2.argtypes = (c_void_p, POINTER(c_uint16), POINTER(c_uint16))
        kernel.IsWow64Process2.restype = c_int
        process, native = c_uint16(), c_uint16()
        ok = kernel.IsWow64Process2(c_void_p(kernel.GetCurrentProcess()), byref(process), byref(native))
        require(ok and process.value == 0 and native.value == 0x8664, "Windows process architecture mismatch")
        cpu = os.environ.get("PROCESSOR_IDENTIFIER") or platform.processor()
    else:
        raise RuntimeError(f"Unknown native platform {expected}")
    return {
        "system": system,
        "machine": machine,
        "release": platform.platform(),
        "cpu": cpu,
        "logical_cpus": os.cpu_count(),
        "runner_image": os.environ.get("ImageOS"),
        "runner_image_version": os.environ.get("ImageVersion"),
        "python": platform.python_version(),
    }


def check_trial(record, variant):
    require(record["variant"] == variant, "Unexpected queue variant in result")
    require(record["headers"] == COUNT, "Unexpected header count in result")
    require(record["participants"] == record["pending_limit"] == PARTICIPANTS, "Unexpected queue capacity")
    require(0 < record["caller_parallel_proofs"] < COUNT, "Missing caller participation")
    require(
        all(math.isfinite(record[key]) and record[key] > 0 for key in
            ("wall_seconds", "cpu_seconds", "serial_wall_seconds")),
        "Invalid measured duration",
    )
    require(record["serial_wall_seconds"] < record["wall_seconds"], "Invalid serial proof interval")


def run(expected, work):
    metadata = host_metadata(expected)
    binary = work / ("queue-proofs.exe" if expected == "windows-x64" else "queue-proofs")
    save(work / "host.json", metadata)
    require(digest((work / "headers.bin").read_bytes()) == FIXTURE_SHA, "Mainnet fixture changed before execution")
    result = {
        "host": metadata,
        "binary_sha256": digest(binary.read_bytes()),
        "order": ["single", "split", "split", "single"],
        "pair_requirements": {"maximum_wall_ratio": 0.95, "maximum_cpu_ratio": 1.03},
        "trials": [],
    }
    save(work / "results.json", result)
    reference = None
    for i, variant in enumerate(result["order"], 1):
        prefix = f"trial-{i}-{variant}"
        proof_file = work / f"{prefix}.proofs"
        stdout, stderr = work / f"{prefix}.json", work / f"{prefix}.stderr"
        with stdout.open("wb") as out, stderr.open("wb") as err:
            subprocess.run(
                [str(binary), variant, str(work / "headers.bin"), str(proof_file)],
                stdout=out, stderr=err, timeout=125, check=True,
            )
        record = json.loads(stdout.read_text(encoding="utf-8"))
        check_trial(record, variant)
        actual = proof_file.read_bytes()
        require(len(actual) == COUNT * 32 and digest(actual) == PROOF_SHA, f"Unexpected ordered proof output in {prefix}")
        if reference is None:
            reference = actual
        require(actual == reference, f"Different ordered proof output in {prefix}")
        record.update(trial=i, ordered_proof_sha256=digest(actual))
        result["trials"].append(record)
        save(work / "results.json", result)

    result["pairs"] = []
    for old_index, new_index in ((0, 1), (3, 2)):
        baseline, candidate = result["trials"][old_index], result["trials"][new_index]
        wall_ratio = candidate["wall_seconds"] / baseline["wall_seconds"]
        cpu_ratio = candidate["cpu_seconds"] / baseline["cpu_seconds"]
        result["pairs"].append({
            "baseline_trial": old_index + 1,
            "candidate_trial": new_index + 1,
            "wall_ratio": wall_ratio,
            "cpu_ratio": cpu_ratio,
            "meets_screen": wall_ratio <= 0.95 and cpu_ratio <= 1.03,
        })
    result["screen_pass"] = all(pair["meets_screen"] for pair in result["pairs"])
    save(work / "results.json", result)
    print(json.dumps({"platform": expected, "pairs": result["pairs"], "screen_pass": result["screen_pass"]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    stage = sub.add_parser("prepare")
    stage.add_argument("--source", type=Path, required=True)
    stage.add_argument("--probe", type=Path, required=True)
    measure = sub.add_parser("run")
    measure.add_argument("--platform", choices=("apple-arm64", "windows-x64"), required=True)
    for command in (stage, measure):
        command.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.source.resolve(), args.probe.resolve(), args.work.resolve())
    else:
        run(args.platform, args.work.resolve())


if __name__ == "__main__":
    main()

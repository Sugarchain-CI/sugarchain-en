#!/usr/bin/env python3
"""Build and run the isolated Windows block-index storage write guard."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import statistics
import subprocess
import sys

SOURCE_COMMIT = "9c502574b652804905d2533d51742ca91f694532"
SOURCE_TREE = "f44aa1b47f9701996046bbb396106f1d5c365e66"
LEVELDB_TREE = "2127174963e4df3aceec7a8d6fd14c04272d2e1e"
CRC32C_TREE = "28f07d0bd5d6fcd3273d9651ff3c960ad344c202"
ROWS = 1_048_576
ORDER = (1000, 10, 42, 42, 10, 1000)
BATCH = 32_768
REVIEW_RATIO = 1.05
WRITE_PHASES = ("ingest", "ingest_compaction", "status_rewrite", "rewrite_compaction", "close")
READ_PHASES = ("reopen", "verify_scan", "sentinels")


def output(*command):
    return subprocess.check_output(command, text=True).strip()


def select_visual_studio(generators, installations):
    names = {}
    for generator in generators:
        match = re.fullmatch(r"Visual Studio (\d+) \d{4}", generator["name"])
        if match and generator.get("platformSupport"):
            names[int(match[1])] = generator["name"]

    options = []
    for installation in installations:
        try:
            version = tuple(int(part) for part in installation["installationVersion"].split("."))
            location = installation["installationPath"]
        except (KeyError, AttributeError, ValueError):
            continue
        if version and version[0] >= 17 and version[0] in names and location:
            options.append((version, names[version[0]], location))

    if not options:
        raise RuntimeError(
            "No compatible Visual Studio x64 toolset and CMake generator. "
            "Use an up-to-date CMake that supports an installed Visual Studio 2022 or newer."
        )
    _, generator, location = max(options)
    return generator, location


def detect_visual_studio():
    installer = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    vswhere = installer / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not vswhere.is_file():
        available = shutil.which("vswhere.exe")
        if available is None:
            raise RuntimeError("Visual Studio Installer vswhere.exe was not found")
        vswhere = Path(available)
    installations = json.loads(subprocess.check_output(
        [str(vswhere), "-products", "*", "-prerelease", "-requires",
         "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-format", "json", "-utf8"],
        encoding="utf-8-sig",
    ))
    capabilities = json.loads(output("cmake", "-E", "capabilities"))
    return select_visual_studio(capabilities["generators"], installations)


def native(smoke):
    system, machine = platform.system(), platform.machine().lower()
    if system == "Windows":
        if machine not in ("amd64", "x86_64") or os.environ.get("PROCESSOR_ARCHITEW6432"):
            raise RuntimeError("Requires native Windows x86-64")
        generator, instance = detect_visual_studio()
        return generator, ["-A", "x64", f"-DCMAKE_GENERATOR_INSTANCE={instance}"], "Release/block-index-db-probe.exe"
    if system == "Linux" and smoke:
        return "Ninja", [], "block-index-db-probe"
    raise RuntimeError("Native Windows x86-64 is required, except for the small Linux smoke check")


def verify(data, max_open_files, rows):
    expected = {
        "workload": "synthetic index-shaped LevelDB status rewrites",
        "status": "verified",
        "cache_mib": 64,
        "block_cache_bytes": 32 * 2**20,
        "write_buffer_bytes": 16 * 2**20,
        "max_file_size_bytes": 32 * 2**20,
        "max_open_files": max_open_files,
        "small_table_cache": max_open_files != 1000,
        "table_cache_nominal_entries": max_open_files - 10,
        "rows": rows,
        "verified_index": rows,
        "verified_evidence": rows,
        "verified_sentinels": 10,
        "ingest_sync_writes": (rows + BATCH - 1) // BATCH,
        "status_rewrite_sync_writes": (rows + BATCH - 1) // BATCH,
    }
    for name, value in expected.items():
        if type(data.get(name)) is not type(value) or data[name] != value:
            raise ValueError(f"Unexpected {name}: {data.get(name)!r}; wanted {value!r}")
    if not re.fullmatch(r"[0-9a-f]{16}", data["ordered_fnv1a64"]):
        raise ValueError("Invalid ordered fingerprint")
    for phase in WRITE_PHASES + READ_PHASES:
        wall, cpu = data[f"{phase}_wall_seconds"], data[f"{phase}_cpu_ns"]
        if not math.isfinite(wall) or wall < 0 or type(cpu) is not int or cpu < 0:
            raise ValueError(f"Invalid timing for {phase}")
    data["write_guard_wall_seconds"] = sum(data[f"{phase}_wall_seconds"] for phase in WRITE_PHASES)
    data["write_guard_cpu_ns"] = sum(data[f"{phase}_cpu_ns"] for phase in WRITE_PHASES)
    if data["write_guard_wall_seconds"] <= 0 or data["write_guard_cpu_ns"] <= 0:
        raise ValueError("Empty write guard timing")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--parallel", type=int, default=2)
    parser.add_argument("--smoke", action="store_true", help="Use 65,537 rows for local correctness only")
    args = parser.parse_args()
    rows = BATCH * 2 + 1 if args.smoke else ROWS
    if not 1 <= args.parallel <= 4:
        parser.error("Use 1 to 4 build workers")
    generator, options, executable = native(args.smoke)

    root = args.output.resolve()
    root.mkdir(parents=True)
    build = root / "build"
    results = root / "evidence"
    results.mkdir()
    source = args.source.resolve(strict=True)
    scope = ("src/leveldb", "src/crc32c", "cmake/leveldb.cmake", "cmake/crc32c.cmake", "cmake/module")
    subprocess.run(["git", "-C", str(source), "diff", "--quiet", "HEAD", "--", *scope], check=True)
    repo = ["git", "-C", str(source), "rev-parse"]
    evidence = {
        "status": "in_progress",
        "source_commit": output(*repo, "HEAD"),
        "source_tree": output(*repo, "HEAD^{tree}"),
        "leveldb_tree": output(*repo, "HEAD:src/leveldb"),
        "crc32c_tree": output(*repo, "HEAD:src/crc32c"),
        "system": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cmake_generator": generator,
        "rows": rows,
        "order_max_open_files": ORDER,
        "leveldb_table_cache_lru_shards": 16,
        "smoke": args.smoke,
    }
    (results / "environment.json").write_text(json.dumps(evidence, indent=2) + "\n")
    build_commands = [
        ["cmake", "-S", str(Path(__file__).resolve().parent), "-B", str(build),
         "-G", generator, f"-DSUGARCHAIN_SOURCE={source}", "-DCMAKE_BUILD_TYPE=Release", *options],
        ["cmake", "--build", str(build), "--config", "Release", "--parallel", str(args.parallel)],
    ]
    evidence["measurements"] = []
    report = results / "result.json"
    try:
        evidence["phase"] = "preflight"
        expected_source = (SOURCE_COMMIT, SOURCE_TREE, LEVELDB_TREE, CRC32C_TREE)
        actual_source = tuple(evidence[k] for k in ("source_commit", "source_tree", "leveldb_tree", "crc32c_tree"))
        if actual_source != expected_source:
            raise RuntimeError("Unexpected audited source or vendor trees")
        if shutil.disk_usage(root).free < (1 if args.smoke else 4) * 2**30:
            raise RuntimeError("Insufficient disk space for isolated trial databases")
        evidence["phase"] = "build"
        with (results / "build.log").open("wb") as log:
            for command, timeout in zip(build_commands, (60, 180), strict=True):
                subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        binary = build / executable
        with binary.open("rb") as stream:
            evidence["binary_sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
        for index, max_open_files in enumerate(ORDER, 1):
            case = results / f"{index:02d}-open-{max_open_files}"
            evidence["phase"] = case.name
            with case.with_suffix(".log").open("wb") as log:
                subprocess.run([str(binary), str(case), str(max_open_files), str(rows)], check=True,
                               stdout=log, stderr=subprocess.STDOUT, timeout=75)
            data = json.loads((case / "result.json").read_text())
            verify(data, max_open_files, rows)
            if evidence["measurements"] and data["ordered_fnv1a64"] != evidence["measurements"][0]["ordered_fnv1a64"]:
                raise ValueError("Ordered reopen fingerprints differ across cache options")
            evidence["measurements"].append(data)
            report.write_text(json.dumps(evidence, indent=2) + "\n")
    except Exception as error:
        evidence["status"] = "failed"
        evidence["error"] = str(error)
        report.write_text(json.dumps(evidence, indent=2) + "\n")
        raise
    fields = ("write_guard_wall_seconds", "write_guard_cpu_ns", "status_rewrite_sync_p95_seconds",
              "reopen_wall_seconds", "verify_scan_wall_seconds", "peak_rss_bytes")
    measured = evidence["measurements"]
    evidence["summary"] = {}
    for first, last in ((0, 5), (1, 4), (2, 3)):
        evidence["summary"][str(ORDER[first])] = {
            field: {"trials": [measured[first][field], measured[last][field]],
                    "median": statistics.median([measured[first][field], measured[last][field]])}
            for field in fields
        }
    evidence["target_over_default_ratios"] = {
        field: [measured[target][field] / measured[control][field] for target, control in ((2, 0), (3, 5))]
        for field in ("write_guard_wall_seconds", "write_guard_cpu_ns")
    }
    if not args.smoke:
        evidence["write_guard_review_ratio"] = REVIEW_RATIO
        evidence["write_guard_review_signals"] = [
            field for field, ratios in evidence["target_over_default_ratios"].items()
            if all(ratio > REVIEW_RATIO for ratio in ratios)
        ]
    evidence.pop("phase")
    evidence["status"] = "verified_smoke" if args.smoke else "verified"
    report.write_text(json.dumps(evidence, indent=2) + "\n")
    print(report)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError:
        print("Inspect the build log and the retained per-case evidence", file=sys.stderr)
        raise

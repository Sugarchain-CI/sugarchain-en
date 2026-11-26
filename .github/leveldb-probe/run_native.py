#!/usr/bin/env python3
"""Build the native storage diagnostic and run its fixed cache-size sequence."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import statistics
import subprocess
import sys

DEFAULT_HEADERS = 1_048_576
ORDER = (2, 16, 64, 64, 16, 2)
BATCH = 32_768


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


def native():
    system, machine = platform.system(), platform.machine().lower()
    if system == "Darwin":
        translated = subprocess.run(
            ["sysctl", "-in", "sysctl.proc_translated"], text=True, capture_output=True
        ).stdout.strip()
        if machine != "arm64" or translated == "1":
            raise RuntimeError("Requires native Apple Silicon")
        return "Ninja", ["-DCMAKE_OSX_ARCHITECTURES=arm64"], "block-index-db-probe"
    if system == "Windows":
        if machine not in ("amd64", "x86_64") or os.environ.get("PROCESSOR_ARCHITEW6432"):
            raise RuntimeError("Requires native Windows x86-64")
        generator, instance = detect_visual_studio()
        return generator, ["-A", "x64", f"-DCMAKE_GENERATOR_INSTANCE={instance}"], "Release/block-index-db-probe.exe"
    if system == "Linux":
        return "Ninja", [], "block-index-db-probe"
    raise RuntimeError(f"Unsupported native platform: {system}")


def verify(data, cache, headers):
    expected = {
        "workload": "synthetic index-shaped LevelDB storage",
        "status": "verified",
        "cache_mib": cache,
        "block_cache_bytes": cache * 2**19,
        "write_buffer_bytes": cache * 2**18,
        "headers": headers,
        "verified_records": 2 * headers,
        "sync_writes": (headers + BATCH - 1) // BATCH,
    }
    for name, value in expected.items():
        if data.get(name) != value:
            raise ValueError(f"Unexpected {name}: {data.get(name)!r}; wanted {value!r}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--headers", type=int, default=DEFAULT_HEADERS)
    parser.add_argument("--parallel", type=int, default=2)
    parser.add_argument("--smoke", action="store_true", help="Run small schema and restart checks only")
    args = parser.parse_args()
    if args.smoke:
        headers = BATCH * 2 + 1
        order = (2, 16, 64)
    else:
        if not 1_000_000 < args.headers <= 8_388_608:
            parser.error("Require more than one million and at most 8,388,608 headers")
        headers, order = args.headers, ORDER
    if not 1 <= args.parallel <= 8:
        parser.error("Use 1 to 8 build workers")
    generator, options, executable = native()

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
        "headers": headers,
        "order": order,
        "smoke": args.smoke,
    }
    (results / "environment.json").write_text(json.dumps(evidence, indent=2) + "\n")
    build_commands = [
        ["cmake", "-S", str(Path(__file__).resolve().parent), "-B", str(build),
         "-G", generator, f"-DSUGARCHAIN_SOURCE={source}", "-DCMAKE_BUILD_TYPE=Release", *options],
        ["cmake", "--build", str(build), "--config", "Release", "--parallel", str(args.parallel)],
    ]
    with (results / "build.log").open("wb") as log:
        for command in build_commands:
            subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)

    binary = build / executable
    with binary.open("rb") as stream:
        evidence["binary_sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
    evidence["measurements"] = []
    report = results / "result.json"
    for index, cache in enumerate(order, 1):
        case = results / f"{index:02d}-{cache}MiB"
        subprocess.run([str(binary), str(case), str(cache), str(headers)], check=True)
        data = json.loads((case / "result.json").read_text())
        verify(data, cache, headers)
        evidence["measurements"].append(data)
        report.write_text(json.dumps(evidence, indent=2) + "\n")
    evidence["status"] = "verified"
    evidence["median"] = {
        str(cache): {
            field: statistics.median(row[field] for row in evidence["measurements"] if row["cache_mib"] == cache)
            for field in (
                "ingest_seconds", "sync_write_seconds_sum", "sync_write_p95_seconds",
                "forced_compaction_seconds", "peak_ingest_rss_bytes", "peak_total_rss_bytes",
            )
        }
        for cache in (2, 16, 64)
    }
    report.write_text(json.dumps(evidence, indent=2) + "\n")
    print(report)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError:
        print("Inspect the build log and the retained per-case evidence", file=sys.stderr)
        raise

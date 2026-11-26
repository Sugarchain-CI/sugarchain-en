#!/usr/bin/env python3
"""Compare exact native Windows release binaries on a fixed Mainnet header prefix."""

import argparse
import gzip
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import statistics
import struct
import time
from types import SimpleNamespace

from mainnet_paired import BATCH, compact_size, hash256, message
from windows_cold_proof import GENESIS, WindowsTimes, decode_headers, digest, persist, replay


BASELINE_SOURCE = "81934405da9cdfeca55c2a07997b881c22993bc6"
BASELINE_TREE = "b921f383b962f3c27164c9b2f9740e1a235e142d"
BASELINE = {
    "msvcrt": {
        "manifest": "11718bc28a45af5ab2aefd0aebb6be7eb8d3959667371611ae6bfc8dfb0f634d",
        "cli": "86fde9a2d883f7df0bad95dcc4f15247d46adea212427fad7d0116b7f7ba9476",
        "gui": "898c593f2026440992017ace3085e758d9138404d9436b0a561f5addb66b01a0",
    },
    "ucrt": {
        "manifest": "c9a24456b0eeecc1cb2b2a6e95bb915b11f82bf2d1eace802f10a0a7c2173e33",
        "cli": "1b69988443da2684e156be5f4784fcc2cad5568c05a862ee20da5802fded9d36",
        "gui": "c64c15d7c42d436ab2e276f8d1061f44ca12f551a9c151f53c084a989ccee828",
    },
}
BINARIES = {"cli": "bin/sugarchaind.exe", "gui": "bin/sugarchain-qt.exe"}
BUILD_MARKERS = {"source": "release-source-sha.txt", "tree": "release-source-tree.txt"}
MANIFEST = "SHA256SUMS.release-inputs"

ARCHIVE_SHA = "1d6b46da12f732190804a276b0c457d3c0ff923733ba29294f826eea971664ce"
COUNT = 50_000
PREFIX_SHA = "56067df408db5d0b1607671ad91c6a2bb267b69c95d7bd66ed2e0786f6f7b2b8"
TIP = "89014795f54676c2a4db8663d114e7c818950f4b3fe45c6d2de63ab9cc0aa945"

WORKERS = 8
CASE_LIMIT = 180
INTERFACE_LIMIT = 750
ORDER = ("baseline", "candidate", "candidate", "baseline")
MIN_GAIN = 0.05
CPU_LIMIT = 1.03


def require_amd64_pe(path):
    with path.open("rb") as file:
        dos = file.read(64)
        if len(dos) != 64 or dos[:2] != b"MZ":
            raise ValueError(f"Invalid Windows executable: {path.name}")
        pe_offset, = struct.unpack_from("<I", dos, 60)
        file.seek(pe_offset)
        header = file.read(26)
    if len(header) != 26 or header[:6] != b"PE\0\0\x64\x86" or header[24:26] != b"\x0b\x02":
        raise ValueError(f"Expected an AMD64 PE32+ release executable: {path.name}")


def verify_artifact(root, binary_name, source, tree, *, fixed=None):
    root = root.resolve(strict=True)
    manifest = root / MANIFEST
    manifest_sha = digest(manifest)
    if fixed and manifest_sha != fixed["manifest"]:
        raise ValueError("Baseline manifest SHA-256 differs from the pinned artifact")

    verified = {}
    names = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([A-Za-z0-9_./-]+)", line)
        if not match:
            raise ValueError("Malformed package manifest record")
        expected, name = match.groups()
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != name or name.casefold() in names:
            raise ValueError("Unsafe or duplicate package manifest path")
        names.add(name.casefold())
        file = (root / relative).resolve(strict=True)
        if not file.is_relative_to(root) or not file.is_file() or digest(file) != expected:
            raise ValueError(f"Invalid package manifest entry: {name}")
        verified[name] = expected

    for label, expected in (("source", source), ("tree", tree)):
        marker = BUILD_MARKERS[label]
        if marker not in verified or (root / marker).read_text(encoding="ascii").strip() != expected:
            raise ValueError(f"Artifact {label} does not match the expected build")
    if binary_name not in verified:
        raise ValueError(f"Artifact omits {binary_name}")
    if fixed and verified[binary_name] != fixed["binary"]:
        raise ValueError("Baseline executable SHA-256 differs from the pinned artifact")

    binary = root / binary_name
    require_amd64_pe(binary)
    return binary, {
        "source_sha": source, "source_tree": tree, "binary": binary_name,
        "binary_sha256": verified[binary_name], "manifest_sha256": manifest_sha,
        "manifest_verified_files": len(verified), "machine": "AMD64 PE32+",
    }


def fixture(archive):
    if digest(archive) != ARCHIVE_SHA:
        raise ValueError("Mainnet fixture archive does not match the pinned SHA-256")
    with gzip.open(archive, "rb") as file:
        prefix = file.read(COUNT * 80)
    headers, tip = decode_headers(prefix, PREFIX_SHA, COUNT)
    if tip != TIP:
        raise ValueError("Mainnet prefix final hash differs from the pinned tip")
    hashes = [bytes.fromhex(GENESIS)[::-1]]
    frames = []
    for start in range(0, COUNT, BATCH):
        batch = headers[start:start + BATCH]
        hashes.append(hash256(batch[-1]))
        frames.append(message(b"headers", compact_size(BATCH) + b"".join(header + b"\0" for header in batch)))
    return frames, hashes


def score(rows):
    if tuple(row["label"] for row in rows) != ORDER:
        raise ValueError("Expected four samples in ABBA order")
    for row in rows:
        if (row["workers"] != WORKERS or row["presynced_headers"] != COUNT or row["last_presynced_hash"] != TIP
                or row["admitted_headers"] != 0 or row["active_blocks"] != 0 or not row["clean_exit"]
                or len(row["batch_seconds"]) != COUNT // BATCH):
            raise ValueError("A sample failed the common Mainnet proof workload")
        times = (row["wall_seconds"], row["process_cpu_seconds"], *row["batch_seconds"])
        if any(not math.isfinite(value) or value <= 0 for value in times):
            raise ValueError("A sample contains invalid timing results")

    pairs = []
    for baseline, candidate in ((rows[0], rows[1]), (rows[3], rows[2])):
        wall_ratio = candidate["wall_seconds"] / baseline["wall_seconds"]
        cpu_ratio = candidate["process_cpu_seconds"] / baseline["process_cpu_seconds"]
        pairs.append({
            "baseline_sample": baseline["sample"], "candidate_sample": candidate["sample"],
            "wall_gain_percent": 100 * (1 - wall_ratio), "candidate_to_baseline_cpu": cpu_ratio,
            "passes": wall_ratio <= 1 - MIN_GAIN and cpu_ratio <= CPU_LIMIT,
        })

    summary = {}
    for label in ("baseline", "candidate"):
        keys = ("wall_seconds", "headers_per_second", "process_cpu_seconds", "other_host_cpu_core_equivalents")
        summary[label] = {key: statistics.median(row[key] for row in rows if row["label"] == label) for key in keys}
    return {"pairs": pairs, "medians": summary, "passes": all(pair["passes"] for pair in pairs)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crt", required=True, choices=BASELINE)
    parser.add_argument("--interface", required=True, choices=BINARIES)
    parser.add_argument("--baseline-root", required=True, type=Path)
    parser.add_argument("--candidate-root", required=True, type=Path)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--candidate-tree", required=True)
    parser.add_argument("--headers-gz", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not all(re.fullmatch(r"[0-9a-f]{40}", value) for value in (args.candidate_sha, args.candidate_tree)):
        parser.error("Candidate source and tree require full lowercase Git object IDs")
    if args.candidate_sha == BASELINE_SOURCE or args.candidate_tree == BASELINE_TREE:
        parser.error("Candidate build must differ from the pinned baseline source and tree")
    if args.interface == "gui" and (os.environ.get("GITHUB_ACTIONS") != "true"
                                    or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        parser.error("GUI profile reset requires a disposable GitHub-hosted runner")

    interface_deadline = time.monotonic() + INTERFACE_LIMIT
    output = args.output.resolve()
    output.mkdir(parents=True)
    result_file = output / "result.json"
    report = {
        "status": "running", "scope": "Native Windows cold Mainnet header presync", "crt": args.crt,
        "interface": args.interface, "order": ORDER, "workers": WORKERS, "case_limit_seconds": CASE_LIMIT,
        "interface_limit_seconds": INTERFACE_LIMIT,
        "screen": {"minimum_paired_wall_gain_percent": 100 * MIN_GAIN, "maximum_paired_cpu_ratio": CPU_LIMIT},
        "host": {"platform": platform.platform(), "machine": platform.machine(),
                 "logical_cpus": os.cpu_count(), "processor": os.environ.get("PROCESSOR_IDENTIFIER"),
                 "runner_image": os.environ.get("ImageOS"), "image_version": os.environ.get("ImageVersion")},
        "fixture": {"count": COUNT, "batch": BATCH, "genesis": GENESIS, "tip": TIP,
                    "archive_sha256": ARCHIVE_SHA, "prefix_sha256": PREFIX_SHA},
        "results": [],
    }
    persist(result_file, report)
    current_sample = None
    try:
        sampler = WindowsTimes()
        binary_name = BINARIES[args.interface]
        pin = BASELINE[args.crt]
        baseline, baseline_artifact = verify_artifact(
            args.baseline_root, binary_name, BASELINE_SOURCE, BASELINE_TREE,
            fixed={"manifest": pin["manifest"], "binary": pin[args.interface]},
        )
        candidate, candidate_artifact = verify_artifact(args.candidate_root, binary_name, args.candidate_sha, args.candidate_tree)
        if baseline_artifact["binary_sha256"] == candidate_artifact["binary_sha256"]:
            raise ValueError("Candidate executable is byte-identical to the baseline")
        report["artifacts"] = {"baseline": baseline_artifact, "candidate": candidate_artifact}
        frames, hashes = fixture(args.headers_gz.resolve(strict=True))
        programs = {"baseline": baseline, "candidate": candidate}
        for sample, label in enumerate(ORDER, 1):
            now = time.monotonic()
            if now >= interface_deadline:
                raise TimeoutError("Interface benchmark deadline expired")
            current_sample = f"{sample:02d}-{label}"
            options = SimpleNamespace(binary=programs[label], gui=args.interface == "gui", count=COUNT, timeout=CASE_LIMIT)
            row = replay(options, output / current_sample, frames, hashes, WORKERS, sampler,
                         case_deadline=min(now + CASE_LIMIT, interface_deadline))
            row.update(sample=sample, label=label, clean_exit=True, trial_seconds=time.monotonic() - now)
            report["results"].append(row)
            persist(result_file, report)
            print(f"{args.crt}/{args.interface} {current_sample}: {row['wall_seconds']:.3f} s, "
                  f"CPU {row['process_cpu_seconds']:.3f} s, {row['headers_per_second']:.1f} headers/s", flush=True)
        report["comparison"] = score(report["results"])
        report["status"] = "complete"
        persist(result_file, report)
        print("Performance screen " + ("passed" if report["comparison"]["passes"] else "missed"), flush=True)
    except Exception as error:
        report["status"] = "failed"
        report["error"] = {"type": type(error).__name__, "message": str(error)[:400], "sample": current_sample}
        persist(result_file, report)
        raise


if __name__ == "__main__":
    main()

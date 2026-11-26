#!/usr/bin/env python3
"""Compare native Mainnet automatic IBD request ceilings against En.7."""

import argparse
import asyncio
import ctypes
from ctypes import wintypes
import hashlib
import math
import os
from pathlib import Path
import platform
import statistics
import struct
import subprocess
from types import SimpleNamespace

from mainnet_delivery import NODE_COUNT, Resources, block_geometry, get_fixture, measure_case, persist
from mainnet_probe import check_host
from mainnet_warm import make_batch


class WindowsMemoryStatus(ctypes.Structure):
    _fields_ = [("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD)] + [
        (name, ctypes.c_uint64) for name in (
            "ullTotalPhys", "ullAvailPhys", "ullTotalPageFile", "ullAvailPageFile",
            "ullTotalVirtual", "ullAvailVirtual", "ullAvailExtendedVirtual",
        )
    ]


def detected_physical_ram(resources):
    if os.name == "nt":
        get_memory = resources.kernel.GlobalMemoryStatusEx
        get_memory.argtypes = [ctypes.POINTER(WindowsMemoryStatus)]
        get_memory.restype = wintypes.BOOL
        status = WindowsMemoryStatus(dwLength=ctypes.sizeof(WindowsMemoryStatus))
        return status.ullTotalPhys if get_memory(ctypes.byref(status)) else None
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGESIZE")
    except (AttributeError, OSError, ValueError):
        return None
    return pages * page_size if pages > 0 and page_size > 0 else None


def expected_candidate_default(system, architecture, ram):
    supported = (system == "Windows" and architecture in ("amd64", "x86_64")) or (
        system == "Darwin" and architecture == "arm64"
    )
    if supported and ram is not None:
        if ram >= 8 << 30:
            return 128
        if ram >= 4 << 30:
            return 64
    return 16


def open_executable(path, expected_sha, system, architecture):
    path = path.resolve(strict=True)
    with path.open("rb") as stream:
        actual_sha = hashlib.file_digest(stream, "sha256").hexdigest()
        if expected_sha is not None and actual_sha != expected_sha:
            raise ValueError(f"Executable checksum differs for {path.name}")
        if system == "Windows":
            stream.seek(0x3C)
            offset = stream.read(4)
            if len(offset) != 4:
                raise ValueError(f"Invalid PE header for {path.name}")
            stream.seek(struct.unpack("<I", offset)[0])
            if stream.read(6) != b"PE\x00\x00\x64\x86":
                raise ValueError(f"Expected native Windows AMD64 executable {path.name}")
    if system == "Darwin":
        arches = subprocess.check_output(["lipo", "-archs", str(path)], text=True).split()
        if architecture not in arches:
            raise ValueError(f"Executable does not contain the native {architecture} slice: {path.name}")
    return path, actual_sha


async def run(options):
    check_host()
    resources = Resources()
    system = platform.system()
    architecture = platform.machine().lower()
    ram = detected_physical_ram(resources)
    baseline, baseline_sha = open_executable(options.baseline, options.baseline_sha256, system, architecture)
    candidate, candidate_sha = open_executable(options.candidate, options.candidate_sha256, system, architecture)
    candidate_cap = expected_candidate_default(system, architecture, ram)
    if (system == "Windows" or system == "Darwin") and baseline_sha == candidate_sha:
        raise ValueError("The released baseline and native candidate must be distinct executables")
    fixture, headers, blocks = get_fixture(options.fixture, options.fixture_info)
    header_batch = make_batch("submitheader", [header.hex() for header in headers])
    output = options.output.resolve()
    output.mkdir(parents=True)

    available_cases = {
        "baseline-default": (baseline, baseline_sha, None, 16),
        "candidate-default": (candidate, candidate_sha, None, candidate_cap),
        "candidate-explicit-16": (candidate, candidate_sha, 16, 16),
    }
    order = []
    if "default" in options.limits:
        order.extend(("baseline-default", "candidate-default", "candidate-default", "baseline-default"))
    if "16" in options.limits:
        order.append("candidate-explicit-16")
    cases = {case: available_cases[case] for case in dict.fromkeys(order)}
    result_path = output / "result.json"
    report = {
        "scope": "Native Mainnet fixture, loopback P2P body transport, same-host ABBA comparison",
        "mode": "gui" if options.gui else "cli",
        "measurement": "Body transport through exact block-tip acceptance; startup, header priming and restart are excluded",
        "test_minimumchainwork_override": "0 for isolated fixture admission only",
        "assumevalid": 0, "peer_count": NODE_COUNT, "injected_delay_ms": options.latency_ms,
        "host": {
            "platform": platform.platform(), "machine": architecture, "logical_cpus": os.cpu_count(),
            "cpu": os.environ.get("PROCESSOR_IDENTIFIER") or platform.processor(), "detected_ram_bytes": ram,
        },
        "binary_sha256": {"baseline": baseline_sha, "candidate": candidate_sha},
        "expected_candidate_default": candidate_cap, "fixture": fixture, "block_geometry": block_geometry(blocks),
        "order": order, "samples": [],
    }
    persist(result_path, report)
    for index, case in enumerate(order, 1):
        binary, sha, request_limit, expected_ceiling = cases[case]
        trial = SimpleNamespace(binary=binary, gui=options.gui, timeout=options.timeout, latency_ms=options.latency_ms)
        print(f"Sample {index}, {case}: priming the fixed Mainnet header fixture", flush=True)
        row = await measure_case(
            trial, output / f"{index:02d}-{case}", fixture, headers, blocks, header_batch, expected_ceiling, resources,
            request_limit=request_limit, verify_restart=True, require_wire_ceiling=True,
        )
        row.update(case=case, binary_sha256=sha)
        report["samples"].append(row)
        persist(result_path, report)
        print(f"Sample {index}, {case}: {row['seconds']:.3f}s, {row['node_cpu_seconds']:.3f}s CPU, "
              f"{row['wire_peak_pending_per_peer']} peak wire requests per peer, restart verified", flush=True)
    report["medians"] = {
        case: {
            field: statistics.median(row[field] for row in report["samples"] if row["case"] == case)
            for field in ("seconds", "node_cpu_seconds", "sampled_peak_rss_bytes", "wire_peak_pending_per_peer")
        }
        for case in cases
    }
    for path, digest in ((baseline, baseline_sha), (candidate, candidate_sha)):
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise ValueError(f"Executable changed during comparison: {path.name}")
    report["complete"] = True
    persist(result_path, report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--baseline-sha256")
    parser.add_argument("--candidate-sha256")
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--fixture-info", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--limits", choices=("default", "16"), nargs="+", default=("default", "16"),
                        help="Run the default ABBA comparison and the candidate explicit-16 control by default")
    parser.add_argument("--latency-ms", default=100.0, type=float)
    parser.add_argument("--timeout", default=95.0, type=float)
    options = parser.parse_args()
    if not math.isfinite(options.latency_ms) or not 0 <= options.latency_ms <= 1000:
        parser.error("Use a finite injected response delay between 0 and 1,000 milliseconds")
    if not math.isfinite(options.timeout) or options.timeout <= 0:
        parser.error("Use a positive finite startup and phase timeout")
    asyncio.run(run(options))


if __name__ == "__main__":
    main()

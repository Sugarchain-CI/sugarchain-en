#!/usr/bin/env python3
"""Test ordinary and 64 KiB hinted Windows scratch pages on pinned Mainnet headers."""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import struct
import subprocess


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def native_host():
    if os.name != "nt":
        raise ValueError("Native AMD64 Windows is required")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    wow = kernel32.IsWow64Process2
    wow.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.USHORT), ctypes.POINTER(wintypes.USHORT)]
    wow.restype = wintypes.BOOL
    process, host = wintypes.USHORT(), wintypes.USHORT()
    if not wow(kernel32.GetCurrentProcess(), ctypes.byref(process), ctypes.byref(host)):
        raise ctypes.WinError(ctypes.get_last_error())
    if process.value or host.value != 0x8664 or hasattr(ctypes.WinDLL("ntdll"), "wine_get_version"):
        raise ValueError("Native AMD64 Windows is required")
    if os.cpu_count() != 4:
        raise ValueError("Expected a native runner exposing exactly four logical CPUs")
    return {"platform": platform.platform(), "cpu": os.environ.get("PROCESSOR_IDENTIFIER"), "logical_cpus": 4}


def native_executable(path):
    path = path.resolve(strict=True)
    with path.open("rb") as stream:
        stream.seek(0x3c)
        stream.seek(struct.unpack("<I", stream.read(4))[0])
        if stream.read(6) != b"PE\0\0\x64\x86":
            raise ValueError(f"Not a native AMD64 PE executable: {path.name}")
    return path


def run_probe(executable, input_path, root, workers, mode, timeout):
    root.mkdir()
    proof_path = root / "proof-digests.bin"
    report_path = root / "probe.json"
    with report_path.open("wb") as stdout, (root / "probe.log").open("wb") as stderr:
        subprocess.run([str(executable), str(input_path), str(proof_path), str(workers), mode],
                       check=True, timeout=timeout, stdout=stdout, stderr=stderr, creationflags=subprocess.CREATE_NO_WINDOW)
    report = json.loads(report_path.read_bytes())
    count = input_path.stat().st_size // 80
    if (report.get("mode") != mode or report["workers"] != workers or report["proofs"] != count
            or len(report["scratch"]) != workers or not math.isfinite(report["seconds"]) or report["seconds"] <= 0
            or proof_path.stat().st_size != count * 32):
        raise ValueError(f"Invalid native probe result: {root.name}")
    with proof_path.open("rb") as stream:
        report["leading_512_proof_sha256"] = hashlib.sha256(stream.read(512 * 32)).hexdigest()
    report["proof_sha256"] = digest(proof_path)
    return report


def persist(path, report):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def allocation_status(report):
    mode = report["mode"]
    tries_hint = mode == "page64"
    expects_fallback = mode == "page64-fallback"
    api = report["virtualalloc2"]
    available = api["available"]
    if (api["lookup_attempted"] is not tries_hint or type(available) is not bool
            or (available != (api["module"] in ("kernel32.dll", "kernelbase.dll")))
            or (available and not tries_hint)):
        raise ValueError(f"Inconsistent VirtualAlloc2 resolution evidence for {mode}")
    for row in report["scratch"]:
        accepted, fell_back = row["hint_successes"], row["hint_fallbacks"]
        if (row["allocation_calls"] != 1 or row["base_size"] <= 0 or row["allocation_seconds"] < 0
                or (mode != "malloc" and row["base_size"] % 65536)
                or (accepted + fell_back != int(tries_hint or expects_fallback))
                or row["hint_attempts"] != int(tries_hint and available)
                or (accepted and (not available or row["hint_error"]))):
            raise ValueError(f"Unexpected allocation evidence for {mode}")
    if not tries_hint:
        return "control"
    if not available:
        return "inconclusive_api_unavailable"
    accepted = sum(row["hint_successes"] for row in report["scratch"])
    if accepted == report["workers"]:
        return "accepted"
    return "inconclusive_partial_allocation" if accepted else "inconclusive_allocation_rejected"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--page-probe", type=Path, required=True)
    parser.add_argument("--reference-probe", type=Path, required=True)
    parser.add_argument("--abi-probe", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--headers", type=Path, required=True)
    parser.add_argument("--headers-sha256", required=True)
    parser.add_argument("--leading-512-proof-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=100)
    args = parser.parse_args()
    host = native_host()
    page_probe = native_executable(args.page_probe)
    reference = native_executable(args.reference_probe)
    abi = native_executable(args.abi_probe)
    executable_digests = {path.name: digest(path) for path in (page_probe, reference, abi)}
    recorded = [line.split() for line in args.manifest.read_text(encoding="ascii").splitlines()]
    if len(recorded) != 3 or any(len(row) != 2 for row in recorded) or (
        {name: checksum for checksum, name in recorded} != executable_digests
    ):
        raise ValueError("Native test executable digests differ from the cross-compile manifest")
    headers = args.headers.resolve(strict=True)
    if headers.stat().st_size != 16384 * 80 or digest(headers) != args.headers_sha256:
        raise ValueError("Unexpected pinned Mainnet header fixture")
    output = args.output.resolve()
    output.mkdir(parents=True)
    smoke_headers = output / "headers-512.bin"
    with headers.open("rb") as stream:
        smoke_headers.write_bytes(stream.read(512 * 80))

    report_path = output / "result.json"
    report = {
        "host": host, "headers_sha256": args.headers_sha256, "proofs_per_sample": 16384, "workers": 8,
        "binary_sha256": executable_digests,
        "measurement": "Yespower wall time after allocating and warming independent worker scratch",
        "page_hint": "VirtualAlloc2 success does not establish physical page size",
        "status": "running", "correctness": {}, "samples": [],
    }
    for label, executable, mode in [
        ("reference", reference, "as-built"), ("private-abi", abi, "as-built"),
        ("forced-page64-fallback", page_probe, "page64-fallback"),
        ("page64-readiness", page_probe, "page64"),
    ]:
        row = run_probe(executable, smoke_headers, output / label, 8, mode, args.timeout)
        if row["proof_sha256"] != args.leading_512_proof_sha256:
            raise ValueError(f"Proof digest differs from the independent baseline: {label}")
        if executable == page_probe:
            row["allocation_status"] = allocation_status(row)
        report["correctness"][label] = row
        persist(report_path, report)
    readiness = report["correctness"]["page64-readiness"]
    print(f"VirtualAlloc2 readiness: {readiness['allocation_status']}, {readiness['virtualalloc2']}; "
          f"allocation errors: {[row['hint_error'] for row in readiness['scratch']]}", flush=True)
    if readiness["allocation_status"] != "accepted":
        report["status"] = readiness["allocation_status"]
        report["complete"] = True
        persist(report_path, report)
        return
    order = ("malloc", "pages", "page64", "page64", "pages", "malloc")
    for index, mode in enumerate(order, 1):
        row = run_probe(page_probe, headers, output / f"{index:02d}-{mode}", 8, mode, args.timeout)
        if row["leading_512_proof_sha256"] != args.leading_512_proof_sha256 or (
            report["samples"] and row["proof_sha256"] != report["samples"][0]["proof_sha256"]
        ):
            raise ValueError(f"Proof digest differs: sample {index}, {mode}")
        row["allocation_status"] = allocation_status(row)
        report["samples"].append(row)
        persist(report_path, report)
        print(f"{index} {mode}: {row['proofs_per_second']:.1f} proofs/s, "
              f"{sum(item['hint_successes'] for item in row['scratch'])} accepted hints", flush=True)
        if mode == "page64" and row["allocation_status"] != "accepted":
            report["status"] = row["allocation_status"]
            report["complete"] = True
            persist(report_path, report)
            print("Page hint became unavailable during timing. No comparable throughput medians.", flush=True)
            return
    report["medians_proofs_per_second"] = {
        mode: statistics.median(item["proofs_per_second"] for item in report["samples"] if item["mode"] == mode)
        for mode in dict.fromkeys(order)
    }
    report["complete"] = True
    report["status"] = "measured"
    persist(report_path, report)


if __name__ == "__main__":
    main()

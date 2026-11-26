#!/usr/bin/env python3
"""Compare 4 and 8 workers with the signed Windows release and a fixed mainnet prefix."""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import socket
import statistics
import time
from types import SimpleNamespace

from mainnet_paired import BATCH, compact_size, hash256, message, version_payload, wait_for
from mainnet_probe import node, rpc

GENESIS = "7d5eaec2dbb75f99feadfa524c78b7cabc1d8c8204f79d4f3a83381b811b0adc"
DAEMONS = {
    "ucrt": "dd42ac39df4f52605751c610383432c81c497b44103912f90527bcd29c03da2a",
    "msvcrt": "e5ad7945b13e38d93a512287d6cfeca125da6546f0404b655e95c3b7d55c37a4",
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_headers(path, expected_hash, count):
    return decode_headers(path.read_bytes(), expected_hash, count)


def decode_headers(data, expected_hash, count):
    if len(data) != count * 80:
        raise ValueError("Expected an exact consecutive mainnet prefix of 80-byte headers")
    if hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError("Mainnet header fixture checksum differs")
    previous = bytes.fromhex(GENESIS)[::-1]
    headers = []
    for offset in range(0, len(data), 80):
        header = data[offset:offset + 80]
        if header[4:36] != previous:
            raise ValueError(f"Header continuity differs at height {offset // 80 + 1}")
        previous = hash256(header)
        headers.append(header)
    return headers, previous[::-1].hex()


class WindowsTimes:
    def __init__(self):
        if platform.system() != "Windows":
            raise RuntimeError("This CPU-time sampler requires native Windows")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.GetCurrentProcess.restype = wintypes.HANDLE
        self.kernel.IsWow64Process2.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.USHORT), ctypes.POINTER(wintypes.USHORT)]
        self.kernel.IsWow64Process2.restype = wintypes.BOOL
        self.kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
        self.kernel.GetProcessTimes.restype = wintypes.BOOL
        self.kernel.GetSystemTimes.argtypes = [ctypes.POINTER(wintypes.FILETIME)] * 3
        self.kernel.GetSystemTimes.restype = wintypes.BOOL
        process, host = wintypes.USHORT(), wintypes.USHORT()
        if not self.kernel.IsWow64Process2(self.kernel.GetCurrentProcess(), ctypes.byref(process), ctypes.byref(host)):
            raise ctypes.WinError(ctypes.get_last_error())
        if process.value != 0 or host.value != 0x8664 or hasattr(ctypes.WinDLL("ntdll"), "wine_get_version"):
            raise RuntimeError("The test must run directly on native Windows AMD64")

    @staticmethod
    def seconds(filetime):
        return ((filetime.dwHighDateTime << 32) | filetime.dwLowDateTime) / 10_000_000

    def snapshot(self, proc):
        created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
        # The subprocess owns this handle for the duration of the sample.
        handle = wintypes.HANDLE(int(proc._handle))
        if not self.kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in (created, exited, kernel, user))):
            raise ctypes.WinError(ctypes.get_last_error())
        system_idle, system_kernel, system_user = (wintypes.FILETIME() for _ in range(3))
        if not self.kernel.GetSystemTimes(*(ctypes.byref(value) for value in (system_idle, system_kernel, system_user))):
            raise ctypes.WinError(ctypes.get_last_error())
        return {
            "process_user": self.seconds(user), "process_kernel": self.seconds(kernel),
            "system_idle": self.seconds(system_idle), "system_kernel": self.seconds(system_kernel),
            "system_user": self.seconds(system_user),
        }


def delta(before, after):
    return {key: after[key] - value for key, value in before.items()}


def get_capacity(cpu, elapsed, count):
    active = cpu["process_user"] + cpu["process_kernel"]
    system = cpu["system_kernel"] + cpu["system_user"]
    busy = system - cpu["system_idle"]
    other = max(0, busy - active)
    if not all(math.isfinite(value) and value > 0 for value in (elapsed, active, system)):
        raise RuntimeError("Invalid process or host timing sample")
    return {
        "wall_seconds": elapsed, "headers_per_second": count / elapsed,
        "process_cpu_seconds": active, "cpu_seconds_per_header": active / count,
        "average_active_cpu_cores": active / elapsed,
        "other_host_cpu_core_equivalents": other / elapsed,
        "host_busy_percent": 100 * busy / system,
        "cpu_windows_seconds": cpu,
    }


def replay(args, folder, frames, hashes, workers, sampler, *, case_deadline=None):
    directory = folder / "node"
    folder.mkdir()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(args.timeout)
        peer_port = listener.getsockname()[1]
        flags = (
            f"-connect=127.0.0.1:{peer_port}", "-v2transport=0", "-dnsseed=0", "-fixedseeds=0", "-dns=0",
            f"-parpow={workers}", "-assumevalid=0", "-maxpowcache=16",
        )
        if case_deadline is not None:
            # Leave time for the three audit RPCs and the owned process's shutdown.
            deadline = case_deadline - 16
        with node(args, directory, "presync", extra_flags=flags, clean_exit_deadline=case_deadline) as (proc, port, _):
            if case_deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("No time left for the P2P sample")
                listener.settimeout(remaining)
            connection, _ = listener.accept()
            with connection:
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                if case_deadline is None:
                    deadline = time.monotonic() + args.timeout
                wait_for(connection, b"version", deadline)
                connection.sendall(message(b"version", version_payload(peer_port)) + message(b"verack", b""))
                wait_for(connection, b"verack", deadline)
                wait_for(connection, b"getheaders", deadline, locator=hashes[0])
                before = sampler.snapshot(proc)
                start = previous = time.perf_counter()
                batches = []
                for frame, next_hash in zip(frames, hashes[1:]):
                    connection.sendall(frame)
                    now = wait_for(connection, b"getheaders", deadline, locator=next_hash)
                    batches.append(now - previous)
                    previous = now
                after = sampler.snapshot(proc)
                elapsed = previous - start
                peer = rpc(directory, port, "getpeerinfo")
                info = rpc(directory, port, "getblockchaininfo")
                genesis = rpc(directory, port, "getblockhash", 0)
                if (proc.poll() is not None or not info or info["chain"] != "main" or info["headers"] != 0
                        or info["blocks"] != 0 or not peer or len(peer) != 1
                        or peer[0].get("presynced_headers") != args.count or genesis != GENESIS):
                    raise RuntimeError("Owned node did not confirm the required isolated mainnet presync state")
                return {
                    "workers": workers, "presynced_headers": args.count, "admitted_headers": 0, "active_blocks": 0,
                    "last_presynced_hash": hashes[-1][::-1].hex(), "batch_seconds": batches,
                    **get_capacity(delta(before, after), elapsed, args.count),
                }


def persist(path, report):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def summarize(rows):
    keys = ("wall_seconds", "headers_per_second", "process_cpu_seconds", "average_active_cpu_cores",
            "other_host_cpu_core_equivalents")
    return {str(worker): {key: statistics.median(row[key] for row in rows if row["workers"] == worker)
                          for key in keys} for worker in (4, 8)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crt", required=True, choices=DAEMONS)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--headers", required=True, type=Path)
    parser.add_argument("--headers-sha256", required=True)
    parser.add_argument("--count", type=int, default=40000)
    parser.add_argument("--timeout", type=float, default=420)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", args.headers_sha256) or not 40000 <= args.count <= 100000 or args.count % BATCH:
        parser.error("Use a pinned checksum and an exact 40,000–100,000 header prefix divisible by 2,000")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("Use a finite positive timeout")
    args.binary = args.binary.resolve(strict=True)
    args.gui = False
    sha = digest(args.binary)
    if sha != DAEMONS[args.crt]:
        raise ValueError("Daemon does not match the signed En.7 CRT runtime")
    sampler = WindowsTimes()
    headers, tip = load_headers(args.headers, args.headers_sha256, args.count)
    hashes = [bytes.fromhex(GENESIS)[::-1]] + [hash256(headers[i - 1]) for i in range(BATCH, len(headers) + 1, BATCH)]
    frames = [message(b"headers", compact_size(BATCH) + b"".join(header + b"\0" for header in headers[i:i+BATCH]))
              for i in range(0, len(headers), BATCH)]
    output = args.output.resolve()
    output.mkdir(parents=True)
    report = {
        "scope": "Native Windows En.7 ordered cold mainnet header presync",
        "method": "Single loopback peer, empty isolated profiles, the same 2,000-header boundaries and no validation overrides",
        "host": {"name": platform.platform(), "machine": platform.machine(), "logical_cpus": os.cpu_count(),
                 "processor": os.environ.get("PROCESSOR_IDENTIFIER"), "runner": os.environ.get("ImageOS")},
        "crt": args.crt, "binary_sha256": sha, "fixture": {"genesis": GENESIS, "count": args.count,
                                                            "sha256": args.headers_sha256, "tip": tip},
        "order": [4, 8, 8, 4], "results": [],
    }
    result_file = output / "result.json"
    persist(result_file, report)
    for index, workers in enumerate(report["order"], 1):
        row = replay(args, output / f"{index:02d}-workers-{workers}", frames, hashes, workers, sampler)
        report["results"].append(row)
        persist(result_file, report)
        print(f"{args.crt} workers={workers} sample={index}: {row['wall_seconds']:.3f}s, "
              f"CPU {row['process_cpu_seconds']:.3f}s, {row['headers_per_second']:.2f} headers/s", flush=True)
    report["medians"] = summarize(report["results"])
    persist(result_file, report)


if __name__ == "__main__":
    main()

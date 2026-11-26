#!/usr/bin/env python3
"""Measure packaged native macOS Mainnet PRESYNC on a pinned localhost fixture."""

import argparse
import ctypes
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import statistics
import time
from types import SimpleNamespace

from mainnet_paired import BATCH, compact_size, hash256, message, version_payload, wait_for
from mainnet_probe import check_host, node, rpc


GENESIS = "7d5eaec2dbb75f99feadfa524c78b7cabc1d8c8204f79d4f3a83381b811b0adc"
SETTING_ORDER = ("default", 1, 2, 3, 4, 6)
SCREEN_HEADERS = 12_000
CONFIRM_HEADERS = 100_000
MIN_SCREEN_GAIN = 0.08


class MachTimebase(ctypes.Structure):
    _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]


class ProcessUsage(ctypes.Structure):
    # RUSAGE_INFO_V0, defined by XNU bsd/sys/resource.h.
    _fields_ = [("uuid", ctypes.c_uint8 * 16)] + [
        (field, ctypes.c_uint64) for field in (
            "user", "system", "package_wakeups", "interrupt_wakeups", "pageins",
            "wired_size", "resident_size", "physical_footprint", "proc_start", "proc_exit",
        )
    ]


class DarwinUsage:
    def __init__(self):
        self.libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self.libsystem = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        self.libproc.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        self.libproc.proc_pid_rusage.restype = ctypes.c_int
        self.libproc.proc_pidinfo.argtypes = [
            ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int,
        ]
        self.libproc.proc_pidinfo.restype = ctypes.c_int
        self.libsystem.mach_timebase_info.argtypes = [ctypes.POINTER(MachTimebase)]
        self.libsystem.mach_timebase_info.restype = ctypes.c_int
        self.timebase = MachTimebase()
        if self.libsystem.mach_timebase_info(ctypes.byref(self.timebase)) or not self.timebase.denom:
            raise RuntimeError("Could not read the Darwin Mach timebase")

    def process(self, pid):
        usage = ProcessUsage()
        if self.libproc.proc_pid_rusage(pid, 0, ctypes.byref(usage)):
            failure = ctypes.get_errno()
            raise OSError(failure, os.strerror(failure))
        return usage

    def seconds(self, ticks):
        return ticks * self.timebase.numer / self.timebase.denom / 1_000_000_000

    def thread_count(self, pid):
        # PROC_PIDLISTTHREADS supplies 64-bit thread identifiers for this pid.
        threads = (ctypes.c_uint64 * 1024)()
        size = self.libproc.proc_pidinfo(pid, 6, 0, ctypes.byref(threads), ctypes.sizeof(threads))
        if size <= 0 or size % ctypes.sizeof(ctypes.c_uint64) or size == ctypes.sizeof(threads):
            raise RuntimeError("Could not read the owned daemon's thread count")
        return size // ctypes.sizeof(ctypes.c_uint64)


def read_fixture(path, expected_sha256, expected_tip):
    raw = gzip.decompress(path.read_bytes()) if path.suffix == ".gz" else path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256 or len(raw) % 80:
        raise ValueError("Fixture digest or header record size does not match")
    headers = [raw[offset:offset + 80] for offset in range(0, len(raw), 80)]
    if not SCREEN_HEADERS <= len(headers) <= CONFIRM_HEADERS:
        raise ValueError(f"Fixture must contain {SCREEN_HEADERS}–{CONFIRM_HEADERS} complete headers")
    previous = bytes.fromhex(GENESIS)[::-1]
    for index, header in enumerate(headers, 1):
        if header[4:36] != previous:
            raise ValueError(f"Broken Mainnet fixture link at height {index}")
        previous = hash256(header)
    if previous[::-1].hex() != expected_tip:
        raise ValueError("Fixture tip does not match")
    return headers


def prepare_wire(headers):
    locators = [bytes.fromhex(GENESIS)[::-1]]
    frames = []
    for start in range(0, len(headers), BATCH):
        batch = headers[start: start + BATCH]
        if len(batch) != BATCH:
            raise ValueError("The timed fixture must contain complete P2P messages")
        locators.append(hash256(batch[-1]))
        frames.append(message(b"headers", compact_size(BATCH) + b"".join(header + b"\0" for header in batch)))
    return locators, frames


def timed_presync(args, case_dir, locators, frames, setting, usage, *, timeout=None, timings=None, progress=None):
    header_count = len(frames) * BATCH
    # Retain headroom for the single-worker case without allowing a hung test.
    if timeout is None:
        timeout = 90 + header_count // 110
    if timings is None:
        timings = []
    deadline = time.monotonic() + timeout
    def remaining():
        available = deadline - time.monotonic()
        if available <= 0:
            raise TimeoutError("PRESYNC trial soft deadline expired")
        return available
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(min(30, remaining()))
        peer_port = listener.getsockname()[1]
        flags = [f"-connect=127.0.0.1:{peer_port}", "-v2transport=0", "-dnsseed=0", "-fixedseeds=0", "-dns=0"]
        if setting != "default":
            flags.append(f"-parpow={setting}")
        with node(args, case_dir, "presync", extra_flags=flags) as (proc, rpc_port, _):
            listener.settimeout(min(30, remaining()))
            connection, _ = listener.accept()
            with connection:
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                wait_for(connection, b"version", deadline)
                version = version_payload(peer_port, starting_height=header_count)
                connection.settimeout(remaining())
                connection.sendall(message(b"version", version) + message(b"verack", b""))
                wait_for(connection, b"verack", deadline)
                wait_for(connection, b"getheaders", deadline, locator=locators[0])
                initial_threads = usage.thread_count(proc.pid)
                before = usage.process(proc.pid)
                started = time.perf_counter()
                for index, frame in enumerate(frames):
                    sent = time.perf_counter()
                    connection.settimeout(remaining())
                    connection.sendall(frame)
                    observed = wait_for(connection, b"getheaders", deadline, locator=locators[index + 1])
                    timings.append(observed - sent)
                    if progress is not None:
                        current = usage.process(proc.pid)
                        progress({
                            "confirmed_through_height": (index + 1) * BATCH,
                            "wall_seconds": observed - started,
                            "user_cpu_seconds": usage.seconds(current.user - before.user),
                            "system_cpu_seconds": usage.seconds(current.system - before.system),
                            "initial_node_threads": initial_threads,
                        })
                after = usage.process(proc.pid)
                final_threads = usage.thread_count(proc.pid)

                peers = rpc(case_dir, rpc_port, "getpeerinfo")
                state = rpc(case_dir, rpc_port, "getblockchaininfo")
                genesis = rpc(case_dir, rpc_port, "getblockhash", 0)
                if (
                    proc.poll() is not None or not peers or len(peers) != 1
                    or peers[0].get("presynced_headers") != header_count
                    or not state or state["chain"] != "main" or state["blocks"] != 0 or state["headers"] != 0
                    or genesis != GENESIS
                ):
                    raise RuntimeError("Released node did not report the expected Mainnet PRESYNC state")
    if proc.returncode != 0:
        raise RuntimeError(f"Owned daemon did not stop cleanly: {proc.returncode}")
    wall = observed - started
    cpu_user = usage.seconds(after.user - before.user)
    cpu_system = usage.seconds(after.system - before.system)
    if cpu_user <= 0 or cpu_system < 0 or wall <= 0 or before.proc_start != after.proc_start:
        raise RuntimeError("Process accounting did not cover the tested node lifetime")
    return {
        "parpow": setting,
        "headers": header_count,
        "wall_seconds": wall,
        "headers_per_second": header_count / wall,
        "user_cpu_seconds": cpu_user,
        "system_cpu_seconds": cpu_system,
        "mean_cpu_cores": (cpu_user + cpu_system) / wall,
        "starting_resident_bytes": before.resident_size,
        "final_resident_bytes": after.resident_size,
        "final_physical_footprint_bytes": after.physical_footprint,
        "initial_node_threads": initial_threads,
        "final_node_threads": final_threads,
        "node_exit_code": proc.returncode,
        "final_state": {"chain": state["chain"], "blocks": state["blocks"], "active_headers": state["headers"],
                        "presynced_headers": peers[0]["presynced_headers"], "genesis": genesis},
        "last_presynced_hash": locators[-1][::-1].hex(),
        "message_wall_seconds": timings,
    }


def save(output, record):
    intermediate = output.with_suffix(".tmp")
    intermediate.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    intermediate.replace(output)


def audit(options):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("A native Apple Silicon host is required")
    check_host()
    usage = DarwinUsage()
    fixture = read_fixture(options.headers, options.headers_sha256, options.fixture_tip)
    def verify_binary(path, expected):
        with path.open("rb") as binary:
            digest = hashlib.file_digest(binary, "sha256").hexdigest()
        if digest != expected:
            raise ValueError("The executed binary does not match the pinned release digest")
        return digest

    binary_sha = verify_binary(options.binary, options.binary_sha256)
    gui_sha = verify_binary(options.gui_binary, options.gui_binary_sha256)
    options.work.mkdir()
    options.output.parent.mkdir(parents=True, exist_ok=True)
    meta = {
        "mode": "native packaged Mainnet loopback PRESYNC with stock chainwork checks",
        "host": {"platform": platform.platform(), "logical_cpus": os.cpu_count(),
                 "machine": platform.machine(), "runner_image_version": os.environ.get("ImageVersion")},
        "mac_timebase": {"numer": usage.timebase.numer, "denom": usage.timebase.denom},
        "fixture": {"full_count": len(fixture), "full_sha256": options.headers_sha256, "full_tip": options.fixture_tip},
        "binary_sha256": {"cli": binary_sha, "gui": gui_sha},
        "screen_trials": [],
        "confirmation_trials": [],
        "gui_confirmation_trials": [],
    }
    save(options.output, meta)
    def run(round_num, order, cohort, count, gui=False):
        executable = options.gui_binary if gui else options.binary
        args = SimpleNamespace(binary=executable.resolve(), gui=gui)
        locators, frames = prepare_wire(fixture[:count])
        for setting in order:
            case = options.work / f"{cohort}-{round_num}-{setting}"
            observed = timed_presync(args, case, locators, frames, setting, usage)
            meta[cohort].append({"round": round_num, **observed})
            save(options.output, meta)
            print(f"{cohort} {round_num}, {setting}: {count} headers in {observed['wall_seconds']:.3f} s, "
                  f"mean CPU {observed['mean_cpu_cores']:.3f} cores", flush=True)

    for round_num, order in enumerate((SETTING_ORDER, SETTING_ORDER[::-1]), 1):
        run(round_num, order, "screen_trials", SCREEN_HEADERS)
    rows = meta["screen_trials"]
    medians = {setting: statistics.median(row["wall_seconds"] for row in rows if row["parpow"] == setting)
               for setting in SETTING_ORDER}
    best = min(medians, key=medians.get)
    meta["screen_wall_medians"] = medians
    comparable = {setting: [row["wall_seconds"] for row in rows if row["parpow"] == setting] for setting in medians}
    selected = (best != "default" and all(new <= old * (1 - MIN_SCREEN_GAIN)
                for old, new in zip(comparable["default"], comparable[best])))
    if selected and len(fixture) >= CONFIRM_HEADERS:
        confirmation_order = (("default", best), (best, "default"))
        for round_num, order in enumerate(confirmation_order, 1):
            run(round_num, order, "confirmation_trials", CONFIRM_HEADERS)
        cli_confirmation = {setting: [row["wall_seconds"] for row in meta["confirmation_trials"]
                                     if row["parpow"] == setting] for setting in ("default", best)}
        if all(new <= old * (1 - MIN_SCREEN_GAIN)
               for old, new in zip(cli_confirmation["default"], cli_confirmation[best])):
            for round_num, order in enumerate(confirmation_order[::-1], 1):
                run(round_num, order, "gui_confirmation_trials", CONFIRM_HEADERS, gui=True)
        else:
            meta["gui_confirmation_skipped"] = "The CLI candidate did not sustain the paired gain at 100000 headers"
    else:
        meta["confirmation_skipped"] = "insufficient paired screen gain or shorter-than-100000-header input"
    save(options.output, meta)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--gui-binary", type=Path, required=True)
    parser.add_argument("--gui-binary-sha256", required=True)
    parser.add_argument("--headers", type=Path, required=True)
    parser.add_argument("--headers-sha256", required=True)
    parser.add_argument("--fixture-tip", required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    audit(parser.parse_args())

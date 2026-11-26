#!/usr/bin/env python3
"""Qualify one native CLI process against a pinned mature public Mainnet checkpoint."""

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime
from decimal import Decimal
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import ProxyHandler, build_opener, install_opener

from checkpoint_fixture import CHECKPOINT, QualificationError, extract, load_manifest
from windows_startup_memory import StartupObserver

HELPERS = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(HELPERS / "body-reread"), str(HELPERS / "delivery")]
import mainnet_apple_body_ab as apple
from mainnet_body_reread_ab import release_input
from mainnet_delivery import Resources, persist
from mainnet_probe import check_host, node, rpc
from mainnet_warm import make_rpc_request, read_rpc_response

RUNTIME_SOURCE = "9c502574b652804905d2533d51742ca91f694532"
RUNTIME_TREE = "f44aa1b47f9701996046bbb396106f1d5c365e66"
STARTUP_LIMIT = 480
VERIFY_LIMIT = 90
UTXO_LIMIT = 180
CLEANUP_RESERVE = 24
VERIFY_DEPTH = 4096
VERIFY_TXS = 4149
MEMORY_FLOOR = (CHECKPOINT["height"] + 1) * 192
START_MARK = f"Verifying last {VERIFY_DEPTH} blocks at level 4"
END_MARK = f"No coin database inconsistencies in last {VERIFY_DEPTH} blocks ({VERIFY_TXS} transactions)"
TIMESTAMP = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)")
LAZY_POW = re.compile(r"Lazy PoW: (\d+)/(\d+) \([^)]+\) checked, (\d+) verified, (\d+) reused")
POW_AND_STORAGE_TIMERS = {
    "reconnect_sanity_checks": re.compile(r" - Sanity checks: ([\d.]+)ms "),
    "reconnect_fork_checks": re.compile(r" - Fork checks: ([\d.]+)ms "),
    "reconnect_transactions": re.compile(r" - Connect \d+ transactions: ([\d.]+)ms "),
    "reconnect_script_inputs": re.compile(r" - Verify \d+ txins: ([\d.]+)ms "),
    "reconnect_undo": re.compile(r" - Write undo data: ([\d.]+)ms "),
}
OOM_LOG = re.compile(r"out of memory|std::bad_alloc|not enough memory|cannot allocate memory", re.IGNORECASE)


def guard(condition, status, detail):
    if not condition:
        raise QualificationError(status, detail)


def stage_deadline(overall, seconds, status):
    bound = min(overall - CLEANUP_RESERVE, time.monotonic() + seconds)
    guard(bound > time.monotonic(), status, "The shared qualification deadline left no time for this phase")
    return bound


class MemoryStatus(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("load", wintypes.DWORD),
                *((key, ctypes.c_ulonglong) for key in ("total_physical", "available_physical", "total_commit",
                   "available_commit", "total_virtual", "available_virtual", "extended_virtual"))]


def memory_state():
    if platform.system() == "Windows":
        query = ctypes.WinDLL("kernel32", use_last_error=True).GlobalMemoryStatusEx
        query.argtypes = [ctypes.POINTER(MemoryStatus)]
        query.restype = wintypes.BOOL
        info = MemoryStatus(size=ctypes.sizeof(MemoryStatus))
        if not query(ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        # Windows labels these fields "PageFile", but they represent commit limits.
        return {"physical_bytes": info.total_physical, "available_physical_bytes": info.available_physical,
                "commit_available_bytes": info.available_commit, "commit_limit_bytes": info.total_commit}

    total = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGESIZE")
    rows = subprocess.check_output(["vm_stat"], text=True, timeout=3)
    page_size = re.search(r"page size of (\d+) bytes", rows)
    counters = dict(re.findall(r"^([^:]+):\s*(\d+)\.?$", rows, re.MULTILINE))
    result = {"physical_bytes": total}
    if page_size:
        for name, field in (("Pages free", "free_page_bytes"), ("Swapins", "swapin_bytes"),
                            ("Swapouts", "swapout_bytes"), ("Pages occupied by compressor", "compressor_bytes")):
            if name in counters:
                result[field] = int(counters[name]) * int(page_size[1])
    return result


def windows_paging():
    if platform.system() != "Windows":
        return {}
    script = (
        "$m = Get-CimInstance Win32_PerfRawData_PerfOS_Memory; "
        "$p = @(Get-CimInstance Win32_PageFileUsage | Select-Object CurrentUsage,PeakUsage); "
        "[ordered]@{ counters=($m | Select-Object PagesInputPersec,PageReadsPersec,AvailableBytes); "
        "pagefile_usage_mib=$p } | ConvertTo-Json -Depth 4 -Compress"
    )
    try:
        raw = subprocess.check_output(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                                      text=True, stderr=subprocess.DEVNULL, timeout=6)
        return json.loads(raw)
    except (OSError, ValueError, subprocess.SubprocessError):
        return {"sample": "unavailable"}


def record_resources(proc, profile, resources, timeline, done):
    with timeline.open("w", encoding="utf-8", buffering=1) as out:
        zero = time.monotonic()
        while not done.is_set() and proc.poll() is None:
            row = {"elapsed_seconds": round(time.monotonic() - zero, 3)}
            try:
                cpu, rss = resources.sample(proc)
                row.update(process_cpu_seconds=cpu, working_set_bytes=rss,
                           disk_free_bytes=shutil.disk_usage(profile).free, memory=memory_state())
            except (OSError, RuntimeError, subprocess.SubprocessError) as failure:
                row["sample_error"] = type(failure).__name__
            out.write(json.dumps(row) + "\n")
            done.wait(2)


def verify_windows_pe(path):
    status = "runtime_architecture_failure"
    with path.open("rb") as binary:
        length = os.fstat(binary.fileno()).st_size
        dos = binary.read(64)
        guard(len(dos) == 64 and dos[:2] == b"MZ", status, "Missing Windows DOS executable header")
        offset, = struct.unpack_from("<I", dos, 0x3C)
        guard(64 <= offset <= length - 26, status, "Windows PE header offset is outside the executable")
        binary.seek(offset)
        header = binary.read(26)
        guard(header[:4] == b"PE\x00\x00" and len(header) == 26, status, "Missing Windows PE header")
        machine, = struct.unpack_from("<H", header, 4)
        optional_size, magic = struct.unpack_from("<H2xH", header, 20)
        guard(machine == 0x8664 and magic == 0x20B and 2 <= optional_size <= length - offset - 24,
              status, "Selected Windows daemon is not AMD64 PE32+")


def runtime_binary(args, output):
    if args.target == "apple-arm64":
        guard(platform.system() == "Darwin" and platform.machine() == "arm64", "native_host_inconclusive",
              "A native Apple Silicon runner is required")
        check_host()
        metadata = apple.check_package(args.runtime, RUNTIME_SOURCE, RUNTIME_TREE)
        metadata.update(apple.prepare_binary(args.runtime, output / "runtime", False))
        return metadata

    guard(platform.system() == "Windows" and platform.machine().lower() in {"amd64", "x86_64"},
          "native_host_inconclusive", "Native Windows x86-64 is required")
    metadata = release_input(args.runtime, RUNTIME_SOURCE, RUNTIME_TREE)
    verify_windows_pe(Path(metadata["binary"]))
    return metadata


def get_exact_tip(profile, port, proc, deadline, status):
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise QualificationError("process_exit_inconclusive", f"Fixture node exited with status {proc.returncode}")
        info = rpc(profile, port, "getblockchaininfo")
        if info is not None:
            guard(info["chain"] == "main" and info["blocks"] == CHECKPOINT["height"]
                  and info["bestblockhash"] == CHECKPOINT["hash"] and info["headers"] >= info["blocks"]
                  and info["pruned"] is True,
                  "checkpoint_identity_failure", "Unexpected loaded Mainnet checkpoint tip")
            return {key: info[key] for key in ("chain", "blocks", "headers", "bestblockhash", "pruned", "initialblockdownload")}
        time.sleep(0.2)
    raise QualificationError(status, "Exact checkpoint RPC readiness deadline expired")


def long_rpc(profile, port, method, params, deadline, timeout_status):
    cookie = (profile / ".cookie").read_bytes().strip()
    request = make_rpc_request(port, cookie, json.dumps({
        "jsonrpc": "2.0", "id": "checkpoint-qualification", "method": method, "params": params,
    }).encode("ascii"))
    seconds = deadline - time.monotonic()
    guard(seconds > 0, timeout_status, f"Timeout before {method}")
    try:
        raw = read_rpc_response(request, seconds)
    except TimeoutError as failure:
        raise QualificationError(timeout_status, f"{method} exceeded its deadline") from failure
    except HTTPError as failure:
        raise QualificationError("rpc_failure_inconclusive", f"{method} returned HTTP {failure.code}") from failure
    result = json.loads(raw, parse_float=Decimal)
    guard(result.get("error") is None and result.get("id") == "checkpoint-qualification",
          "rpc_failure_inconclusive", f"{method} did not return a verified result")
    return result["result"]


def new_log_text(path, begin, end=None):
    with path.open("rb") as log:
        log.seek(begin)
        return log.read(-1 if end is None else end - begin).decode("utf-8", errors="replace")


def log_stamp(line):
    match = TIMESTAMP.match(line)
    return datetime.fromisoformat(match[1]) if match else None


def lazy_pow(log):
    matches = list(LAZY_POW.finditer(log))
    names = ("checked", "total", "verified", "reused")
    return dict(zip(names, map(int, matches[-1].groups()))) if matches else None


def verification_log(log):
    lines = log.splitlines()
    begins = [index for index, line in enumerate(lines) if START_MARK in line]
    ends = [index for index, line in enumerate(lines) if END_MARK in line]
    guard(len(begins) == len(ends) == 1 and begins[0] < ends[0],
          "level4_log_failure", "Missing exact completed level-4 4096-block, 4149-transaction log proof")
    segment = lines[begins[0]:ends[0] + 1]
    mid = next((log_stamp(line) for line in segment if "Verification progress: 50%" in line), None)
    start, stop = log_stamp(segment[0]), log_stamp(segment[-1])
    result = {"level": 4, "blocks": VERIFY_DEPTH, "transactions": VERIFY_TXS, "log_timer_resolution_ms": 0.01}
    if all((start, mid, stop)) and start <= mid <= stop:
        result["read_proof_disconnect_log_seconds"] = (mid - start).total_seconds()
        result["reconnect_log_seconds"] = (stop - mid).total_seconds()
    for label, pattern in POW_AND_STORAGE_TIMERS.items():
        values = [float(match[1]) for line in segment if (match := pattern.search(line))]
        result[label] = {"events": len(values), "sum_ms": round(sum(values), 3)}
    return result


def utxo_state(result):
    guard(result["height"] == CHECKPOINT["height"] and result["bestblock"] == CHECKPOINT["hash"]
          and result["hash_serialized_3"] == CHECKPOINT["utxo_hash"] and result["txouts"] == CHECKPOINT["txouts"]
          and result["total_amount"] == Decimal(CHECKPOINT["total_amount"]),
          "checkpoint_identity_failure", "Serialized UTXO state differs from the mature fixture")
    return {**CHECKPOINT}


def verify_pass(proc, profile, port, debug, resources, overall, label):
    begin = debug.stat().st_size
    before, rss_before = resources.sample(proc)
    deadline = stage_deadline(overall, VERIFY_LIMIT, "level4_timeout_inconclusive")
    started = time.monotonic()
    success = long_rpc(profile, port, "verifychain", [4, VERIFY_DEPTH], deadline, "level4_timeout_inconclusive")
    elapsed = time.monotonic() - started
    after, rss_after = resources.sample(proc)
    end = debug.stat().st_size
    if success is not True:
        segment = new_log_text(debug, begin, end)
        if "insufficient database cache size" in segment:
            raise QualificationError("database_cache_capacity_inconclusive", "Level-4 verification skipped required coin checks")
        raise QualificationError("level4_validation_failure", "verifychain did not complete successfully")
    return {"name": label, "pid": proc.pid, "wall_seconds": elapsed, "node_cpu_seconds": after - before,
            "rss_before_bytes": rss_before, "rss_after_bytes": rss_after, "log_start_byte": begin, "log_end_byte": end}


def summarize_resources(report, timeline):
    rows = [json.loads(row) for row in timeline.read_text(encoding="utf-8").splitlines()] if timeline.exists() else []
    working_sets = [row["working_set_bytes"] for row in rows if "working_set_bytes" in row]
    rss = max(working_sets, default=None)
    disk = min((row["disk_free_bytes"] for row in rows if "disk_free_bytes" in row), default=None)
    before, after = report.get("memory_before", {}), report.get("memory_after", {})
    pressure = {}
    for key in ("swapin_bytes", "swapout_bytes"):
        if key in before and key in after and after[key] >= before[key]:
            pressure[f"{key}_delta"] = after[key] - before[key]
    before_windows = report.get("windows_page_read_counters_before", {})
    after_windows = report.get("windows_page_read_counters_after", {})
    if "pagefile_usage_mib" in before_windows and "pagefile_usage_mib" in after_windows:
        before_used = sum(entry["CurrentUsage"] for entry in before_windows["pagefile_usage_mib"])
        after_used = sum(entry["CurrentUsage"] for entry in after_windows["pagefile_usage_mib"])
        pressure["windows_pagefile_usage_mib_delta"] = after_used - before_used
    memory = before.get("physical_bytes")
    floor = memory < MEMORY_FLOOR if memory is not None else None
    paged = any(change > 0 for change in pressure.values())
    report["capacity"] = {
        "sample_count": len(rows), "peak_sampled_working_set_bytes": rss, "minimum_sampled_free_disk_bytes": disk,
        "index_values_and_chain_pointer_floor_bytes": MEMORY_FLOOR, "physical_below_floor": floor,
        "observed_swap": pressure,
        "speed_interpretation": ("below_resident_memory_floor" if floor else
                                 "paging_observed" if paged else "qualification_only"),
    }


def run(args):
    install_opener(build_opener(ProxyHandler({})))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = output / "result.json"
    report = {
        "status": "in_progress", "phase": "preflight", "target": args.target, "checkpoint": CHECKPOINT,
        "host": {"platform": platform.platform(), "logical_cpus": os.cpu_count(), "image_version": os.getenv("ImageVersion")},
        "passes": [], "first_pass_os_cache": "not reset after extraction and startup", "fast_startup": 1,
        "assumevalid": 0, "networkactive": False, "prune": "manual", "scope": "mature local checkpoint capacity and level-4 qualification",
    }
    persist(result, report)
    overall = time.monotonic() + max(0, args.deadline_epoch - time.time())
    profile = output / "node"
    debug = profile / "debug-restart.log"
    timeline = output / "resources.jsonl"
    process = None
    try:
        report["binary"] = runtime_binary(args, output)
        resources = Resources()
        metadata = load_manifest(args.fixture / args.manifest_name, args.fixture_manifest_sha256)
        report["fixture_manifest_sha256"] = args.fixture_manifest_sha256
        report["phase"] = "extract"
        persist(result, report)
        report["extraction"] = extract(args.fixture, metadata, profile, stage_deadline(overall, 300, "extract_timeout"))
        report["memory_before"] = memory_state()
        report["windows_page_read_counters_before"] = windows_paging()

        flags = ("-networkactive=0", "-connect=0", "-dnsseed=0", "-fixedseeds=0", "-dns=0", "-proxy=0",
                 "-assumevalid=0", "-fast-startup=1", "-prune=1", "-debug=bench")
        variant = SimpleNamespace(binary=Path(report["binary"]["binary"]), gui=False)
        report["phase"] = "startup"
        persist(result, report)
        with node(variant, profile, "mature-checkpoint", restart=True, extra_flags=flags, shutdown_timeout=10) as (proc, port, started):
            process = proc
            done = threading.Event()
            observer = threading.Thread(target=record_resources, args=(proc, profile, resources, timeline, done), daemon=True)
            observer.start()
            memory_probe = StartupObserver(proc, profile, started)
            memory_probe.start()
            diagnostic_stopped = False
            try:
                deadline = stage_deadline(overall, STARTUP_LIMIT, "startup_timeout_inconclusive")
                report["starting_tip"] = get_exact_tip(profile, port, proc, deadline, "startup_timeout_inconclusive")
                report["startup_seconds"] = time.monotonic() - started
                diagnostic_stopped = memory_probe.stop()
                guard(diagnostic_stopped, "startup_memory_observer_stop_inconclusive",
                      "The Windows startup diagnostic must stop before timed verification")
                network = rpc(profile, port, "getnetworkinfo")
                guard(network and network["networkactive"] is False and rpc(profile, port, "getpeerinfo") == [],
                      "isolation_failure", "Fixture process is not isolated")
                report["startup_lazy_pow"] = lazy_pow(new_log_text(debug, 0))
                report["fixture_pid"] = proc.pid
                for label in ("first_after_start", "immediate_same_process_warm"):
                    report["phase"] = label
                    persist(result, report)
                    report["passes"].append(verify_pass(proc, profile, port, debug, resources, overall, label))
                for case in report["passes"]:
                    segment = new_log_text(debug, case["log_start_byte"], case["log_end_byte"])
                    case["level4_log"] = verification_log(segment)
                    case["latest_lazy_pow_log_within_pass"] = lazy_pow(segment)
                report["ending_tip"] = get_exact_tip(profile, port, proc,
                    stage_deadline(overall, 3, "post_verify_rpc_inconclusive"), "post_verify_rpc_inconclusive")
                guard(report["starting_tip"] == report["ending_tip"], "checkpoint_identity_failure",
                      "The pinned checkpoint state changed across passes")
                report["phase"] = "post_verification_utxo"
                persist(result, report)
                start_utxo = time.monotonic()
                utxo = long_rpc(profile, port, "gettxoutsetinfo", ["hash_serialized_3"],
                                stage_deadline(overall, UTXO_LIMIT, "utxo_timeout_inconclusive"), "utxo_timeout_inconclusive")
                report["verified_state"] = utxo_state(utxo)
                report["post_verification_utxo_seconds"] = time.monotonic() - start_utxo
                report["phase"] = "shutdown"
                persist(result, report)
            finally:
                if not diagnostic_stopped:
                    diagnostic_stopped = memory_probe.stop()
                try:
                    memory_probe.persist(output / "windows-startup-memory.json", diagnostic_stopped)
                except OSError as failure:
                    report["diagnostic_report_write_error"] = type(failure).__name__
                done.set()
                observer.join(timeout=5)
        log = new_log_text(debug, 0)
        guard(proc.returncode == 0 and "Shutdown done" in log, "shutdown_inconclusive", "Fixture node did not stop cleanly")
        report["shutdown_lazy_pow"] = lazy_pow(log)
        report["status"] = "verified"
        report["phase"] = "complete"
    except Exception as error:
        status = error.status if isinstance(error, QualificationError) else "harness_inconclusive"
        if process is not None:
            report["process_exit_code"] = process.returncode
            try:
                log = new_log_text(debug, 0) if debug.exists() else ""
            except OSError as failure:
                log = ""
                report["failure_log_read_error"] = type(failure).__name__
            exit_code = (process.returncode or 0) & 0xFFFFFFFF
            if OOM_LOG.search(log) or exit_code in (0xC0000017, 0xC000012D):
                status = "memory_exhaustion_inconclusive"
            elif process.returncode == -9 and status == "process_exit_inconclusive":
                status = "process_killed_reason_unconfirmed"
        report.update(status=status, error=f"{type(error).__name__}: {error}")
        raise
    finally:
        try:
            report["memory_after"] = memory_state()
            report["windows_page_read_counters_after"] = windows_paging()
        except Exception as failure:
            report["post_resource_sample_error"] = type(failure).__name__
        try:
            summarize_resources(report, timeline)
        except Exception as failure:
            report["resource_summary_error"] = type(failure).__name__
        persist(result, report)
    print(f"Verified mature checkpoint in two passes. Results at {result}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("runtime", "fixture", "output"):
        parser.add_argument(f"--{argument}", type=Path, required=True)
    parser.set_defaults(target="windows-ucrt")
    parser.add_argument("--fixture-manifest-sha256", required=True)
    parser.add_argument("--manifest-name", required=True)
    parser.add_argument("--deadline-epoch", type=float, required=True)
    args = parser.parse_args()
    run(args)
    profile_path = args.output / "windows-startup-memory.json"
    if not profile_path.is_file():
        parser.exit(1, "Core checks completed, but Windows startup memory evidence is unavailable.\n")
    diagnosis = json.loads(profile_path.read_text(encoding="utf-8"))
    if diagnosis["status"] != "verified_metadata":
        parser.exit(1, "Core checks completed. The requested Windows startup memory breakdown remains unresolved.\n")


if __name__ == "__main__":
    main()

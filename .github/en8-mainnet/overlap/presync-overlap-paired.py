"""Compare complete native Mainnet presync batches over deterministic loopback."""

import argparse
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import platform
import re
import socket
import time
from types import SimpleNamespace

from mainnet_paired import first_locator, message, read_message, sha256_file, version_payload, wait_for
from mainnet_probe import check_host, log_text, node, rpc, wait_for_presynced_height
from presync_sweep import BATCH, DarwinUsage, GENESIS, prepare_wire, read_fixture


FIXTURE_SHA = "f64a65677abdfa525b67d9a09291868fbfd1f9fb0d4089cdfafc3b2718dd07dd"
FIXTURE_TIP = "b62290c6914adee9b29326b8a4567114fff1f9013acb9c3b6ff68612a2947f99"
HEIGHT = 40_000
LATENCY = 0.200
ORDER = ("baseline", "candidate", "candidate", "baseline")
CREDIT = re.compile(rb"PRESYNC proof time credit: peer=(\d+) granted_us=(\d+) remaining_us=(\d+) height=(\d+)\r?$")


class WindowsUsage:
    def __init__(self):
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel.OpenProcess.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.kernel.IsWow64Process2.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.WORD)]
        self.kernel.IsWow64Process2.restype = wintypes.BOOL
        self.kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        self.kernel.GetProcessTimes.restype = wintypes.BOOL

    def sample(self, pid):
        handle = self.kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            machine, native = wintypes.WORD(), wintypes.WORD()
            if not self.kernel.IsWow64Process2(handle, ctypes.byref(machine), ctypes.byref(native)):
                raise ctypes.WinError(ctypes.get_last_error())
            if machine.value or native.value != 0x8664:
                raise RuntimeError("Windows comparison requires a native x86-64 node on x86-64 Windows")
            times = [wintypes.FILETIME() for _ in range(4)]
            if not self.kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self.kernel.CloseHandle(handle)
        created, _, system, user = [(value.dwHighDateTime << 32) | value.dwLowDateTime for value in times]
        return created, user / 10_000_000, system / 10_000_000


def cpu_sampler():
    check_host()
    if platform.system() == "Darwin" and platform.machine() == "arm64":
        usage = DarwinUsage()

        def sample(pid):
            record = usage.process(pid)
            return record.proc_start, usage.seconds(record.user), usage.seconds(record.system)

        return sample
    if platform.system() == "Windows":
        return WindowsUsage().sample
    raise RuntimeError("Comparison requires native Apple Silicon or Windows x86-64")


def next_headers_request(connection, locator, deadline):
    while True:
        command, payload = read_message(connection, deadline)
        if command == b"getheaders":
            if first_locator(payload) != locator:
                raise RuntimeError("Unexpected or duplicate getheaders locator")
            return time.perf_counter()
        if command == b"ping":
            connection.sendall(message(b"pong", payload))


def wait_for_final_credit(proc, path, deadline):
    """Read appended log bytes, avoiding repeated RPCs during the last proof."""
    marker_deadline = min(deadline, time.monotonic() + 15)
    attempts = 0
    try:
        logfile = path.open("rb")
    except FileNotFoundError:
        return None, attempts, None
    with logfile as handle:
        incomplete = b""
        while time.monotonic() < marker_deadline:
            if proc.poll() is not None:
                raise RuntimeError(f"Node exited before the local proof barrier: {proc.returncode}")
            attempts += 1
            rows = (incomplete + handle.read()).split(b"\n")
            incomplete = rows.pop()
            for row in rows:
                match = CREDIT.search(row)
                if match:
                    peer, grant, remaining, height = map(int, match.groups())
                    if height == HEIGHT and grant > 0:
                        return time.perf_counter(), attempts, {"peer": peer, "grant_us": grant, "remaining_us": remaining}
            time.sleep(0.01)
    return None, attempts, None


def measure(args, case, locators, frames, sample):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(30)
        peer_port = listener.getsockname()[1]
        flags = [f"-connect=127.0.0.1:{peer_port}", "-v2transport=0", "-dnsseed=0", "-fixedseeds=0", "-dns=0", "-debug=net"]
        with node(args, case, "presync", extra_flags=flags) as (proc, port, _):
            connection, _ = listener.accept()
            with connection:
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                deadline = time.monotonic() + 240
                wait_for(connection, b"version", deadline)
                connection.sendall(message(b"version", version_payload(peer_port, starting_height=HEIGHT)) + message(b"verack", b""))
                wait_for(connection, b"verack", deadline)
                requested = next_headers_request(connection, locators[0], deadline)
                before = sample(proc.pid)
                wire = []
                for index, frame in enumerate(frames):
                    remaining = requested + LATENCY - time.perf_counter()
                    if remaining > 0:
                        time.sleep(remaining)
                    sent = time.perf_counter()
                    connection.sendall(frame)
                    record = {"height": (index + 1) * BATCH, "requested": requested, "sent": sent}
                    wire.append(record)
                    if index == len(frames) - 1:
                        break
                    following = next_headers_request(connection, locators[index + 1], deadline)
                    record["next_request"] = following
                    requested = following

                # Both source versions log proof credit after an advancing
                # contextual result. Stop the score before the single RPC.
                completed, marker_attempts, credit = wait_for_final_credit(proc, case / "debug.log", deadline)
                peers = None
                rpc_attempts = 0
                fallback = None
                if credit:
                    after = sample(proc.pid)
                    peers = rpc(case, port, "getpeerinfo")
                    rpc_attempts = 1
                    if (not peers or len(peers) != 1 or peers[0].get("id") != credit["peer"]
                            or peers[0].get("presynced_headers") != HEIGHT):
                        fallback = "final credit marker lacked a matching immediate peer RPC"
                else:
                    fallback = "final credit marker was not observed within the marker deadline"
                if fallback:
                    completed, _, fallback_attempts = wait_for_presynced_height(case, port, proc, HEIGHT, deadline)
                    after = sample(proc.pid)
                    rpc_attempts += fallback_attempts
                wire[-1]["next_request"] = next_headers_request(connection, locators[-1], deadline)
                wire[-1]["next_request_outside_timing"] = True
                state = rpc(case, port, "getblockchaininfo")
                if (not state or state["chain"] != "main" or state["blocks"] != 0 or state["headers"] != 0
                        or state["initialblockdownload"] is not True or rpc(case, port, "getblockhash", 0) != GENESIS):
                    raise RuntimeError("Unexpected chain state at the verified height barrier")
                # A late duplicate for the final locator cannot be mistaken
                # for the next trial's request. This check is outside timing.
                quiet_deadline = time.monotonic() + 0.05
                while time.monotonic() < quiet_deadline:
                    try:
                        command, _ = read_message(connection, quiet_deadline)
                    except TimeoutError:
                        break
                    if command == b"getheaders":
                        raise RuntimeError("Duplicate getheaders after the final proof barrier")

    wall = completed - wire[0]["requested"]
    user, system = after[1] - before[1], after[2] - before[2]
    log = log_text(case)
    if proc.returncode != 0 or "Shutdown: done" not in log:
        raise RuntimeError(f"Expected clean RPC shutdown, process return code {proc.returncode}")
    if wall <= 0 or before[0] != after[0] or user <= 0 or system < 0:
        raise RuntimeError("Invalid process CPU sample")
    # Elapsed offsets keep the timing comparisons reproducible across clocks.
    origin = wire[0]["requested"]
    for row in wire:
        for field in ("requested", "sent", "next_request"):
            row[field] -= origin
    return {
        "status": "verified",
        "height": HEIGHT,
        "wall_seconds": wall,
        "user_cpu_seconds": user,
        "system_cpu_seconds": system,
        "completion_method": "post-validation proof credit log" if fallback is None else "unscored peer RPC fallback",
        "scored": fallback is None,
        "completion_fallback_reason": fallback,
        "credit": credit,
        "log_poll_attempts": marker_attempts,
        "state_rpc_attempts": rpc_attempts,
        "wire": wire,
        "chain": {key: state[key] for key in ("chain", "blocks", "headers", "initialblockdownload")},
        "clean_exit": True,
        "debug_log": str(case / "debug.log"),
        "lead_getheaders": log.count(args.lead_marker),
    }


def save(path, data):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--headers", type=Path, required=True)
    parser.add_argument("--case-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--lead-marker", default="PRESYNC lead getheaders:")
    options = parser.parse_args()

    sampler = cpu_sampler()
    headers = read_fixture(options.headers, FIXTURE_SHA, FIXTURE_TIP)
    locators, frames = prepare_wire(headers[:HEIGHT])
    binaries = {role: getattr(options, role).resolve(strict=True) for role in {"baseline", "candidate"}}
    if platform.system() == "Darwin":
        for binary in binaries.values():
            with binary.open("rb") as handle:
                if handle.read(8) != bytes.fromhex("cffaedfe0c000001"):
                    raise RuntimeError(f"Expected a native Apple Silicon package member: {binary}")
    result = {
        "host": platform.platform(),
        "interface": "gui" if options.gui else "cli",
        "height": HEIGHT,
        "fixture_raw_sha256": FIXTURE_SHA,
        "fixture_prefix_tip": locators[-1][::-1].hex(),
        "minimum_work": "stock",
        "peer_wait_seconds": LATENCY,
        "order": ORDER,
        "binaries": {role: {"file": str(binary), "sha256": sha256_file(binary)} for role, binary in binaries.items()},
        "trials": [],
    }
    options.case_root.mkdir(parents=True, exist_ok=True)
    options.output.parent.mkdir(parents=True, exist_ok=True)
    for index, role in enumerate(ORDER, 1):
        case = options.case_root.resolve() / f"{index:02d}-{role}"
        trial = {"run": index, "role": role, "case_dir": str(case)}
        result["trials"].append(trial)
        try:
            args = SimpleNamespace(binary=binaries[role], gui=options.gui, lead_marker=options.lead_marker)
            trial.update(measure(args, case, locators, frames, sampler))
            expected_leads = len(frames) - 1 if role == "candidate" else 0
            if trial["lead_getheaders"] != expected_leads:
                raise RuntimeError(f"Expected {expected_leads} lead requests, got {trial['lead_getheaders']}")
        except Exception as failure:
            trial.update(status="failed", error=str(failure))
            save(options.output, result)
            raise
        save(options.output, result)

    trials = result["trials"]
    result["pairs"] = []
    for baseline, candidate in ((trials[0], trials[1]), (trials[3], trials[2])):
        pair = {"baseline_run": baseline["run"], "candidate_run": candidate["run"],
                "scored": baseline["scored"] and candidate["scored"]}
        result["pairs"].append(pair)
        if not pair["scored"]:
            pair["reason"] = "at least one trial required a validation RPC fallback"
            continue
        base_cpu = baseline["user_cpu_seconds"] + baseline["system_cpu_seconds"]
        cand_cpu = candidate["user_cpu_seconds"] + candidate["system_cpu_seconds"]
        pair.update({
            "wall_seconds_saved": baseline["wall_seconds"] - candidate["wall_seconds"],
            "wall_gain_fraction": 1 - candidate["wall_seconds"] / baseline["wall_seconds"],
            "cpu_ratio": cand_cpu / base_cpu,
        })
    save(options.output, result)


if __name__ == "__main__":
    main()

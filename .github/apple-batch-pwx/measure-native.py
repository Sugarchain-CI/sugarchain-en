#!/usr/bin/env python3
"""Measure the one predeclared native Mainnet presync matrix."""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import select
import shutil
import signal
import socket
import sys
import time

from pins import ARCHIVE_SHA, HEADER_SHA, HEADER_TIP, ORDER, PEER_DELAY, SETTINGS, SOURCES, file_sha

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "en8-mainnet/overlap"))
from mainnet_paired import first_locator, message, read_message, version_payload, wait_for
from mainnet_probe import check_host, free_port, rpc
from presync_sweep import BATCH, DarwinUsage, GENESIS, prepare_wire, read_fixture


CREDIT = re.compile(rb"PRESYNC proof time credit: peer=(\d+) granted_us=(\d+) remaining_us=(\d+) height=(\d+)\r?$")
COUNTS = re.compile(rb"Apple presync proof kernels: headers=(\d+) original=(\d+) split=(\d+)\r?$")
TRIAL_SECONDS = {1: 100, 3: 75, 8: 180}
MATRIX_SECONDS = 1200
METRICS = ("node_cpu_ns", "wall_ns")


def require(ok, detail):
    if not ok:
        raise ValueError(detail)


def save(path, value):
    temporary = path.with_suffix(".partial")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


class OwnedChild:
    def __init__(self, binary, arguments, environment, actions):
        self.exit_usage = None
        self.started = time.monotonic_ns()
        self.pid = os.posix_spawn(str(binary), [str(binary), *arguments], environment, file_actions=actions)

    def reap(self, options):
        if self.exit_usage is None:
            observed, status, usage = os.wait4(self.pid, options)
            if observed:
                require(observed == self.pid, "Exit receipt came from another process")
                self.exit_usage = {"source": "wait4", "pid": observed, "status": os.waitstatus_to_exitcode(status),
                                   "whole_wall_ns": time.monotonic_ns() - self.started,
                                   "user_cpu_ns": round(usage.ru_utime * 1_000_000_000),
                                   "system_cpu_ns": round(usage.ru_stime * 1_000_000_000)}
        return self.exit_usage

    def await_exit(self, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.reap(os.WNOHANG):
                return True
            time.sleep(0.02)
        return False

    def signal(self, action):
        if self.reap(os.WNOHANG):
            return
        try:
            os.kill(self.pid, action)
        except ProcessLookupError:
            pass


class OwnedNode(OwnedChild):
    def __init__(self, binary, case, workers, peer_port):
        self.case = case
        self.rpc_port = free_port()
        self.shutdown = "none"
        self.stop_receipt = {"rpc": "unattempted"}
        self.flags = ["-chain=main", f"-datadir={case}", "-server=1", f"-rpcport={self.rpc_port}",
                      "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-disablewallet=1", "-listen=0", "-discover=0",
                      "-listenonion=0", "-logtimemicros=1", "-printtoconsole=0", f"-parpow={workers}",
                      f"-connect=127.0.0.1:{peer_port}", "-v2transport=0", "-dnsseed=0", "-fixedseeds=0", "-dns=0",
                      "-debug=net", "-debug=bench", "-loglevel=debug"]
        environment = {**os.environ, "XDG_CONFIG_HOME": str(case / "config"), "XDG_DATA_HOME": str(case / "data"),
                       "CFFIXED_USER_HOME": str(case)}
        with (case / "console.log").open("xb") as console:
            actions = [(os.POSIX_SPAWN_DUP2, console.fileno(), stream) for stream in (1, 2)]
            super().__init__(binary, self.flags, environment, actions)

    def stop(self):
        if self.reap(os.WNOHANG):
            return
        try:
            acknowledged = rpc(self.case, self.rpc_port, "stop") is not None
        except Exception as error:
            self.stop_receipt.update(rpc="error", error=f"{type(error).__name__}: {error}")
        else:
            self.stop_receipt["rpc"] = "acknowledged" if acknowledged else "no_response"
            if acknowledged:
                self.shutdown = "rpc"
                if self.await_exit(10):
                    return
        self.shutdown = "term"
        self.signal(signal.SIGTERM)
        if self.await_exit(4):
            return
        self.shutdown = "kill"
        self.signal(signal.SIGKILL)
        self.reap(0)


def next_request(peer, locator, deadline):
    while time.monotonic() < deadline:
        command, payload = read_message(peer, deadline)
        if command == b"getheaders":
            require(first_locator(payload) == locator, "Unexpected or duplicate GETHEADERS locator")
            return time.perf_counter_ns()
        if command == b"ping":
            peer.sendall(message(b"pong", payload))
    raise TimeoutError("No matching GETHEADERS request")


def final_credit(node, height, deadline):
    path = node.case / "debug.log"
    require(path.is_file(), "Node proof log is missing")
    with path.open("rb") as log:
        while time.monotonic() < deadline:
            if node.reap(os.WNOHANG):
                raise RuntimeError(f"Node exited before reaching the proof barrier: {node.exit_usage}")
            line = log.readline()
            if not line or not line.endswith(b"\n"):
                if line:
                    log.seek(-len(line), os.SEEK_CUR)
                time.sleep(0.01)
                continue
            match = CREDIT.search(line.rstrip(b"\n"))
            if match:
                peer, amount, remaining, observed = map(int, match.groups())
                if observed == height and amount > 0:
                    return time.perf_counter_ns(), {"peer": peer, "grant_us": amount, "remaining_us": remaining, "height": observed}
    raise TimeoutError("Verified final credit marker did not arrive")


def sample(usage, pid):
    r = usage.process(pid)
    return {"pid": pid, "start_ticks": r.proc_start, "exit_ticks": r.proc_exit,
            "user_ticks": r.user, "system_ticks": r.system}


def cpu_ns(samples, timebase):
    ticks = samples["user_ticks"] + samples["system_ticks"]
    return ticks * timebase.numer // timebase.denom


CPU_CALIBRATION_CHILD = """
import os
import time

os.write(1, b"R")
assert os.read(0, 1) == b"G"
cpu_until = time.thread_time_ns() + 160_000_000
wall_until = time.monotonic() + 1.5
while time.thread_time_ns() < cpu_until and time.monotonic() < wall_until:
    pass
os.write(1, b"B")
assert os.read(0, 1) == b"Q"
"""


def calibration_marker(fd, marker):
    readable, _, _ = select.select([fd], [], [], 4)
    require(readable and os.read(fd, 1) == marker, "CPU calibration child missed its barrier")


def calibrate(usage, receipt):
    commands = os.pipe()
    ready = os.pipe()
    child = None
    try:
        actions = [(os.POSIX_SPAWN_DUP2, commands[0], 0), (os.POSIX_SPAWN_DUP2, ready[1], 1)]
        child = OwnedChild(sys.executable, ["-I", "-S", "-c", CPU_CALIBRATION_CHILD], os.environ, actions)
        receipt["pid"] = child.pid
        calibration_marker(ready[0], b"R")
        receipt["start"] = sample(usage, child.pid)
        time.sleep(0.16)
        receipt["idle"] = sample(usage, child.pid)
        os.write(commands[1], b"G")
        calibration_marker(ready[0], b"B")
        receipt["busy"] = sample(usage, child.pid)
        os.write(commands[1], b"Q")
        require(child.await_exit(4), "CPU calibration child did not exit")
    finally:
        if child is not None:
            if child.exit_usage is None:
                child.signal(signal.SIGKILL)
                child.reap(0)
            receipt["exit_accounting"] = child.exit_usage
        for fd in commands + ready:
            os.close(fd)
    start, idle, busy = (receipt[phase] for phase in ("start", "idle", "busy"))
    require(start["start_ticks"] == idle["start_ticks"] == busy["start_ticks"] > 0 and
            start["exit_ticks"] == idle["exit_ticks"] == busy["exit_ticks"] == 0,
            "CPU calibration measurements do not describe a single live child")
    live = cpu_ns(busy, usage.timebase)
    final = receipt["exit_accounting"]
    final_cpu = final["user_cpu_ns"] + final["system_cpu_ns"]
    receipt.update(idle_cpu_ns=cpu_ns(idle, usage.timebase) - cpu_ns(start, usage.timebase),
                   busy_cpu_ns=live - cpu_ns(idle, usage.timebase), live_total_cpu_ns=live, exit_total_cpu_ns=final_cpu)
    require(final["status"] == 0 and 0 <= receipt["idle_cpu_ns"] <= 25_000_000 and
            100_000_000 <= receipt["busy_cpu_ns"] <= 250_000_000 and abs(live - final_cpu) <= 25_000_000,
            "Mach timebase calibration disagrees with idle/busy barriers or independent wait4 CPU")
    receipt["status"] = "matched_wait4"


def scoring_counts(rows, role, workers, height):
    expected = ([(BATCH, BATCH, 0)] + [(BATCH, 1, BATCH - 1)] * (height // BATCH - 1) if role == "candidate" and workers == 8
                else [(BATCH, BATCH, 0)] * (height // BATCH))
    require(rows == expected, f"Unexpected kernel routing or proof-cache hits: {rows}")
    return {"original": sum(row[1] for row in rows), "split": sum(row[2] for row in rows), "frames": rows}


def check_accounting(row):
    before, after = row["cpu_before"], row["cpu_after"]
    final = row["exit_accounting"]
    require(before["pid"] == after["pid"] == final["pid"] and before["start_ticks"] > 0 and
            before["start_ticks"] == after["start_ticks"] and before["exit_ticks"] == after["exit_ticks"] == 0,
            "The before/after CPU samples do not belong to the same live process")
    tolerance = 10_000_000
    require(row["wall_ns"] > 0 and min(row["node_user_cpu_ns"], row["node_system_cpu_ns"]) >= 0 and
            row["node_cpu_ns"] * 16 >= row["wall_ns"] and
            row["node_cpu_ns"] <= row["logical_cpus"] * row["wall_ns"] + tolerance, "Invalid live node CPU or wall interval")
    total_exit = final["user_cpu_ns"] + final["system_cpu_ns"]
    require(final["source"] == "wait4" and final["status"] == 0 and row["shutdown"] == "rpc" and
            min(final["user_cpu_ns"], final["system_cpu_ns"]) >= 0 and final["whole_wall_ns"] >= row["wall_ns"] and
            total_exit + tolerance >= row["node_cpu_ns"], "Clean child exit accounting does not cover the measured CPU interval")


def trial(binary, case, role, workers, height, locators, frames, usage, row, matrix_deadline):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(min(30, max(0.1, matrix_deadline - time.monotonic())))
        peer_port = listener.getsockname()[1]
        node = OwnedNode(binary, case, workers, peer_port)
        row["node_flags"] = node.flags
        measurement_error = None
        try:
            peer, _ = listener.accept()
            with peer:
                deadline = min(matrix_deadline, time.monotonic() + TRIAL_SECONDS[workers])
                peer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                wait_for(peer, b"version", deadline)
                peer.sendall(message(b"version", version_payload(peer_port, starting_height=height)) + message(b"verack", b""))
                wait_for(peer, b"verack", deadline)
                requested = next_request(peer, locators[0], deadline)
                row["cpu_before"] = sample(usage, node.pid)
                wire = row["wire"] = []
                for index, frame in enumerate(frames):
                    remaining = requested / 1_000_000_000 + PEER_DELAY - time.perf_counter()
                    if remaining > 0:
                        time.sleep(remaining)
                    sent = time.perf_counter_ns()
                    peer.sendall(frame)
                    wire.append({"height": (index + 1) * BATCH, "requested_ns": requested, "sent_ns": sent})
                    if index + 1 < len(frames):
                        requested = next_request(peer, locators[index + 1], deadline)
                completed, row["credit"] = final_credit(node, height, deadline)
                row["cpu_after"] = sample(usage, node.pid)
                row["wall_ns"] = completed - wire[0]["requested_ns"]
                peers = rpc(case, node.rpc_port, "getpeerinfo")
                require(peers and len(peers) == 1 and peers[0].get("id") == row["credit"]["peer"] and
                        peers[0].get("presynced_headers") == height and peers[0].get("permissions") == [],
                        "Final proof marker lacks a matching ordinary peer RPC barrier")
                row["peer"] = {key: peers[0][key] for key in ("id", "presynced_headers", "permissions")}
                row["final_request_ns"] = next_request(peer, locators[-1], deadline)
                quiet_until = time.monotonic() + 0.05
                while time.monotonic() < quiet_until:
                    try:
                        command, payload = read_message(peer, quiet_until)
                    except TimeoutError:
                        break
                    require(command != b"getheaders", "Duplicate request after final presync proof")
                    if command == b"ping":
                        peer.sendall(message(b"pong", payload))
                state = rpc(case, node.rpc_port, "getblockchaininfo")
                require(state and state["chain"] == "main" and state["blocks"] == 0 and state["headers"] == 0 and
                        state["initialblockdownload"] is True and rpc(case, node.rpc_port, "getblockhash", 0) == GENESIS,
                        "The stock minimum work boundary was crossed or the chain differs")
                row["chain_state"] = {key: state[key] for key in ("chain", "blocks", "headers", "initialblockdownload")}
        except BaseException as error:
            measurement_error = error
            raise
        finally:
            try:
                node.stop()
            except Exception as error:
                row["cleanup_error"] = f"{type(error).__name__}: {error}"
                if measurement_error is None:
                    raise
            finally:
                row["exit_accounting"] = node.exit_usage
                row["shutdown"] = node.shutdown
                row["cleanup"] = node.stop_receipt
    log = (case / "debug.log").read_bytes()
    require(b"Shutdown done" in log, "The node did not finish clean shutdown")
    observed = [tuple(map(int, match.groups())) for line in log.splitlines() if (match := COUNTS.search(line))]
    row["proofs"] = scoring_counts(observed, role, workers, height)
    before, after = row["cpu_before"], row["cpu_after"]
    for field in ("user", "system"):
        ticks = after[f"{field}_ticks"] - before[f"{field}_ticks"]
        row[f"node_{field}_cpu_ns"] = ticks * usage.timebase.numer // usage.timebase.denom
    row["node_cpu_ns"] = row["node_user_cpu_ns"] + row["node_system_cpu_ns"]
    check_accounting(row)


def evaluate(trials):
    require(len(trials) == 12 and all(row["status"] == "verified" for row in trials), "Incomplete native comparison")
    comparisons = []
    for offset, (workers, _) in enumerate(SETTINGS):
        group = trials[offset * 4:offset * 4 + 4]
        require(tuple(row["role"] for row in group) == ORDER and all(row["workers"] == workers for row in group),
                "Native comparison order changed")
        maximum = 92 if workers == 8 else 101
        for order, (control, candidate) in enumerate(((group[0], group[1]), (group[3], group[2])), 1):
            for metric in METRICS:
                comparisons.append({"workers": workers, "order": order, "metric": metric,
                                    "candidate_over_control": candidate[metric] / control[metric],
                                    "required_maximum": maximum / 100,
                                    "passed": 100 * candidate[metric] <= maximum * control[metric]})
    return {"eligible_for_further_validation": all(item["passed"] for item in comparisons), "comparisons": comparisons}


def run(options):
    check_host()
    require(platform.system() == "Darwin" and platform.machine() == "arm64", "Only native Apple ARM64 is eligible")
    require(file_sha(options.headers) == ARCHIVE_SHA, "Authentic header archive digest differs")
    headers = read_fixture(options.headers, HEADER_SHA, HEADER_TIP)
    manifest_path = options.binaries / "native-builds.json"
    manifest = json.loads(manifest_path.read_bytes())
    binaries = {}
    for role in SOURCES:
        identity = manifest["roles"][role]
        binary = (options.binaries / role / "sugarchaind").resolve(strict=True)
        require((identity["build"]["source"], identity["build"]["tree"]) == SOURCES[role] and
                file_sha(binary) == identity["runtime"]["sugarchaind"]["native_sha256"], "Native binary identity differs")
        binaries[role] = binary
    usage = DarwinUsage()
    logical_cpus = os.cpu_count()
    require(logical_cpus and logical_cpus > 0, "Could not determine the native runner CPU count")
    node_root = options.case_root.resolve()
    directory = options.output.resolve()
    require(node_root != directory and node_root not in directory.parents and directory not in node_root.parents,
            "Node data and evidence must have separate roots")
    node_root.mkdir()
    options.output.mkdir()
    result = {"status": "in_progress", "native_builds_sha256": file_sha(manifest_path), "fixture_raw_sha256": HEADER_SHA,
              "fixture_archive_sha256": ARCHIVE_SHA, "minimum_chain_work": "stock", "peer_delay_seconds": PEER_DELAY,
              "order": ORDER, "settings": SETTINGS, "cpu_metric": "live node process interval with independent wait4 cross-check",
              "mach_timebase": [usage.timebase.numer, usage.timebase.denom], "cpu_calibration": {}, "trials": []}
    start = time.monotonic()
    try:
        calibrate(usage, result["cpu_calibration"])
        for workers, height in SETTINGS:
            locators, frames = prepare_wire(headers[:height])
            for index, role in enumerate(ORDER, 1):
                require(time.monotonic() < start + MATRIX_SECONDS, "Fixed native matrix deadline expired")
                case = node_root / f"workers-{workers}-{index}-{role}"
                case.mkdir()
                row = {"role": role, "workers": workers, "run": index, "height": height, "case": case.name,
                       "fixture_prefix_tip": locators[-1][::-1].hex(), "logical_cpus": logical_cpus, "status": "in_progress"}
                result["trials"].append(row)
                try:
                    trial(binaries[role], case, role, workers, height, locators, frames, usage, row, start + MATRIX_SECONDS)
                    row["status"] = "verified"
                except Exception as error:
                    row["status"] = "incomplete"
                    row["error"] = f"{type(error).__name__}: {error}"
                    raise
                finally:
                    # Only public logs and measurements are exported. Node datadirs
                    # are siblings outside the evidence tree.
                    evidence = directory / f"{case.name}.json"
                    save(evidence, row)
                    save(directory / "result.json", result)
                    for name in ("debug.log", "console.log"):
                        source = case / name
                        if source.is_file() and not source.is_symlink():
                            shutil.copyfile(source, directory / f"{case.name}-{name}")
        result["decision"] = evaluate(result["trials"])
        result["status"] = "recorded"
    except Exception as error:
        result["status"] = "inconclusive"
        result["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        result["elapsed_seconds"] = time.monotonic() - start
        save(directory / "result.json", result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binaries", "headers", "case-root", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    run(parser.parse_args())


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Measure adjacent ordinary-header noise between two copies of one native daemon."""

import argparse
from contextlib import ExitStack, contextmanager
import hashlib
import importlib.util
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import time

from retained import digest, require, stage


GITHUB = Path(__file__).resolve().parent.parent
ORDINARY = GITHUB / "apple-ordinary-headers"
sys.path.insert(0, str(ORDINARY))
spec = importlib.util.spec_from_file_location("ordinary", ORDINARY / "measure.py")
ordinary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ordinary)
native = ordinary.native
BATCH = ordinary.BATCH
FLOOR = ordinary.MINIMUM
WARMUP = ("AB", "BA")
SCORED = ("AB", "BA", "BA", "AB", "BA", "AB", "AB", "BA", "AB", "BA", "BA", "AB")
FINAL = FLOOR + BATCH * (len(WARMUP) + len(SCORED))
FOOTPRINT_LIMIT = 3 << 30
RUNTIME_LIMIT = 480
LIMITS = {"wall_ns": {"near": 0.025, "hard": 0.05}, "cpu_ns": {"near": 0.005, "hard": 0.01}}


def fixture(path):
    require(digest(path) == ordinary.ARCHIVE_SHA, "Unexpected header fixture archive")
    headers = native.read_fixture(path, ordinary.RAW_SHA, ordinary.TIP)[:FINAL]
    locators, frames = native.prepare_wire(headers)
    work = ordinary.block_proof(ordinary.GENESIS_BITS)
    exact_work = {}
    for height, header in enumerate(headers, 1):
        work += ordinary.block_proof(struct.unpack_from("<I", header, 72)[0])
        if height >= FLOOR and height % BATCH == 0:
            exact_work[height] = work
    return locators, frames, exact_work


def schedule(locators, frames, work):
    pairs = []
    for index, order in enumerate((*WARMUP, *SCORED), 1):
        height = FLOOR + BATCH * index
        begin, end = height // BATCH - 1, height // BATCH
        pairs.append({"number": index, "warmup": index <= len(WARMUP), "order": order,
                      "previous_height": height - BATCH, "height": height,
                      "previous_hash": locators[begin][::-1].hex(), "hash": locators[end][::-1].hex(),
                      "chainwork": f"{work[height]:064x}",
                      "payload_sha256": hashlib.sha256(frames[begin][24:]).hexdigest(),
                      "arms": {name: {"status": "unstarted"} for name in "AB"}})
    return pairs


def memory_counters():
    output = subprocess.check_output(["/usr/bin/vm_stat"], text=True, timeout=5)
    counts = {}
    for name in ("Pageouts", "Swapouts"):
        match = re.search(rf"^{name}:\s+(\d+)\.$", output, re.MULTILINE)
        require(match is not None, f"Could not read the host {name} counter")
        counts[name.lower()] = int(match[1])
    return counts


def snapshot(usage, node):
    raw = usage.process(node.pid)
    return {"pid": node.pid, "start_ticks": raw.proc_start, "exit_ticks": raw.proc_exit,
            "system_ticks": raw.system, "user_ticks": raw.user, "resident_bytes": raw.resident_size,
            "footprint_bytes": raw.physical_footprint, "pageins": raw.pageins}


def cpu_delta(before, after, timebase, pid):
    require(before["pid"] == after["pid"] == pid and before["start_ticks"] == after["start_ticks"] > 0 and
            before["exit_ticks"] == after["exit_ticks"] == 0, "The same live daemon did not span the measurement")
    values = [(after[k] - before[k]) * timebase.numer // timebase.denom for k in ("user_ticks", "system_ticks")]
    require(min(values) >= 0, "Daemon CPU counters were nonmonotone")
    return sum(values)


def validate_pressure(baseline, current, snapshots):
    require(current == baseline, "Host paging or swap-out occurred during the A/A experiment")
    require(all(s["footprint_bytes"] > 0 for s in snapshots) and
            sum(s["footprint_bytes"] for s in snapshots) <= FOOTPRINT_LIMIT, "The two resident daemons exceed the footprint budget")


def require_quiet_history(node):
    info = native.rpc(node.case, node.rpc_port, "getblockchaininfo")
    history = info["historicalpow"] if isinstance(info, dict) else {}
    require(history.get("state") in ("complete", "disabled") and history.get("historical_trust") is False and
            history.get("remaining") == 0, "The idle daemon can still have historical proof work")
    return history


@contextmanager
def endpoint(binary, folder, work, receipt):
    folder.mkdir()
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(25)
        port = server.getsockname()[1]
        node = ordinary.OrdinaryNode(binary, folder, port, work)
        receipt["flags"] = node.flags
        error = None
        try:
            peer, _ = server.accept()
            with peer:
                yield node, peer, port
        except BaseException as raised:
            error = raised
            raise
        finally:
            try:
                node.stop()
            except Exception as exc:
                receipt["cleanup_error"] = f"{type(exc).__name__}: {exc}"
                if error is None:
                    raise
            finally:
                receipt.update(shutdown=node.shutdown, cleanup=node.stop_receipt, exit_accounting=node.exit_usage)


def reach_floor(target, locators, frames, work, deadline):
    node, peer, port = target
    deadline = min(deadline, time.monotonic() + 150)
    ordinary.handshake(peer, port, deadline)
    batch_count = FLOOR // BATCH
    for _ in range(2):
        for index in range(batch_count):
            ordinary.request(peer, locators[index], deadline)
            peer.sendall(frames[index])
    ordinary.request(peer, locators[batch_count], deadline)
    return ordinary.state(node, FLOOR, locators[batch_count], work[FLOOR])


def deliver(pair, name, targets, locators, frames, work, usage, deadline, logical_cpus):
    other = "B" if name == "A" else "A"
    node, peer, _ = targets[name]
    idle, _, _ = targets[other]
    row = pair["arms"][name]
    row["status"] = "in_progress"
    height = pair["height"]
    end = height // BATCH
    frame = frames[end - 1]
    require(hashlib.sha256(frame[24:]).hexdigest() == pair["payload_sha256"], "The pair's input frame changed")
    log = node.case / "debug.log"
    offset = log.stat().st_size
    deadline = min(deadline, time.monotonic() + 25)
    row["idle_before"] = snapshot(usage, idle)
    row["active_before"] = snapshot(usage, node)
    row["wire_start_ns"] = time.perf_counter_ns()
    peer.sendall(frame)
    row["acceptance_observed_ns"] = ordinary.accepted_at(log, height, locators[end], deadline, offset)
    row["active_after"] = snapshot(usage, node)
    row["idle_after"] = snapshot(usage, idle)
    row["wall_ns"] = row["acceptance_observed_ns"] - row["wire_start_ns"]
    row["cpu_ns"] = cpu_delta(row["active_before"], row["active_after"], usage.timebase, node.pid)
    row["idle_cpu_ns"] = cpu_delta(row["idle_before"], row["idle_after"], usage.timebase, idle.pid)
    row["idle_cpu_limit_ns"] = max(10_000_000, row["wall_ns"] // 100)
    require(row["wall_ns"] > 0 and row["wall_ns"] // 16 <= row["cpu_ns"] <= logical_cpus * row["wall_ns"] + 10_000_000,
            "Active CPU interval was impossible")
    require(row["idle_cpu_ns"] <= row["idle_cpu_limit_ns"], "The inactive node was not idle")
    for boundary in ("before", "after"):
        samples = [row[f"{role}_{boundary}"] for role in ("active", "idle")]
        require(all(s["footprint_bytes"] > 0 for s in samples) and
                sum(s["footprint_bytes"] for s in samples) <= FOOTPRINT_LIMIT,
                "The two resident daemons exceeded the footprint budget")
    row["accepted_index"] = ordinary.state(node, height, locators[end], work[height])
    ordinary.request(peer, locators[end], deadline)
    row["next_request_confirmed_ns"] = time.perf_counter_ns()
    row["status"] = "verified"


def signed_difference(a, b):
    require(a > 0 and b > 0, "A noise pair must contain two positive measurements")
    return 2 * (b - a) / (a + b)


def evaluate(pairs):
    scored = [pair for pair in pairs if not pair["warmup"]]
    require(len(scored) == len(SCORED) and tuple(pair["order"] for pair in scored) == SCORED, "Fixed scored sequence differs")
    results = []
    for pair in scored:
        a, b = (pair["arms"][arm] for arm in "AB")
        require(a["status"] == b["status"] == "verified", "Incomplete scored A/A comparison")
        differences = {metric: signed_difference(a[metric], b[metric]) for metric in LIMITS}
        results.append({"number": pair["number"], "order": pair["order"], "signed_ratios": differences,
                        "within_near": all(abs(differences[m]) <= limits["near"] for m, limits in LIMITS.items()),
                        "within_hard": all(abs(differences[m]) <= limits["hard"] for m, limits in LIMITS.items())})
    medians = {order: {metric: statistics.median(row["signed_ratios"][metric] for row in results if row["order"] == order)
                       for metric in LIMITS} for order in ("AB", "BA")}
    separation = {metric: abs(medians["AB"][metric] - medians["BA"][metric]) for metric in LIMITS}
    near = sum(row["within_near"] for row in results)
    hard = sum(row["within_hard"] for row in results)
    passes = near >= 11 and hard == 12 and all(separation[m] <= limits["near"] for m, limits in LIMITS.items())
    return {"status": "PASS" if passes else "FAIL", "near_pairs": near, "hard_pairs": hard,
            "order_medians": medians, "median_separation": separation, "scored_pairs": results}


def verify_shutdowns(pairs, receipts, cases):
    for name, receipt in receipts.items():
        exit = receipt["exit_accounting"]
        times = [pair["arms"][name] for pair in pairs]
        require(receipt["shutdown"] == "rpc" and receipt["cleanup"]["rpc"] == "acknowledged" and
                exit["source"] == "wait4" and exit["status"] == 0 and
                b"Shutdown done" in (cases / name / "debug.log").read_bytes(), "An owned daemon did not shut down cleanly")
        require(all(arm["active_after"]["pid"] == exit["pid"] for arm in times), "Final receipt belongs to a different daemon")
        cpu = exit["user_cpu_ns"] + exit["system_cpu_ns"]
        require(cpu + 10_000_000 >= sum(arm["cpu_ns"] for arm in times), "Final CPU receipt did not cover sequential intervals")


def run(args):
    require(platform.system() == "Darwin" and platform.machine() == "arm64", "Native Apple ARM64 is required")
    native.check_host()
    out, cases = args.output.resolve(), args.case_root.resolve()
    require(cases != out and cases not in out.parents and out not in cases.parents, "Test datadirs must be separate from evidence")
    out.mkdir()
    cases.mkdir()
    usage = native.DarwinUsage()
    cap = os.cpu_count()
    require(cap and cap > 0, "Could not determine runner CPU count")
    result = {"schema": 1, "status": "in_progress", "scope": "isolated genuine early Mainnet, private height-32000 work floor",
              "calibration": {}, "mach_timebase": [usage.timebase.numer, usage.timebase.denom], "cpu_count": cap,
              "retention": "all scheduled arms retained, including unstarted and incomplete arms",
              "limits": {"ratios": LIMITS, "near_pairs": 11, "hard_pairs": 12, "footprint_bytes": FOOTPRINT_LIMIT,
                         "idle_cpu": "max(10 ms, 1 percent of measured wall time)", "runtime_seconds": RUNTIME_LIMIT},
              "nodes": {name: {} for name in "AB"}, "memory": []}
    deadline = time.monotonic() + RUNTIME_LIMIT

    def save():
        native.save(out / "result.json", result)

    try:
        binary, result["binary"] = stage(args.artifact, cases / "daemon")
        locators, frames, work = fixture(args.headers)
        result["fixture"] = {"archive_sha256": ordinary.ARCHIVE_SHA, "header_sha256": ordinary.RAW_SHA,
                             "setup_height": FLOOR, "setup_work": f"{work[FLOOR]:064x}", "final_height": FINAL}
        pairs = result["pairs"] = schedule(locators, frames, work)
        save()
        native.calibrate(usage, result["calibration"])
        initial_memory = memory_counters()
        result["memory"].append({"after": "pre_setup", **initial_memory})
        with ExitStack() as exits:
            targets = {}
            for name in "AB":
                row = result["nodes"][name]
                targets[name] = exits.enter_context(endpoint(binary, cases / name, work[FLOOR], row))
                row["floor"] = reach_floor(targets[name], locators, frames, work, deadline)
                row["historicalpow"] = require_quiet_history(targets[name][0])
                save()
            current = memory_counters()
            footprints = [snapshot(usage, target[0]) for target in targets.values()]
            result["memory"].append({"after": "setup", "nodes": footprints, **current})
            validate_pressure(initial_memory, current, footprints)
            previous_end = 0
            for pair in pairs:
                require(time.monotonic() < deadline, "A/A runtime budget expired")
                for name in pair["order"]:
                    arm = pair["arms"][name]
                    try:
                        deliver(pair, name, targets, locators, frames, work, usage, deadline, cap)
                        require(previous_end <= arm["wire_start_ns"] and
                                arm["wire_start_ns"] < arm["acceptance_observed_ns"] <= arm["next_request_confirmed_ns"],
                                "Ordinary header intervals overlapped")
                        previous_end = arm["next_request_confirmed_ns"]
                    except Exception as error:
                        arm.update(status="incomplete", error=f"{type(error).__name__}: {error}")
                        raise
                    finally:
                        save()
                current = memory_counters()
                footprints = [snapshot(usage, target[0]) for target in targets.values()]
                result["memory"].append({"after": pair["number"], "nodes": footprints, **current})
                validate_pressure(initial_memory, current, footprints)
            for name, target in targets.items():
                result["nodes"][name]["final_historicalpow"] = require_quiet_history(target[0])
        verify_shutdowns(pairs, result["nodes"], cases)
        result["decision"] = evaluate(pairs)
        result["status"] = result["decision"]["status"]
        print(f"A/A noise gate {result['status']}")
    except Exception as error:
        result.update(status="INCONCLUSIVE", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        save()
        for name in "AB":
            for log in ("debug.log", "console.log"):
                path = cases / name / log
                if path.is_file() and not path.is_symlink():
                    shutil.copyfile(path, out / f"{name}-{log}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("artifact", "headers", "case-root", "output"):
        parser.add_argument(f"--{arg}", type=Path, required=True)
    run(parser.parse_args())

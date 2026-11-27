#!/usr/bin/env python3
"""Compare Regtest 100,000 synchronization with body-phase net logging on and off."""

import argparse
from datetime import datetime
import hashlib
import http.client
import importlib.util
import json
import math
from pathlib import Path
import platform
import re
import sys
import time

COMMON_SHA = "d712a428c7bf29cab49827daf60e85f5d7196b5bf82c56c888ab5b73c7c5d714"
ABBA = ("net", "body-net-off", "body-net-off", "net")
COUNTERS = ("cpu_user_seconds", "cpu_system_seconds", "read_bytes", "write_bytes")
LINUX_LOGICAL_COUNTERS = ("rchar", "wchar", "syscr", "syscw")
TIMESTAMP = re.compile(rb"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z) ")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def load_module(path, name, digest=None):
    path = path.resolve(strict=True)
    if digest:
        with path.open("rb") as source:
            require(hashlib.file_digest(source, "sha256").hexdigest() == digest, "Common harness SHA-256 mismatch")
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"Cannot load module {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def resources(resource_module, node):
    pid = node.proc.pid
    snapshot = resource_module.sample(pid)
    require(isinstance(snapshot, dict), "Process resource helper did not return an object")
    require(snapshot.get("pid", pid) == pid, "Resource snapshot belongs to a different process")
    require(type(snapshot.get("process_start_identity")) in (str, int)
            and bool(snapshot["process_start_identity"]), "Missing process creation identity")
    require(isinstance(snapshot.get("io_byte_semantics"), str)
            and bool(snapshot["io_byte_semantics"]), "Missing process I/O byte semantics")
    for counter in COUNTERS:
        value = snapshot.get(counter)
        if counter.endswith("_bytes"):
            valid = type(value) is int and value >= 0
        else:
            valid = type(value) in (int, float) and math.isfinite(value) and value >= 0
        require(valid, f"Unavailable or invalid {counter}")
    return {**snapshot, "pid": pid}


def delta(before, after):
    require(before["pid"] == after["pid"] and before["process_start_identity"] == after["process_start_identity"],
            "Resource samples do not belong to the same live process")
    require(before["io_byte_semantics"] == after["io_byte_semantics"], "Process I/O semantics changed")
    keys = list(COUNTERS)
    keys.extend(key for key in LINUX_LOGICAL_COUNTERS if key in before and key in after)
    values = {key: after[key] - before[key] for key in keys}
    require(all(value >= 0 for value in values.values()), "Process resource counters decreased")
    return values


def short_state(state, node):
    return {
        "seconds_since_launch": time.perf_counter() - node.started,
        "blocks": state["blocks"], "headers": state["headers"],
        "initialblockdownload": state["initialblockdownload"],
    }


def change_logging(node, receiver, deadline, net_enabled):
    before = time.perf_counter()
    require(before < deadline, "Timed out before applying logging treatment")
    include, exclude = (["net"], []) if net_enabled else ([], ["net"])
    categories = node.rpc("logging", include, exclude, timeout=min(3.0, deadline - before))
    after = time.perf_counter()
    require(categories.get("net") is net_enabled, f"logging RPC did not set net={net_enabled}")
    require(after <= deadline, "Logging RPC exceeded synchronization deadline")
    return {"request_start_seconds": before - receiver.started,
            "request_complete_seconds": after - receiver.started, "net_enabled": net_enabled}


def await_treated_tip(m, receiver, sender, info, cap_seconds, net_enabled, timing):
    deadline = receiver.started + cap_seconds
    last_state = None
    last_error = None
    while (remaining := deadline - time.perf_counter()) > 0:
        require(receiver.proc.poll() is None, "Receiver exited before synchronization endpoint")
        require(sender.proc.poll() is None, "Sender exited before synchronization endpoint")
        try:
            state = receiver.rpc("getblockchaininfo", timeout=min(remaining, 1.0))
        except (OSError, http.client.HTTPException, m.RpcError) as exc:
            last_error = str(exc)
        else:
            observed = time.perf_counter()
            require(state["chain"] == "regtest", "Wrong network from receiver RPC")
            require(state["blocks"] <= state["headers"] <= m.HEIGHT, "Receiver exceeded pinned height")
            last_state = short_state(state, receiver)
            timing.setdefault("first_rpc", last_state)
            if state["headers"] == m.HEIGHT and "switch" not in timing:
                require(state["blocks"] < m.HEIGHT and state["initialblockdownload"] is True,
                        "Full headers were first observed after the body treatment window")
                timing["switch"] = {"before": last_state, "target_net_enabled": net_enabled}
                for name, node in (("receiver", receiver), ("sender", sender)):
                    timing["switch"][name] = change_logging(node, receiver, deadline, net_enabled)
                continue
            if "switch" in timing:
                timing["switch"].setdefault("first_observation_after", last_state)
            if state["initialblockdownload"] is False:
                require(state["headers"] == state["blocks"] == m.HEIGHT, "IBD cleared before the pinned height")
                require(state["bestblockhash"] == info["tip"] and state["chainwork"] == info["chainwork"],
                        "IBD cleared at wrong tip or cumulative work")
                require("switch" in timing and observed <= deadline, "Missing bounded logging treatment")
                timing["endpoint"] = {
                    "startup_to_ibd_clear_seconds": observed - receiver.started,
                    "blocks": m.HEIGHT, "headers": m.HEIGHT, "initialblockdownload": False,
                    "bestblockhash": state["bestblockhash"], "chainwork": state["chainwork"],
                }
                return
        time.sleep(0.025)
    raise TimeoutError(f"Target not reached in {cap_seconds}s, last progress {last_state}, last RPC error {last_error}")


def timestamp(line):
    matched = TIMESTAMP.match(line)
    require(matched, "Missing wall timestamp on debug phase marker")
    return matched[1]


def collect_log_counts(receiver, sender, phases):
    begin_line = phases["redownload_completed"]["line"]
    end_line = phases["body_progress"]["line"]
    begin = end = None
    receiver_count = 0
    receiver_bytes = 0
    with receiver.debug.open("rb") as log:
        for number, line in enumerate(log, 1):
            if number == begin_line:
                begin = timestamp(line)
            if begin_line < number < end_line and b" [net] " in line:
                receiver_count += 1
                receiver_bytes += len(line)
            if number == end_line:
                end = timestamp(line)
                break
    require(begin and end and begin < end, "Invalid post-REDOWNLOAD log interval")
    sender_count = 0
    sender_bytes = 0
    with sender.debug.open("rb") as log:
        for line in log:
            if b" [net] " in line:
                stamp = timestamp(line)
                if begin <= stamp <= end:
                    sender_count += 1
                    sender_bytes += len(line)
    begin_text = begin.decode("ascii")
    end_text = end.decode("ascii")
    suffix = datetime.fromisoformat(end_text.replace("Z", "+00:00")) - datetime.fromisoformat(begin_text.replace("Z", "+00:00"))
    return {"start_utc": begin_text, "end_utc": end_text,
            "header_release_to_tip_seconds": suffix.total_seconds(),
            "receiver_net_lines": receiver_count, "receiver_net_log_bytes": receiver_bytes,
            "sender_net_lines": sender_count, "sender_net_log_bytes": sender_bytes}


def run_case(m, resource_module, sender_exe, receiver_exe, fixture, info, directory, profile, cap_seconds):
    directory.mkdir()
    result = {"status": "failed", "profile": profile, "timing": {}, "process_resources": {}, "cleanup": {}}
    samples = result["process_resources"]
    sender = receiver = None
    try:
        sender = m.Node(sender_exe, directory / "sender", info, fixture=fixture)
        sender.start()
        prepared = m.await_tip(sender, 300, info)
        sender.verify_process()
        result["sender_preparation"] = {
            "seconds": prepared["startup_to_ibd_clear_seconds"],
            "tip_proof": m.tip_proof(sender, info),
            "utxo": m.utxo(sender, info),
        }
        receiver = m.Node(receiver_exe, directory / "receiver", info, peer_port=sender.p2p_port)
        samples["sender_before_receiver_launch"] = resources(resource_module, sender)
        receiver.start()
        samples["receiver_immediately_after_launch"] = resources(resource_module, receiver)
        await_treated_tip(m, receiver, sender, info, cap_seconds, profile == "net", result["timing"])
        samples["receiver_at_rpc_endpoint"] = resources(resource_module, receiver)
        samples["sender_at_rpc_endpoint"] = resources(resource_module, sender)
        samples["receiver_since_birth"] = {key: samples["receiver_at_rpc_endpoint"][key] for key in COUNTERS}
        samples["receiver_after_launch_delta"] = delta(samples["receiver_immediately_after_launch"],
                                                        samples["receiver_at_rpc_endpoint"])
        samples["sender_during_receiver_delta"] = delta(samples["sender_before_receiver_launch"],
                                                        samples["sender_at_rpc_endpoint"])
        receiver.verify_process()
        result["phases"] = m.phase_evidence(receiver.debug)
        result["post_headers_net_log"] = collect_log_counts(receiver, sender, result["phases"])
        result["tip_proof"] = m.tip_proof(receiver, info)
        result["verifychain"] = m.verify_chain(receiver, cap_seconds)
        result["utxo"] = m.utxo(receiver, info)
        result["status"] = "passed"
    except (RuntimeError, OSError, TimeoutError, ValueError, KeyError, TypeError, http.client.HTTPException) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        for name, node in (("receiver", receiver), ("sender", sender)):
            if node is not None:
                receipt = node.close()
                result["cleanup"][name] = receipt
                if not m.successful_close(receipt):
                    result["status"] = "failed"
                    result.setdefault("error", f"{name} did not complete controlled shutdown")
        m.write_json(directory / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--common", required=True, type=Path)
    parser.add_argument("--resources", required=True, type=Path)
    parser.add_argument("--sender", required=True, type=Path)
    parser.add_argument("--receiver", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--fixture-info", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--platform", choices=("linux", "windows", "macos"), required=True)
    parser.add_argument("--arch", choices=("x86_64", "arm64", "armhf", "ppc64", "riscv64"), required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--receiver-sha256", required=True)
    parser.add_argument("--trial-seconds", type=int, default=300)
    args = parser.parse_args()
    require(args.work_dir.is_absolute(), "Use an absolute new work directory")
    work = args.work_dir.resolve()
    work.mkdir()
    out = {"schema": 1, "status": "failed", "diagnostic": "regtest100k-body-net-log-abba",
           "sequence": list(ABBA), "cases": [],
           "platform": args.platform, "architecture": args.arch,
           "emulation": False, "os_release": platform.release(), "common_harness_sha256": COMMON_SHA,
           "counter_scope": "Cumulative owned-process snapshots; final snapshots immediately after target RPC"}
    try:
        m = load_module(args.common, "regtest100k_common", COMMON_SHA)
        out.update(release_source=m.RELEASE_SOURCE, release_tree=m.RELEASE_TREE)
        resource_module = load_module(args.resources, "resource_metrics")
        require(callable(getattr(resource_module, "sample", None)), "Resource module must export sample(pid)")
        require(1 <= args.trial_seconds <= 300, "Trial limit must be between 1 and 300 seconds")
        require(re.fullmatch(r"[0-9a-f]{64}", args.archive_sha256), "Invalid archive digest")
        require(re.fullmatch(r"[0-9a-f]{64}", args.receiver_sha256), "Invalid receiver digest")
        fixture = args.fixture.resolve(strict=True)
        info = m.fixture_metadata(args.fixture_info.resolve(strict=True), fixture)
        out["fixture"] = info
        out["machine"] = m.native_environment(args.platform, args.arch)
        sender_exe = args.sender.resolve(strict=True)
        receiver_exe = args.receiver.resolve(strict=True)
        for binary in (sender_exe, receiver_exe):
            m.verify_binary(binary, args.platform, args.arch)
        receiver_sha = m.sha256_file(receiver_exe)
        require(receiver_sha == args.receiver_sha256, "Receiver executable SHA-256 mismatch")
        require(m.sha256_file(sender_exe) == receiver_sha, "Diagnostic sender/receiver release binaries differ")
        out["archive_sha256"] = args.archive_sha256
        out["receiver_sha256"] = receiver_sha
        out["trial_deadline_seconds"] = args.trial_seconds
        for index, profile in enumerate(ABBA, 1):
            case = run_case(m, resource_module, sender_exe, receiver_exe, fixture, info,
                            work / f"case-{index:02}", profile, args.trial_seconds)
            out["cases"].append({"number": index, **case})
            m.write_json(work / "result.json", out)
            require(all(c["pid"] is None or c["reaped"] for c in case["cleanup"].values()),
                    "An owned child could not be reaped. Remaining cases were not launched.")
        require(all(case["status"] == "passed" for case in out["cases"]), "One or more fixed cases failed")
        times = [case["timing"]["endpoint"]["startup_to_ibd_clear_seconds"] for case in out["cases"]]
        out["matched_pairs"] = [
            {"net_case": a, "body_net_off_case": b, "net_seconds": times[a - 1],
             "body_net_off_seconds": times[b - 1], "net_minus_off_seconds": times[a - 1] - times[b - 1]}
            for a, b in ((1, 2), (4, 3))
        ]
        out["status"] = "passed"
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, ImportError, http.client.HTTPException) as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        path = work / "result.json"
        staging = path.with_suffix(".tmp")
        staging.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
        staging.replace(path)
    print(f"{out['status']} {work / 'result.json'}")
    return int(out["status"] != "passed")


if __name__ == "__main__":
    sys.exit(main())

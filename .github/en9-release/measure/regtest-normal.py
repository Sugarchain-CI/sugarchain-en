#!/usr/bin/env python3
"""Measure stock En.8 Regtest 100,000 synchronization with debug disabled at launch."""

import argparse
import hashlib
import http.client
import importlib.util
import json
import math
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

COMMON_SHA = "d712a428c7bf29cab49827daf60e85f5d7196b5bf82c56c888ab5b73c7c5d714"
MIN_TWO_PASS_HEADERS_BYTES = 16_200_000
MAX_TWO_PASS_HEADERS_BYTES = 16_210_000
COUNTERS = ("cpu_user_seconds", "cpu_system_seconds", "read_bytes", "write_bytes")
LINUX_COUNTERS = ("rchar", "wchar", "syscr", "syscw")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def write_json(path, document):
    stage = path.with_suffix(".tmp")
    stage.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    stage.replace(path)


def load_module(path, name, digest=None):
    path = path.resolve(strict=True)
    if digest:
        with path.open("rb") as src:
            require(hashlib.file_digest(src, "sha256").hexdigest() == digest, "Common harness SHA-256 mismatch")
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"Cannot load module {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def normal_node(m, *args, **kwargs):
    node = m.Node(*args, **kwargs)
    require(node.argv.count("-debug=net") == 1, "Expected one debug option from the pinned common harness")
    node.argv[node.argv.index("-debug=net")] = "-debug=0"
    return node


def sample(module, node):
    pid = node.proc.pid
    data = module.sample(pid)
    require(isinstance(data, dict) and data.get("pid", pid) == pid, "Resource sample has the wrong child identity")
    require(type(data.get("process_start_identity")) in (str, int) and bool(data["process_start_identity"]),
            "Resource sample lacks process creation identity")
    require(isinstance(data.get("io_byte_semantics"), str) and bool(data["io_byte_semantics"]),
            "Resource sample lacks I/O semantics")
    for name in COUNTERS:
        value = data.get(name)
        if name.endswith("_bytes"):
            valid = type(value) is int and value >= 0
        else:
            valid = type(value) in (int, float) and math.isfinite(value) and value >= 0
        require(valid, f"Missing or invalid resource counter {name}")
    return {**data, "pid": pid}


def delta(before, after):
    for name in ("pid", "process_start_identity", "io_byte_semantics"):
        require(before[name] == after[name], f"Resource identity mismatch: {name}")
    fields = [*COUNTERS, *(key for key in LINUX_COUNTERS if key in before and key in after)]
    values = {key: after[key] - before[key] for key in fields}
    require(all(value >= 0 for value in values.values()), "Resource counters decreased")
    return values


def peer_observation(receiver, sender, cap):
    peers = receiver.rpc("getpeerinfo", timeout=cap)
    require(isinstance(peers, list) and len(peers) <= 1, "Unexpected extra or invalid peers")
    if not peers:
        return None
    p = peers[0]
    require(p["addr"] == f"127.0.0.1:{sender.p2p_port}" and p["inbound"] is False,
            "The receiver is connected to an unexpected peer")
    require(type(p["id"]) is int and p["id"] >= 0, "Invalid RPC peer identity")
    count = p["bytesrecv_per_msg"].get("headers", 0)
    require(type(count) is int and count >= 0, "Invalid received HEADERS bytes")
    height = p["presynced_headers"]
    require(type(height) is int and -1 <= height <= 100_000, "Invalid peer PRESYNC height")
    return {
        "peer_id": p["id"], "address": p["addr"], "transport": p["transport_protocol_type"],
        "presynced_headers": height, "accepted_headers": p["synced_headers"],
        "header_bytes": count, "seconds_since_launch": time.perf_counter() - receiver.started,
    }


def verify_two_passes(early, endpoint):
    require(early is not None and endpoint is not None, "Missing early and final same-peer header observations")
    for field in ("peer_id", "address", "transport"):
        require(early[field] == endpoint[field], "PRESYNC and final HEADERS evidence belong to different peers")
    require(early["transport"] in ("v1", "v2"), "Unknown completed peer transport")
    require(0 < early["presynced_headers"] < 100_000 and 81 * early["presynced_headers"] <= early["header_bytes"],
            "Missing positive bounded in-progress PRESYNC evidence")
    require(early["header_bytes"] < MIN_TWO_PASS_HEADERS_BYTES, "Early sample already saw both header passes")
    require(endpoint["presynced_headers"] == -1 and endpoint["accepted_headers"] == 100_000,
            "Expected peer PRESYNC to finish and its accepted header height to reach 100,000")
    require(MIN_TWO_PASS_HEADERS_BYTES <= endpoint["header_bytes"] <= MAX_TWO_PASS_HEADERS_BYTES,
            f"HEADERS byte total does not account for two full passes: {endpoint['header_bytes']}")
    require(early["seconds_since_launch"] < endpoint["seconds_since_launch"], "Peer samples are out of order")


def await_tip(m, receiver, sender, info, cap_seconds, observation, on_full_headers):
    deadline = receiver.started + cap_seconds
    last_rpc_error = None
    last_state = None
    while (remaining := deadline - time.perf_counter()) > 0:
        require(receiver.proc.poll() is None and sender.proc.poll() is None,
                "An owned node exited before the synchronized endpoint")
        try:
            state = receiver.rpc("getblockchaininfo", timeout=min(1.0, remaining))
        except (OSError, http.client.HTTPException, m.RpcError) as exc:
            last_rpc_error = str(exc)
        else:
            observed = time.perf_counter()
            require(state["chain"] == "regtest" and 0 <= state["blocks"] <= state["headers"] <= m.HEIGHT,
                    "Unexpected chain or heights from receiver RPC")
            last_state = {"blocks": state["blocks"], "headers": state["headers"],
                          "initialblockdownload": state["initialblockdownload"],
                          "seconds_since_launch": observed - receiver.started,
                          "observed_utc_ns": time.time_ns()}
            observation.setdefault("first_rpc", last_state)
            if state["headers"] == m.HEIGHT:
                if "first_full_headers" not in observation:
                    require("presync" in observation, "Full headers reached before a positive PRESYNC sample was observed")
                    require(state["blocks"] < m.HEIGHT and state["initialblockdownload"] is True,
                            "Full headers were first observed after body transfer completed")
                    observation["first_full_headers"] = last_state
                    on_full_headers()
            elif "presync" not in observation:
                observation["early_peer_rpc_calls"] += 1
                try:
                    sample_peer = peer_observation(receiver, sender, min(1.0, max(0.001, deadline - time.perf_counter())))
                except (OSError, http.client.HTTPException, m.RpcError) as exc:
                    last_rpc_error = str(exc)
                else:
                    if sample_peer and 0 < sample_peer["presynced_headers"] < m.HEIGHT:
                        # v2 may still be negotiating during initial RPC samples.
                        if sample_peer["transport"] in ("v1", "v2"):
                            sample_peer["last_observed_accepted_header_height"] = state["headers"]
                            observation["presync"] = sample_peer
            if state["initialblockdownload"] is False:
                require(state["blocks"] == state["headers"] == m.HEIGHT and observed <= deadline,
                        "IBD cleared outside the pinned height/deadline")
                require(state["bestblockhash"] == info["tip"] and state["chainwork"] == info["chainwork"],
                        "IBD cleared at unexpected tip or cumulative work")
                observation["endpoint"] = {**last_state, "startup_to_ibd_clear_seconds": observed - receiver.started,
                                           "bestblockhash": state["bestblockhash"], "chainwork": state["chainwork"]}
                return
        time.sleep(0.025 if "presync" in observation else 0.0125)
    raise TimeoutError(f"Target not reached in {cap_seconds}s, last progress {last_state}, last RPC error {last_rpc_error}")


def info_log(node, receiver=False):
    debug_options = 0
    net_debug = 0
    plain_ibd = []
    final_tip = []
    with node.debug.open(encoding="utf-8", errors="replace") as stream:
        for number, line in enumerate(stream, 1):
            if 'Command-line arg: debug="0"' in line:
                debug_options += 1
            if " [net] " in line:
                net_debug += 1
            if receiver:
                if "Leaving InitialBlockDownload (latching to false)" in line:
                    plain_ibd.append({"line": number, "utc": line.split(" ", 1)[0]})
                if f"UpdateTip: new best={node.fixture_tip} height=100000 " in line:
                    final_tip.append({"line": number, "utc": line.split(" ", 1)[0]})
    require(debug_options == 1 and net_debug == 0, "Expected debug=0 from startup and no network debug lines")
    evidence = {"disabled_from_start": True, "network_debug_lines": net_debug}
    if receiver:
        require(len(plain_ibd) == len(final_tip) == 1, "Missing ordinary IBD or pinned active-tip log marker")
        evidence.update(ibd_latch=plain_ibd[0], final_tip=final_tip[0])
    return evidence


def run_case(m, resources, profiler, sender_exe, receiver_exe, fixture, info, directory, gui_args, cap_seconds):
    directory.mkdir()
    result = {"status": "failed", "timing": {"early_peer_rpc_calls": 0}, "process_resources": {}, "cleanup": {}}
    counters = result["process_resources"]
    sender = receiver = profile_session = None
    profile_finished = False

    def start_profile():
        if profile_session is not None:
            profile_session.body_started()

    def finish_profile():
        nonlocal profile_finished
        if profile_session is not None and not profile_finished:
            profile_finished = True
            result["profile"] = profile_session.finish(timeout=30)

    try:
        sender = normal_node(m, sender_exe, directory / "sender", info, fixture=fixture)
        sender.start()
        prep = m.await_tip(sender, 300, info)
        sender.verify_process()
        result["sender_preparation"] = {
            "seconds": prep["startup_to_ibd_clear_seconds"], "tip_proof": m.tip_proof(sender, info),
            "utxo": m.utxo(sender, info),
        }
        receiver = normal_node(m, receiver_exe, directory / "receiver", info, peer_port=sender.p2p_port,
                               gui_args=gui_args)
        receiver.fixture_tip = info["tip"]
        if profiler is not None:
            prepare = getattr(profiler, "prepare", None) or profiler.Profile
            profile_session = prepare(directory / "profile-evidence", sender.proc)
        counters["sender_before_receiver_launch"] = sample(resources, sender)
        result["timing"]["launch_utc_ns"] = time.time_ns()
        receiver.start()
        counters["receiver_immediately_after_launch"] = sample(resources, receiver)
        if profile_session is not None:
            profile_session.attach(receiver.proc)
        await_tip(m, receiver, sender, info, cap_seconds, result["timing"], start_profile)
        counters["receiver_at_rpc_endpoint"] = sample(resources, receiver)
        counters["sender_at_rpc_endpoint"] = sample(resources, sender)
        finish_profile()
        counters["receiver_since_birth"] = {key: counters["receiver_at_rpc_endpoint"][key] for key in COUNTERS}
        counters["receiver_after_launch_delta"] = delta(counters["receiver_immediately_after_launch"],
                                                       counters["receiver_at_rpc_endpoint"])
        counters["sender_during_receiver_delta"] = delta(counters["sender_before_receiver_launch"],
                                                       counters["sender_at_rpc_endpoint"])
        result["timing"]["final_peer"] = peer_observation(receiver, sender, 3.0)
        verify_two_passes(result["timing"]["presync"], result["timing"]["final_peer"])
        result["two_header_passes_verified"] = True
        receiver.verify_process()
        result["info_log"] = {"sender": info_log(sender), "receiver": info_log(receiver, receiver=True)}
        result["tip_proof"] = m.tip_proof(receiver, info)
        result["verifychain"] = m.verify_chain(receiver, cap_seconds)
        result["utxo"] = m.utxo(receiver, info)
        if profiler is not None:
            require(isinstance(result.get("profile"), dict) and result["profile"].get("status") == "passed",
                    "Profile case lacked a qualified scoped profiler receipt")
        result["status"] = "passed"
    except (RuntimeError, OSError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError, http.client.HTTPException) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            finish_profile()
        except (RuntimeError, OSError, ValueError, TypeError, subprocess.SubprocessError) as exc:
            result["profile_finish_error"] = f"{type(exc).__name__}: {exc}"
            result["status"] = "failed"
        for name, node in (("receiver", receiver), ("sender", sender)):
            if node is not None:
                try:
                    close = node.close()
                except OSError as exc:
                    close = {"pid": node.proc.pid if node.proc else None,
                             "reaped": node.proc.poll() is not None if node.proc else False,
                             "errors": [f"{type(exc).__name__}: {exc}"]}
                    result["status"] = "failed"
                    result.setdefault("error", f"{name} could not finish shutdown receipt")
                else:
                    if not m.successful_close(close):
                        result["status"] = "failed"
                        result.setdefault("error", f"{name} did not complete controlled shutdown")
                result["cleanup"][name] = close
        write_json(directory / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for path in ("common", "resources", "sender", "receiver", "fixture", "fixture-info", "work-dir"):
        parser.add_argument(f"--{path}", required=True, type=Path)
    parser.add_argument("--profiler", type=Path)
    parser.add_argument("--platform", choices=("linux", "windows", "macos"), required=True)
    parser.add_argument("--arch", choices=("x86_64", "arm64", "armhf", "ppc64", "riscv64"), required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--receiver-sha256", required=True)
    parser.add_argument("--sender-sha256", help="Default is the verified receiver SHA-256")
    parser.add_argument("--trials", type=int, choices=(1, 3),
                        help="Three fresh trials by default. Profile mode is always one separate case.")
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--gui-arg", action="append", default=[])
    parser.add_argument("--trial-seconds", type=int, default=300)
    args = parser.parse_args()
    require(args.work_dir.is_absolute(), "Use an absolute new work directory")
    work = args.work_dir.resolve()
    work.mkdir()
    root = {"schema": 1, "status": "failed", "diagnostic": "regtest100k-debug-off-from-launch",
            "profiled": args.profiler is not None, "platform": args.platform, "architecture": args.arch,
            "interface": "gui" if args.gui else "cli", "emulation": False,
            "os_release": platform.release(), "common_harness_sha256": COMMON_SHA, "cases": []}
    try:
        m = load_module(args.common, "regtest100k_common", COMMON_SHA)
        root.update(release_source=m.RELEASE_SOURCE, release_tree=m.RELEASE_TREE)
        resources = load_module(args.resources, "resource_metrics")
        require(callable(getattr(resources, "sample", None)), "Resource module must export sample(pid)")
        profiler = load_module(args.profiler, "native_scoped_profiler") if args.profiler else None
        if profiler is not None:
            require(any(callable(getattr(profiler, name, None)) for name in ("prepare", "Profile")),
                    "Profiler module must export prepare or Profile")
        require(1 <= args.trial_seconds <= 300, "Trial limit must be between 1 and 300 seconds")
        require(re.fullmatch(r"[0-9a-f]{64}", args.archive_sha256), "Invalid archive digest")
        require(re.fullmatch(r"[0-9a-f]{64}", args.receiver_sha256), "Invalid receiver executable digest")
        sender_pin = args.sender_sha256 or args.receiver_sha256
        require(re.fullmatch(r"[0-9a-f]{64}", sender_pin), "Invalid sender executable digest")
        require(profiler is None or args.trials != 3, "Profile mode runs one separate case")
        trials = args.trials or (1 if profiler is not None else 3)
        require(args.gui or not args.gui_arg, "GUI arguments require --gui")
        fixture = args.fixture.resolve(strict=True)
        info = m.fixture_metadata(args.fixture_info.resolve(strict=True), fixture)
        root["fixture"] = info
        root["machine"] = m.native_environment(args.platform, args.arch)
        sender_exe = args.sender.resolve(strict=True)
        receiver_exe = args.receiver.resolve(strict=True)
        for binary in (sender_exe, receiver_exe):
            m.verify_binary(binary, args.platform, args.arch)
        receiver_sha = m.sha256_file(receiver_exe)
        require(receiver_sha == args.receiver_sha256, "Receiver executable SHA-256 mismatch")
        sender_sha = m.sha256_file(sender_exe)
        require(sender_sha == sender_pin, "Sender executable SHA-256 mismatch")
        root.update(archive_sha256=args.archive_sha256, receiver_sha256=receiver_sha,
                    sender_sha256=sender_sha, trial_deadline_seconds=args.trial_seconds, trials=trials)
        gui_args = m.gui_arguments(args.gui_arg) if args.gui else None
        names = ("profile",) if profiler is not None else tuple(f"trial-{i:02}" for i in range(1, trials + 1))
        for name in names:
            case = run_case(m, resources, profiler, sender_exe, receiver_exe, fixture, info,
                            work / name, gui_args, args.trial_seconds)
            root["cases"].append({"case": name, **case})
            write_json(work / "result.json", root)
            require(all(c["pid"] is None or c["reaped"] for c in case["cleanup"].values()),
                    "An owned child could not be reaped. Remaining cases were not launched.")
        require(all(case["status"] == "passed" for case in root["cases"]), "One or more fixed cases failed")
        if profiler is None:
            from statistics import median
            root["median_startup_to_ibd_clear_seconds"] = median(
                case["timing"]["endpoint"]["startup_to_ibd_clear_seconds"] for case in root["cases"])
        root["status"] = "passed"
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, ImportError,
            subprocess.SubprocessError, http.client.HTTPException) as exc:
        root["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        write_json(work / "result.json", root)
    print(f"{root['status']} {work / 'result.json'}")
    return int(root["status"] != "passed")


if __name__ == "__main__":
    sys.exit(main())

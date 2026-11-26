#!/usr/bin/env python3
"""Measure request-to-processing delay during stock native Mainnet presync."""

import argparse
from collections import defaultdict
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import time
from urllib.request import ProxyHandler, build_opener, install_opener


SOURCE = "8cae65e954ee78a1b40879c968ef2049d170930e"
TREE = "a9b417f9093256338b09e095c42f8cb114040a65"
GENESIS = "7d5eaec2dbb75f99feadfa524c78b7cabc1d8c8204f79d4f3a83381b811b0adc"
WINDOW_SECONDS = 72
TOTAL_SECONDS = 90
FULL_HEADERS_BYTES = 162_003
STAMP = re.compile(r"^(\S+Z) \[net\] (.*)$")
EVENTS = (
    ("send", re.compile(r"^sending getheaders \(\d+ bytes\) peer=(\d+)$")),
    ("more", re.compile(r"^more getheaders \(from [0-9a-f]{64}\) to peer=(\d+)$")),
    ("receive", re.compile(r"^received: headers \((\d+) bytes\) peer=(\d+)$")),
    ("credit", re.compile(r"^PRESYNC proof time credit: peer=(\d+) granted_us=(\d+) remaining_us=(\d+) height=(\d+)$")),
    ("state", re.compile(r"^Initial headers sync (?:started|transition|aborted|complete).*?peer=(\d+)\b")),
)


def summarize(values):
    ordered = sorted(values)
    return {"count": len(ordered), "median": statistics.median(ordered),
            "p90_nearest_rank": ordered[math.ceil(0.9 * len(ordered)) - 1], "sum": sum(ordered)}


def parse_trace(lines):
    peers = defaultdict(list)
    for line in lines:
        trace = STAMP.match(line.rstrip("\r\n"))
        if not trace:
            continue
        stamp, text = trace.groups()
        for kind, pattern in EVENTS:
            match = pattern.match(text)
            if not match:
                continue
            values = tuple(map(int, match.groups()))
            peer, payload = (values[-1], values[:1]) if kind == "receive" else (values[0], values[1:])
            peers[peer].append((kind, datetime.fromisoformat(stamp), payload))
            break

    pattern = ("send", "more", "receive", "credit", "send", "more")
    rows = []
    for peer, events in peers.items():
        for i in range(len(events) - len(pattern) + 1):
            burst = events[i:i + len(pattern)]
            if tuple(entry[0] for entry in burst) != pattern:
                continue
            if burst[2][2] != (FULL_HEADERS_BYTES,):
                continue
            grant, remaining, height = burst[3][2]
            outgoing, received, follow = (burst[index][1] for index in (0, 2, 4))
            wait = (received - outgoing).total_seconds() * 1000
            processing = (follow - received).total_seconds() * 1000
            if not 0 <= wait <= 120_000 or grant <= 0 or processing < 0 or grant / 1000 > processing + 0.005:
                continue
            verifier = grant / 1000 if remaining else None
            rows.append({
                "peer": peer, "advanced_presync_height": height, "send": outgoing.isoformat(),
                "receive_for_processing": received.isoformat(), "follow_up_send": follow.isoformat(),
                "request_to_processing_ms": round(wait, 3), "processing_to_follow_up_ms": round(processing, 3),
                "proof_credit_granted_us": grant, "proof_credit_remaining_before_us": grant + remaining,
                "proof_credit_remaining_after_us": remaining, "local_verifier_wall_ms": verifier,
                "overlap_envelope_ms": round(min(wait, verifier), 3) if verifier is not None else None,
            })
    rows.sort(key=lambda row: row["send"])
    return rows, {str(peer): len(events) for peer, events in peers.items()}


def save(path, report):
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def wait_until(process, deadline):
    try:
        process.wait(timeout=max(0, deadline - time.monotonic()))
        return True
    except subprocess.TimeoutExpired:
        return False


def run_probe(binary, output, report):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "delivery"))
    from mainnet_probe import check_host, free_port, rpc

    machine = platform.machine().lower()
    if (platform.system(), machine) not in {("Darwin", "arm64"), ("Windows", "amd64"), ("Windows", "x86_64")}:
        raise RuntimeError("Expected native Apple Silicon or Windows x64")
    check_host()
    install_opener(build_opener(ProxyHandler({})))
    datadir = output / "node"
    datadir.mkdir()
    debug = output / "debug.log"
    flags = ["-chain=main", f"-datadir={datadir}", "-server=1", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
             "-disablewallet=1", "-listen=0", "-listenonion=0", "-discover=0", "-printtoconsole=0",
             "-debug=net", "-logtimemicros=1", "-logips=0", f"-debuglogfile={debug}"]
    port = free_port()
    flags.append(f"-rpcport={port}")
    quick_deadline = time.monotonic() + WINDOW_SECONDS
    deadline = quick_deadline + TOTAL_SECONDS - WINDOW_SECONDS
    exit_method = "already_exited"
    with (output / "console.log").open("wb") as console:
        proc = subprocess.Popen([str(binary), *flags], stdout=console, stderr=console,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        try:
            if not wait_until(proc, quick_deadline):
                chain = rpc(datadir, port, "getblockchaininfo")
                genesis = rpc(datadir, port, "getblockhash", 0)
                connected = rpc(datadir, port, "getpeerinfo") or []
                report["last_chain"] = ({key: chain.get(key) for key in ("chain", "blocks", "headers", "initialblockdownload")}
                                        if chain else None)
                report["genesis"] = genesis
                report["connected_peers"] = [{"id": peer["id"], "inbound": peer.get("inbound"),
                                               "permissions": peer.get("permissions"), "pingtime": peer.get("pingtime")}
                                              for peer in connected]
        finally:
            if proc.poll() is None:
                rpc(datadir, port, "stop")
                if wait_until(proc, deadline - 4):
                    exit_method = "rpc_stop"
                else:
                    proc.terminate()
                    if not wait_until(proc, deadline - 2):
                        proc.kill()
                        wait_until(proc, deadline)
                    exit_method = "forced"
    report["node_exit"] = {"method": exit_method, "code": proc.poll()}
    with debug.open(encoding="utf-8", errors="replace") if debug.exists() else open(os.devnull) as stream:
        rows, events = parse_trace(stream)
    report["request_events_by_peer"] = events
    report["samples"] = rows
    if report.get("genesis") != GENESIS or not report.get("last_chain") or report["last_chain"]["chain"] != "main":
        report["status"] = "unmeasured_node_identity"
    elif any("noban" in (peer["permissions"] or []) for peer in report.get("connected_peers", [])):
        report["status"] = "unmeasured_unexpected_peer_privilege"
    elif not rows:
        report["status"] = "unmeasured_no_established_presync"
    elif exit_method != "rpc_stop" or proc.poll() != 0:
        report["status"] = "partial_unclean_exit"
    else:
        report["status"] = "measured"
    if rows:
        report["summary"] = {key: summarize(values) for key in (
            "request_to_processing_ms", "processing_to_follow_up_ms", "local_verifier_wall_ms", "overlap_envelope_ms",
        ) if (values := [row[key] for row in rows if row[key] is not None])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True)
    report = {"status": "running", "source": SOURCE, "tree": TREE, "host": platform.platform(),
              "measurement_window_seconds": WINDOW_SECONDS, "process_ceiling_seconds": TOTAL_SECONDS,
              "scope": "Stock public peers, queue-inclusive request-to-processing interval", "samples": []}
    result = output / "result.json"
    save(result, report)
    try:
        binary = args.binary.resolve(strict=True)
        with binary.open("rb") as file:
            report["binary_sha256"] = hashlib.file_digest(file, "sha256").hexdigest()
        run_probe(binary, output, report)
    except Exception as error:
        report["status"] = "unmeasured_probe_error"
        report["error"] = {"type": type(error).__name__, "message": str(error)[:300]}
    save(result, report)
    print(f"{report['status']} ({len(report['samples'])} complete established PRESYNC samples)", flush=True)


if __name__ == "__main__":
    main()

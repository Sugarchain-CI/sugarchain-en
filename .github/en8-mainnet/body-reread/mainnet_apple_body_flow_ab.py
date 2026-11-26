#!/usr/bin/env python3
"""Compare signed native Apple packages with continuous Mainnet body delivery."""

import argparse
from datetime import datetime
import json
import math
import os
from pathlib import Path
import platform
import re
import socket
import struct
import time
from types import SimpleNamespace
from urllib.request import ProxyHandler, build_opener, install_opener

import mainnet_apple_body_ab as apple
import mainnet_body_reread as body

CANDIDATE_SOURCE = "9104b9651effe3bbb088e687c586ddab176e29a4"
CANDIDATE_TREE = "c9c8ee39a3367e58e8f894968105b74f2574f4c9"
ORDER = ("baseline", "candidate", "candidate", "baseline")
PREPARATION_TIMEOUT = 45
DELIVERY_TIMEOUT = 45
RESTART_TIMEOUT = 18
WIRE_BYTE_LIMIT = 8 << 20
MAX_BATCH = 128
TIMESTAMP = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z) ")


def host_ram():
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGESIZE")
    except (OSError, ValueError):
        return None
    return pages * page_size if pages > 0 and page_size > 0 else None


def configured_ceiling(ram):
    if ram is None:
        return MAX_BATCH  # The protocol hard limit still applies if the harness cannot read RAM.
    if ram >= (8 << 30):
        return 128
    if ram >= (4 << 30):
        return 64
    return 16


def block_requests(payload, ceiling):
    body.require(bool(payload), "Empty getdata fixture message")
    count = payload[0]
    body.require(0 < count <= ceiling and len(payload) == 1 + count * 36,
                 "Fixture getdata exceeds the request ceiling or has invalid length")
    hashes = []
    for offset in range(1, len(payload), 36):
        kind = struct.unpack_from("<I", payload, offset)[0]
        body.require(kind in (2, 0x40000002), "Expected only ordinary or witness block requests")
        hashes.append(payload[offset + 4:offset + 36])
    return hashes


class ContinuousPlayback:
    def __init__(self, headers, hashes, frames, ceiling):
        self.headers = headers
        self.heights = {digest: height for height, digest in enumerate(hashes)}
        self.frames = frames
        self.ceiling = ceiling
        self.started = None
        self.first_request = None
        self.last_send = None
        self.sent = []
        self.requested = set()
        self.trace = []
        self.wire_received = 0
        self.wire_sent = 0
        self.body_bytes = 0

    def record(self, event, when, heights):
        self.trace.append({"event": event, "seconds": when - self.started, "heights": heights})

    def send(self, wire, frame, deadline):
        self.wire_sent += len(frame)
        body.require(self.wire_sent <= WIRE_BYTE_LIMIT, "Fixture response exceeded its byte budget")
        body.send(wire, frame, deadline)

    def offer_headers(self, connection, headers, deadline):
        payload = body.compact_size(len(headers)) + b"".join(header + b"\0" for header in headers)
        self.send(connection, body.message(b"headers", payload), deadline)

    def run(self, connection, deadline):
        self.started = time.monotonic()
        self.offer_headers(connection, self.headers[-1:], deadline)
        while len(self.sent) < body.HEIGHT:
            command, payload = body.read_message(connection, deadline)
            self.wire_received += 24 + len(payload)
            body.require(self.wire_received <= WIRE_BYTE_LIMIT, "Fixture requests exceeded the byte budget")
            if command == b"ping":
                self.send(connection, body.message(b"pong", payload), deadline)
            elif command == b"getheaders":
                height = self.heights.get(body.first_locator(payload))
                body.require(height is not None, "Unknown fixture header locator")
                self.offer_headers(connection, self.headers[height:height + body.BATCH], deadline)
            elif command == b"getdata":
                hashes = block_requests(payload, self.ceiling)
                heights = [self.heights.get(digest) for digest in hashes]
                body.require(all(height and height not in self.requested for height in heights)
                             and len(set(heights)) == len(heights), "Unexpected or repeated block request")
                received = time.monotonic()
                if self.first_request is None:
                    self.first_request = received
                self.record("request", received, heights)
                self.requested.update(heights)
                frames = [self.frames[height - 1] for height in heights]
                self.send(connection, b"".join(frames), deadline)
                self.last_send = time.monotonic()
                self.record("send", self.last_send, heights)
                self.sent.extend(heights)
                self.body_bytes += sum(len(frame) - 24 for frame in frames)
        body.require(len(self.requested) == len(self.sent) == body.HEIGHT, "The requested body range is incomplete")

    def retain_trace(self, path):
        with path.open("w", encoding="utf-8") as out:
            for row in self.trace:
                out.write(json.dumps(row, separators=(",", ":")) + "\n")

    def summary(self, completed):
        return {
            "announcement_to_first_request_seconds": self.first_request - self.started,
            "first_request_to_last_send_seconds": self.last_send - self.first_request,
            "last_send_to_exact_tip_rpc_seconds": completed - self.last_send,
            "first_request_to_exact_tip_rpc_seconds": completed - self.first_request,
            "largest_getdata_batch": max(len(row["heights"]) for row in self.trace if row["event"] == "request"),
            "getdata_messages": len(self.trace) // 2,
            "blocks_out_of_serial_height_order": sum(height != sequence for sequence, height in enumerate(self.sent, 1)),
            "wire_bytes_received": self.wire_received,
            "wire_bytes_sent": self.wire_sent,
            "body_bytes_sent": self.body_bytes,
            "unique_bodies_sent": len(self.sent),
        }


def logged_ingress_to_tip(log, fixture):
    first_ingress = None
    final_tip = None
    expected = f"new best={fixture['tip']} height={body.HEIGHT} "
    for line in log.splitlines():
        if first_ingress is None and body.INGRESS.search(line):
            first_ingress = TIMESTAMP.match(line)
        if expected in line:
            final_tip = TIMESTAMP.match(line)
    body.require(first_ingress and final_tip, "Missing timestamped Mainnet ingress or exact final tip")
    elapsed = (datetime.fromisoformat(final_tip[1]) - datetime.fromisoformat(first_ingress[1])).total_seconds()
    body.require(math.isfinite(elapsed) and elapsed > 0, "Invalid node-log elapsed duration")
    return elapsed


def run_case(args, directory, data, resources, ceiling):
    fixture, headers, hashes, frames, header_batch, expected_bytes = data
    isolated = ("-networkactive=0", "-connect=0", "-dnsseed=0", "-fixedseeds=0", "-dns=0",
                "-proxy=0", "-v2transport=0", "-assumevalid=0")
    # The authentic historical prefix is below stock minimum work. Only the
    # owned loopback node's fixture admission changes. Proof and script checks remain enabled.
    flags = (*isolated, "-minimumchainwork=0", "-debug=bench", "-debug=net")
    playback = ContinuousPlayback(headers, hashes, frames, ceiling)
    debug = directory / "debug.log"
    with body.node(args, directory, "network-body", extra_flags=flags, shutdown_timeout=10) as (proc, port, started):
        deadline = started + PREPARATION_TIMEOUT
        cold = body.wait_empty_node(directory, port, proc, body.remaining(deadline))
        body.require(cold["chain"] == "main" and cold["blocks"] == cold["headers"] == 0 and
                     cold["bestblockhash"] == fixture["genesis"], "Expected isolated Mainnet genesis")
        cookie = (directory / ".cookie").read_bytes().strip()
        prime_start = time.monotonic()
        primed = body.read_rpc_response(body.make_rpc_request(port, cookie, header_batch), body.remaining(deadline))
        prime_count = body.verify_batch(primed, body.HEIGHT, "submitheader")
        body.ready_state(directory, port, proc, 0, fixture["genesis"], deadline)
        prime_seconds = time.monotonic() - prime_start
        start_log = debug.stat().st_size
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            peer_port = listener.getsockname()[1]
            endpoint = f"127.0.0.1:{peer_port}"
            body.require(body.rpc(directory, port, "setnetworkactive", True) is True, "Could not activate isolated loopback")
            body.rpc(directory, port, "addnode", endpoint, "onetry", False)
            listener.settimeout(body.remaining(deadline))
            connection, _ = listener.accept()
            with connection:
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                body.wait_for(connection, b"version", deadline)
                greeting = body.message(b"version", body.fixture_version_payload(peer_port)) + body.message(b"verack", b"")
                body.send(connection, greeting, deadline)
                body.wait_for(connection, b"verack", deadline)
                peers = body.rpc(directory, port, "getpeerinfo")
                body.require(isinstance(peers, list) and len(peers) == 1 and peers[0]["addr"] == endpoint
                             and not peers[0]["inbound"] and not peers[0]["permissions"], "Unexpected fixture peer")
                peer_id = peers[0]["id"]
                before_cpu, before_rss = resources.sample(proc)
                deadline = time.monotonic() + DELIVERY_TIMEOUT
                try:
                    playback.run(connection, deadline)
                    body.ready_state(directory, port, proc, body.HEIGHT, fixture["tip"], deadline)
                    completed = time.monotonic()
                    after_cpu, after_rss = resources.sample(proc)
                finally:
                    playback.retain_trace(directory / "wire.jsonl")
                peers = body.rpc(directory, port, "getpeerinfo")
                body.require(len(peers) == 1 and peers[0]["id"] == peer_id and not peers[0]["inflight"],
                             "Changed fixture peer or bodies still in flight after exact tip")
                verified = body.verify_utxo(directory, port, fixture)
    with debug.open("rb") as handle:
        handle.seek(start_log)
        log = handle.read().decode("utf-8", errors="replace")
    body.require(proc.returncode == 0 and "Shutdown done" in log, "Owned fixture node did not stop cleanly")
    reads = body.bench_stats(log, playback.sent, [digest[::-1].hex() for digest in hashes], peer_id)
    timing = apple.storage_timing(debug)
    native_seconds = logged_ingress_to_tip(log, fixture)
    body.require(playback.body_bytes == expected_bytes, "Delivered block bodies differ from the exact fixture size")
    with body.node(args, directory, "offline-restart", restart=True,
                   extra_flags=isolated, shutdown_timeout=10) as (restarted, rpc_port, started):
        body.ready_state(directory, rpc_port, restarted, body.HEIGHT, fixture["tip"], started + RESTART_TIMEOUT)
        offline = body.verify_utxo(directory, rpc_port, fixture)
        network = body.rpc(directory, rpc_port, "getnetworkinfo")
        body.require(body.rpc(directory, rpc_port, "getpeerinfo") == [] and network and network["networkactive"] is False,
                     "Restart did not remain offline")
    restart_log = (directory / "debug-restart.log").read_text(encoding="utf-8", errors="replace")
    body.require(restarted.returncode == 0 and "Shutdown done" in restart_log and offline == verified,
                 "Offline restart changed fixture state or did not stop cleanly")
    cpu = after_cpu - before_cpu
    body.require(math.isfinite(cpu) and cpu >= 0, "Invalid process CPU duration")
    return {
        **playback.summary(completed), "node_cpu_seconds": cpu,
        "node_first_ingress_to_exact_tip_log_seconds": native_seconds,
        "rss_before_bytes": before_rss, "rss_after_bytes": after_rss,
        "primed_headers": prime_count, "header_prime_seconds_excluded": prime_seconds,
        "connect_tip": reads, "storage_timing": timing, "state": verified, "offline_restart_state": offline,
    }


def pair(baseline, candidate):
    old = baseline["measurement"]
    new = candidate["measurement"]
    fields = (
        "first_request_to_exact_tip_rpc_seconds", "first_request_to_last_send_seconds",
        "last_send_to_exact_tip_rpc_seconds", "node_first_ingress_to_exact_tip_log_seconds", "node_cpu_seconds",
    )
    return {
        "baseline_trial": baseline["trial"], "candidate_trial": candidate["trial"],
        "candidate_minus_baseline_seconds": {name: new[name] - old[name] for name in fields},
        "baseline_disk_rereads": old["connect_tip"]["disk_rereads"],
        "candidate_disk_rereads": new["connect_tip"]["disk_rereads"],
        "candidate_minus_baseline_log_ms": {
            name: new["storage_timing"][name]["sum_ms"] - timing["sum_ms"]
            for name, timing in old["storage_timing"].items()
        },
    }


def run(args):
    body.require(platform.system() == "Darwin" and platform.machine() == "arm64", "Use a native Apple Silicon runner")
    body.check_host()
    install_opener(build_opener(ProxyHandler({})))
    packages = {
        "baseline": (args.baseline.resolve(strict=True), apple.BASELINE_SOURCE, apple.BASELINE_TREE),
        "candidate": (args.candidate.resolve(strict=True), CANDIDATE_SOURCE, CANDIDATE_TREE),
    }
    data, geometry = apple.fixture_data(args.fixture, args.fixture_info)
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    summary = root / "result.json"
    ram = host_ram()
    ceiling = configured_ceiling(ram)
    report = {
        "status": "in_progress", "interface": "gui" if args.gui else "cli", "order": ORDER,
        "host": {"platform": platform.platform(), "logical_cpus": os.cpu_count(),
                 "ram_bytes": ram, "runner_image": os.environ.get("ImageVersion")},
        "fixture": data[0], "block_geometry": geometry, "configuration": {
            "preparation_timeout_seconds": PREPARATION_TIMEOUT, "delivery_timeout_seconds": DELIVERY_TIMEOUT,
            "restart_timeout_seconds": RESTART_TIMEOUT, "expected_stock_ceiling": ceiling if ram else None,
            "wire_request_batch_bound": ceiling, "wire_byte_bound_per_direction": WIRE_BYTE_LIMIT,
            "peer_count": 1, "response_delay_seconds": 0, "fixture_admission_minimum_chain_work": 0,
            "assumevalid": 0, "inflight_override": None,
        },
        "inputs": {}, "samples": [],
    }
    body.persist(summary, report)
    try:
        for role, (folder, source, tree) in packages.items():
            entry = apple.check_package(folder, source, tree)
            entry.update(apple.prepare_binary(folder, root / f"package-{role}", args.gui))
            report["inputs"][role] = entry
        body.require(report["inputs"]["baseline"]["binary_sha256"] != report["inputs"]["candidate"]["binary_sha256"],
                     "Both packaged arms resolved to the same daemon or GUI")
        resources = body.Resources()
        for index, role in enumerate(ORDER, 1):
            entry = {"trial": index, "role": role, "status": "in_progress"}
            report["samples"].append(entry)
            body.persist(summary, report)
            variant = SimpleNamespace(binary=Path(report["inputs"][role]["binary"]), gui=args.gui)
            entry["measurement"] = run_case(variant, root / f"{index:02d}-{role}", data, resources, ceiling)
            entry["status"] = "verified"
            body.persist(summary, report)
        a, b, c, d = report["samples"]
        report["pairs"] = [pair(a, b), pair(d, c)]
        report["status"] = "verified"
    except Exception as error:
        if report["samples"] and report["samples"][-1]["status"] == "in_progress":
            report["samples"][-1]["status"] = "failed"
        report.update(status="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        body.persist(summary, report)
    print(f"{report['interface']} verified {len(report['samples'])} continuous trials: {summary}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("baseline", "candidate", "fixture", "fixture-info", "output"):
        parser.add_argument(f"--{argument}", type=Path, required=True)
    parser.add_argument("--gui", action="store_true")
    run(parser.parse_args())


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Measure ConnectTip rereads while one fixture peer reorders requested Mainnet blocks."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import socket
import sys
import time
from urllib.request import ProxyHandler, build_opener, install_opener

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "delivery"))
from mainnet_delivery import HEIGHT, UTXO_COUNT, UTXO_SHA, Resources, block_geometry, get_fixture, persist, read_inventory
from mainnet_paired import BATCH, compact_size, first_locator, hash256, message, read_message, version_payload, wait_for
from mainnet_probe import check_host, node, rpc
from mainnet_warm import make_batch, make_rpc_request, read_rpc_response, verify_batch, wait_empty_node

ORDER = ("in-order", "held-gap", "held-gap", "in-order")
GROUP = 8
REQUEST_LIMIT = 128
PROTOCOL_TIMEOUT = 110
RESTART_TIMEOUT = 22
REREAD = re.compile(r"Load block from disk: ([0-9]+(?:\.[0-9]+)?)ms")
CONNECT = re.compile(r"Connect total: ([0-9]+(?:\.[0-9]+)?)ms")
INGRESS = re.compile(r"received block ([0-9a-f]{64}) peer=(\d+)")


def require(value, detail):
    if not value:
        raise RuntimeError(detail)


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError("Owned mainnet body run exceeded its deadline")
    return seconds


def send(wire, frame, deadline):
    wire.settimeout(remaining(deadline))
    wire.sendall(frame)


def fixture_version_payload(port):
    # The retained playback helper advertises 4,000 headers. Preserve its wire
    # fields and relay byte while declaring this fixture's complete height.
    payload = version_payload(port)
    return payload[:-5] + HEIGHT.to_bytes(4, "little", signed=True) + payload[-1:]


def ready_state(path, port, proc, expected_height, expected_hash, deadline):
    last = None
    while time.monotonic() < deadline:
        require(proc.poll() is None, "Owned node exited before the fixture completed")
        last = rpc(path, port, "getblockchaininfo")
        if last and last.get("blocks") == expected_height:
            require(last["chain"] == "main" and last["headers"] == HEIGHT and last["bestblockhash"] == expected_hash,
                    f"Unexpected owned-node tip at height {expected_height}")
            require(last["initialblockdownload"], "The early fixture should remain within IBD")
            return last
        if last and last.get("blocks", 0) > expected_height:
            raise RuntimeError("Owned node advanced beyond the expected fixture height")
        time.sleep(0.01)
    raise TimeoutError(f"Expected block height {expected_height}, got {last!r}")


def verify_utxo(path, port, fixture):
    record = rpc(path, port, "gettxoutsetinfo", "hash_serialized_3")
    require(record and record["height"] == HEIGHT and record["bestblock"] == fixture["tip"]
            and record.get("hash_serialized_3") == UTXO_SHA and record["txouts"] == UTXO_COUNT,
            "Owned node UTXO state differs from the pinned Mainnet fixture")
    return {"height": record["height"], "tip": record["bestblock"], "utxo_hash": record["hash_serialized_3"],
            "utxo_count": record["txouts"]}


def ordered_groups(mode):
    for first in range(1, HEIGHT + 1, GROUP):
        items = list(range(first, first + GROUP))
        if mode == "held-gap":
            yield items[1:], items[0]
        else:
            yield items[:-1], items[-1]


class Playback:
    def __init__(self, wire, node_dir, port, peer_id, headers, frames, hashes, events, deadline):
        self.wire = wire
        self.node_dir = node_dir
        self.port = port
        self.peer_id = peer_id
        self.headers = headers
        self.frames = frames
        self.heights = {digest: height for height, digest in enumerate(hashes)}
        self.events = events
        self.deadline = deadline
        self.started = time.perf_counter()
        self.requested = set()
        self.sent = []
        self.barriers = []

    def record(self, event, **fields):
        self.events.write(json.dumps({"event": event, "seconds": time.perf_counter() - self.started, **fields}) + "\n")

    def headers_message(self, headers):
        return message(b"headers", compact_size(len(headers)) + b"".join(header + b"\0" for header in headers))

    def wait_for_requests(self, wanted):
        while not wanted.issubset(self.requested):
            command, payload = read_message(self.wire, self.deadline)
            if command == b"ping":
                send(self.wire, message(b"pong", payload), self.deadline)
            elif command == b"getheaders":
                from_height = self.heights.get(first_locator(payload))
                require(from_height is not None, "Owned node requested an unknown header locator")
                send(self.wire, self.headers_message(self.headers[from_height:from_height + BATCH]), self.deadline)
            elif command == b"getdata":
                hashes = read_inventory(payload)
                require(bool(hashes), "Fixture received a non-block-only getdata")
                received = [self.heights.get(digest) for digest in hashes]
                require(all(height and height not in self.requested for height in received), "Unexpected or repeated getdata hash")
                require(len(received) == len(set(received)), "Duplicate block request within one getdata")
                self.requested.update(received)
                self.record("request", heights=received)

    def bodies(self, heights):
        require(set(heights).issubset(self.requested), "Fixture would send an unsolicited body")
        send(self.wire, b"".join(self.frames[height - 1] for height in heights), self.deadline)
        self.sent.extend(heights)
        self.record("send", heights=heights)

    def barrier(self, first, remaining_height):
        start = time.perf_counter()
        deadline = min(self.deadline, time.monotonic() + 6)
        while time.monotonic() < deadline:
            records = rpc(self.node_dir, self.port, "getpeerinfo")
            require(isinstance(records, list) and len(records) == 1 and records[0]["id"] == self.peer_id,
                    "Owned fixture peer changed during delivery")
            inflight = set(records[0]["inflight"])
            require(len(inflight) <= REQUEST_LIMIT, "Owned peer exceeded the fixed request ceiling")
            require(remaining_height in inflight, "The held body request left flight before its release")
            if not inflight.intersection(first):
                seconds = time.perf_counter() - start
                self.barriers.append(seconds)
                self.record("barrier", removed=first, still_requested=remaining_height, observation_seconds=seconds)
                return
            time.sleep(0.01)
        raise TimeoutError("Requested first seven bodies remained in flight")

    def run(self, mode):
        send(self.wire, self.headers_message(self.headers[-1:]), self.deadline)
        for initial, last in ordered_groups(mode):
            self.wait_for_requests(set(initial) | {last})
            self.bodies(initial)
            self.barrier(initial, last)
            self.bodies([last])
        require(self.requested == set(range(1, HEIGHT + 1)) and len(self.sent) == len(set(self.sent)) == HEIGHT,
                "Fixture failed to deliver each requested body exactly once")


def bench_stats(log, expected_order, display_hashes, peer_id):
    pairs = []
    connect = []
    using_memory = False
    seen = []
    for line in log.splitlines():
        arrival = INGRESS.search(line)
        if arrival:
            seen.append((arrival[1], int(arrival[2])))
        if "Using cached block" in line:
            require(not using_memory, "Multiple cached-block markers before a ConnectTip timing")
            using_memory = True
        match = REREAD.search(line)
        if match:
            pairs.append((using_memory, float(match[1])))
            using_memory = False
        connected = CONNECT.search(line)
        if connected:
            connect.append(float(connected[1]))
    require(not using_memory and len(pairs) == HEIGHT, f"Expected {HEIGHT} ConnectTip timing records, got {len(pairs)}")
    require(len(connect) == HEIGHT, f"Expected {HEIGHT} ConnectBlock timing records, got {len(connect)}")
    require(seen == [(display_hashes[height], peer_id) for height in expected_order],
            "Node-confirmed block ingress order differs from the single-peer fixture schedule")
    reads = [value for cached, value in pairs if not cached]
    return {
        "connect_tip_records": len(pairs), "disk_rereads": len(reads), "direct_memory_blocks": len(pairs) - len(reads),
        "reread_load_ms_sum": round(sum(reads), 3), "all_load_ms_sum": round(sum(value for _, value in pairs), 3),
        "connect_block_ms_sum": round(sum(connect), 3),
        "log_timing_resolution_ms": 0.01, "confirmed_ingress_count": len(seen),
    }


def run_case(args, mode, directory, data, resources):
    fixture, headers, hashes, frames, header_batch, body_bytes = data
    flags = (
        "-networkactive=0", "-connect=0", "-dnsseed=0", "-fixedseeds=0", "-dns=0", "-proxy=0",
        "-v2transport=0", "-assumevalid=0", "-minimumchainwork=0", "-debug=bench", "-debug=net",
        f"-maxibdblocksinflight={REQUEST_LIMIT}",
    )
    with node(args, directory, "network-body", extra_flags=flags, shutdown_timeout=10) as (proc, port, started):
        deadline = started + PROTOCOL_TIMEOUT
        cold = wait_empty_node(directory, port, proc, remaining(deadline))
        require(cold["chain"] == "main" and cold["blocks"] == cold["headers"] == 0 and
                cold["bestblockhash"] == fixture["genesis"], "Expected an owned Mainnet genesis-only profile")
        cookie = (directory / ".cookie").read_bytes().strip()
        start = time.perf_counter()
        response = read_rpc_response(make_rpc_request(port, cookie, header_batch), remaining(deadline))
        header_prime = verify_batch(response, HEIGHT, "submitheader")
        ready_state(directory, port, proc, 0, fixture["genesis"], deadline)
        prime_seconds = time.perf_counter() - start
        debug = directory / "debug.log"
        start_log = debug.stat().st_size
        with socket.socket() as listener, (directory / "wire.jsonl").open("w", encoding="utf-8") as events:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            endpoint = f"127.0.0.1:{listener.getsockname()[1]}"
            require(rpc(directory, port, "setnetworkactive", True) is True, "Could not enable owned loopback connection")
            rpc(directory, port, "addnode", endpoint, "onetry", False)
            listener.settimeout(remaining(deadline))
            wire, _ = listener.accept()
            with wire:
                wire.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                wait_for(wire, b"version", deadline)
                send(wire, message(b"version", fixture_version_payload(listener.getsockname()[1]))
                     + message(b"verack", b""), deadline)
                wait_for(wire, b"verack", deadline)
                peers = rpc(directory, port, "getpeerinfo")
                require(isinstance(peers, list) and len(peers) == 1 and peers[0]["addr"] == endpoint
                        and not peers[0]["inbound"] and not peers[0]["permissions"], "Unexpected nonfixture peer or permissions")
                peer_id = peers[0]["id"]
                before_cpu, before_rss = resources.sample(proc)
                playback = Playback(wire, directory, port, peer_id, headers, frames, hashes, events, deadline)
                playback.run(mode)
                ready_state(directory, port, proc, HEIGHT, fixture["tip"], deadline)
                controlled_wall = time.perf_counter() - playback.started
                after_cpu, after_rss = resources.sample(proc)
                verified = verify_utxo(directory, port, fixture)
    require(proc.returncode == 0, "Owned node did not shut down cleanly")
    with debug.open("rb") as handle:
        handle.seek(start_log)
        log = handle.read().decode("utf-8", errors="replace")
    require("Shutdown done" in log, "Owned node did not record a clean shutdown")
    stats = bench_stats(log, playback.sent, [digest[::-1].hex() for digest in hashes], peer_id)
    with node(args, directory, "offline-restart", restart=True, shutdown_timeout=10,
              extra_flags=("-networkactive=0", "-connect=0", "-dnsseed=0", "-fixedseeds=0", "-assumevalid=0")) as (restarted, port, started):
        ready_state(directory, port, restarted, HEIGHT, fixture["tip"], started + RESTART_TIMEOUT)
        offline = verify_utxo(directory, port, fixture)
        require(rpc(directory, port, "getpeerinfo") == [], "Restarted fixture has a peer")
        network = rpc(directory, port, "getnetworkinfo")
        require(network and network["networkactive"] is False, "Restarted fixture network is active")
    require(restarted.returncode == 0, "Offline restart did not shut down cleanly")
    require("Shutdown done" in (directory / "debug-restart.log").read_text(encoding="utf-8", errors="replace"),
            "Offline restart did not record a clean shutdown")
    require(verified == offline, "Owned node post-restart state differs")
    return {
        "mode": mode, "result": stats, "state": verified, "offline_restart_state": offline,
        "primed_headers": header_prime, "header_prime_seconds_excluded": prime_seconds,
        "unique_bodies_sent": len(playback.sent), "body_bytes_sent": body_bytes,
        "barrier_count": len(playback.barriers), "barrier_observation_seconds_sum": sum(playback.barriers),
        "controlled_wall_seconds_including_barriers": controlled_wall,
        "node_cpu_seconds_including_barriers": after_cpu - before_cpu,
        "rss_before_bytes": before_rss, "rss_after_bytes": after_rss,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--fixture-info", type=Path, required=True)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fixture-only", action="store_true")
    args = parser.parse_args()
    fixture, headers, blocks = get_fixture(args.fixture, args.fixture_info)
    geometry = block_geometry(blocks)
    if args.fixture_only:
        print(json.dumps({"fixture": fixture, "geometry": geometry}))
        return
    if not args.binary or not args.output:
        parser.error("Specify an owned output and exact native daemon to run the protocol")
    check_host()
    require((platform.system() == "Windows" and platform.machine().lower() in {"amd64", "x86_64"})
            or (platform.system() == "Darwin" and platform.machine() == "arm64"),
            "This timed diagnostic requires native Windows x64 or Apple ARM64")
    install_opener(build_opener(ProxyHandler({})))
    args.binary = args.binary.resolve(strict=True)
    args.output = args.output.resolve()
    args.gui = False
    args.output.mkdir(parents=True, exist_ok=False)
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    hashes = [bytes.fromhex(fixture["genesis"])[::-1]] + [hash256(header) for header in headers]
    frames = [message(b"block", block) for block in blocks]
    data = (fixture, headers, hashes, frames, make_batch("submitheader", [header.hex() for header in headers]), sum(map(len, blocks)))
    resources = Resources()
    result = {
        "status": "in_progress", "fixture": fixture, "geometry": geometry, "binary_sha256": digest,
        "host": {"platform": platform.platform(), "architecture": platform.machine(), "logical_cpu_count": os.cpu_count()},
        "order": ORDER, "request_limit": REQUEST_LIMIT, "group_size": GROUP, "samples": [],
    }
    path = args.output / "result.json"
    persist(path, result)
    try:
        for index, mode in enumerate(ORDER, 1):
            result["samples"].append(run_case(args, mode, args.output / f"{index:02d}-{mode}", data, resources))
            persist(path, result)
        pairs = ((0, 1), (3, 2))
        result["pairs"] = []
        for a, b in pairs:
            baseline = result["samples"][a]["result"]
            held = result["samples"][b]["result"]
            result["pairs"].append({
                "baseline": a + 1, "held_gap": b + 1,
                "extra_disk_rereads": held["disk_rereads"] - baseline["disk_rereads"],
                "reread_load_difference_ms": round(held["reread_load_ms_sum"] - baseline["reread_load_ms_sum"], 3),
            })
        result["status"] = "verified"
    except Exception as error:
        result.update(status="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        persist(path, result)
    print(json.dumps({"status": result["status"], "pairs": result["pairs"]}))


if __name__ == "__main__":
    main()

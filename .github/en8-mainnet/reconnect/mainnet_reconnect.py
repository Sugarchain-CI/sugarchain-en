#!/usr/bin/env python3
"""Replay an actual Mainnet headers-only reconnect through two loopback sessions."""

import argparse
from dataclasses import dataclass
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import struct
import sys
import time
from urllib.request import ProxyHandler, build_opener, install_opener

from mainnet_paired import BATCH, compact_size, first_locator, hash256, message, read_message, version_payload, wait_for
from mainnet_probe import check_host, node, rpc

FIXTURE_HASH = "f64a65677abdfa525b67d9a09291868fbfd1f9fb0d4089cdfafc3b2718dd07dd"
ARCHIVE_HASH = "1d6b46da12f732190804a276b0c457d3c0ff923733ba29294f826eea971664ce"
GENESIS = "7d5eaec2dbb75f99feadfa524c78b7cabc1d8c8204f79d4f3a83381b811b0adc"
GENESIS_BITS = 0x1F3FFFFF
MINIMUM_HEIGHT = 32_000
FINAL_HEIGHT = 40_000
REDOWNLOAD_MESSAGES = 8
REDOWNLOAD_BUFFER = 15_218
FIRST_ACCEPTED = REDOWNLOAD_MESSAGES * BATCH - REDOWNLOAD_BUFFER
WORKERS = 4
SERVICES = (1 << 10) | (1 << 3)  # NODE_NETWORK_LIMITED and NODE_WITNESS


def require(value, message_text):
    if not value:
        raise RuntimeError(message_text)


def sha256(contents):
    return hashlib.sha256(contents).hexdigest()


def block_proof(nbits):
    exponent, mantissa = nbits >> 24, nbits & 0x007FFFFF
    require(not (nbits & 0x00800000) and mantissa > 0, "Invalid fixture target")
    target = mantissa >> (8 * (3 - exponent)) if exponent <= 3 else mantissa << (8 * (exponent - 3))
    require(0 < target <= 2**256 - 1, "Out-of-range fixture target")
    return (1 << 256) // (1 + target)


@dataclass
class Fixture:
    raw: bytes
    hashes: list
    locations: dict
    minimum_work: int

    def display_hash(self, height):
        return self.hashes[height][::-1].hex()

    def headers_message(self, first_height, last_height):
        count = last_height - first_height + 1
        require(1 <= count <= BATCH and 1 <= first_height <= last_height <= FINAL_HEIGHT, "Invalid fixture range")
        return message(b"headers", compact_size(count) + b"".join(
            self.raw[(height - 1) * 80:height * 80] + b"\0" for height in range(first_height, last_height + 1)
        ))

    def metadata(self):
        return {
            "archive_sha256": ARCHIVE_HASH,
            "canonical_sha256": FIXTURE_HASH,
            "genesis": GENESIS,
            "genesis_proof": f"{block_proof(GENESIS_BITS):064x}",
            "minimum_chainwork": f"{self.minimum_work:064x}",
            "minimum_height": MINIMUM_HEIGHT,
            "minimum_height_hash": self.display_hash(MINIMUM_HEIGHT),
            "disconnect_height": FIRST_ACCEPTED,
            "disconnect_hash": self.display_hash(FIRST_ACCEPTED),
            "final_height": FINAL_HEIGHT,
            "final_hash": self.display_hash(FINAL_HEIGHT),
        }


def load_fixture(path):
    archive = path.read_bytes()
    require(sha256(archive) == ARCHIVE_HASH, "Unexpected genuine header archive SHA-256")
    raw = gzip.decompress(archive)
    require(len(raw) == 8_000_000 and sha256(raw) == FIXTURE_HASH, "Unexpected genuine header data SHA-256")
    hashes = [bytes.fromhex(GENESIS)[::-1]]
    minimum_work = block_proof(GENESIS_BITS)
    for offset in range(0, len(raw), 80):
        header = raw[offset:offset + 80]
        require(header[4:36] == hashes[-1], f"Broken Mainnet fixture link at height {offset // 80 + 1}")
        hashes.append(hash256(header))
        if offset < MINIMUM_HEIGHT * 80:
            minimum_work += block_proof(struct.unpack_from("<I", header, 72)[0])
    require(len(set(hashes)) == len(hashes), "Duplicate Mainnet fixture hash")
    hashes = hashes[:FINAL_HEIGHT + 1]
    return Fixture(raw[:FINAL_HEIGHT * 80], hashes, {digest: h for h, digest in enumerate(hashes)}, minimum_work)


def remaining(deadline):
    time_left = deadline - time.monotonic()
    if time_left <= 0:
        raise TimeoutError("Run exceeded the overall node deadline")
    return time_left


def check_peer(peers, previous=None):
    require(isinstance(peers, list) and len(peers) == 1, f"Expected a single connected fixture peer, got {peers!r}")
    peer = peers[0]
    require(not peer["inbound"] and peer["connection_type"] == "manual", "Fixture connection must be outbound -connect")
    require(peer.get("version", 0) > 0 and not peer["permissions"], "Unexpected peer negotiation or permissions")
    require(int(peer["services"], 16) == SERVICES, "Fixture peer used unexpected service flags")
    require(set(peer["servicesnames"]) == {"NETWORK_LIMITED", "WITNESS"}, "Fixture peer is not limited-service")
    require(previous is None or peer["id"] != previous, "The second peer did not get its own connection ID")
    return peer


class Playback:
    def __init__(self, fixture, transcript, deadline):
        self.fixture = fixture
        self.transcript = transcript
        self.deadline = deadline
        self.start = time.perf_counter()

    def record(self, **fields):
        fields.update(elapsed_seconds=time.perf_counter() - self.start)
        self.transcript.write(json.dumps(fields, sort_keys=True) + "\n")
        self.transcript.flush()

    def connect(self, listener, label, *, announce=False):
        listener.settimeout(remaining(self.deadline))
        wire, _ = listener.accept()
        try:
            wire.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            wait_for(wire, b"version", self.deadline)
            frames = message(b"version", version_payload(
                listener.getsockname()[1], starting_height=FINAL_HEIGHT, services=SERVICES,
            ))
            frames += message(b"verack", b"")
            if announce:
                # A standard MSG_BLOCK inventory entry for a genuine later fixture header.
                frames += message(b"inv", compact_size(1) + struct.pack("<I", 2) + self.fixture.hashes[FINAL_HEIGHT])
            wire.sendall(frames)
            wait_for(wire, b"verack", self.deadline)
            self.record(event="handshake", peer=label, queued_inv=announce)
            return wire
        except BaseException:
            wire.close()
            raise

    def request(self, wire, label, phase, expected, *, first=False):
        while True:
            command, data = read_message(wire, self.deadline)
            if command == b"ping":
                wire.sendall(message(b"pong", data))
            require(command != b"getdata", "Unexpected block data request from a headers-only IBD fixture")
            if command != b"getheaders":
                continue
            head = first_locator(data)
            height = self.fixture.locations.get(head)
            fields = {
                "event": "getheaders", "peer": label, "phase": phase, "expected_height": expected,
                "locator_height": height, "first_locator": head[::-1].hex(),
            }
            if first:
                fields["raw_payload_hex"] = data.hex()
            self.record(**fields)
            require(data[-32:] == bytes(32), "Fixture expects an open-ended header request")
            require(height == expected, f"Unexpected first locator {height!r} in {label}/{phase}, expected {expected}")
            return height

    def send(self, wire, label, phase, anchor, end):
        wire.settimeout(remaining(self.deadline))
        wire.sendall(self.fixture.headers_message(anchor + 1, end))
        self.record(event="headers", peer=label, phase=phase, first_height=anchor + 1, last_height=end)

    def phase(self, wire, label, name, start, count, *, final_request=None):
        for number in range(count):
            anchor = start + number * BATCH
            end = anchor + BATCH
            self.send(wire, label, name, anchor, end)
            expected = final_request if number == count - 1 and final_request is not None else end
            self.request(wire, label, name, expected)


def await_state(path, port, wanted, global_deadline, process):
    deadline = min(global_deadline, time.monotonic() + 12)
    last = None
    while time.monotonic() < deadline:
        require(process.poll() is None, f"Isolated node exited before reaching header height {wanted}")
        last = rpc(path, port, "getblockchaininfo")
        if last and last.get("headers") == wanted:
            require(last["chain"] == "main" and last["blocks"] == 0 and last["bestblockhash"] == GENESIS,
                    "Fixture node activated a body or used a different chain")
            require(last["initialblockdownload"], "Headers-only fixture node unexpectedly exited IBD")
            return {key: last[key] for key in ("chain", "blocks", "headers", "bestblockhash", "chainwork", "initialblockdownload")}
        if last and last.get("headers", 0) > wanted:
            raise RuntimeError(f"Isolated node passed the expected header height {wanted}")
        time.sleep(0.1)
    raise TimeoutError(f"Expected header height {wanted}, last state {last!r}")


def prove_tip(path, port, fixture, height, deadline):
    expected = fixture.display_hash(height)
    remaining(deadline)
    header = rpc(path, port, "getblockheader", expected)
    remaining(deadline)
    tips = rpc(path, port, "getchaintips")
    require(isinstance(header, dict) and header.get("hash") == expected and header.get("height") == height,
            f"Missing exact fixture header for height {height}")
    require(isinstance(tips, list) and any(tip.get("height") == height and tip.get("hash") == expected
            and tip.get("status") == "headers-only" for tip in tips), f"Missing headers-only active frontier at {height}")
    return {"hash": expected, "height": height, "chainwork": header["chainwork"]}


def run_peer_sequence(args, fixture, result, listener, process, port, deadline, transcript):
    node_dir = args.output / "node"
    playback = Playback(fixture, transcript, deadline)
    initial = await_state(node_dir, port, 0, deadline, process)
    require(int(initial["chainwork"], 16) == block_proof(GENESIS_BITS), "Genesis proof calculation differs from the node")
    result["initial_state"] = initial

    with playback.connect(listener, "first") as wire:
        playback.request(wire, "first", "initial", 0, first=True)
        first_peer = check_peer(rpc(node_dir, port, "getpeerinfo"))
        result["first_peer"] = {key: first_peer[key] for key in ("id", "connection_type", "permissions", "services", "servicesnames")}
        playback.phase(wire, "first", "presync", 0, MINIMUM_HEIGHT // BATCH, final_request=0)
        result["first_presync_state"] = await_state(node_dir, port, 0, deadline, process)
        playback.phase(wire, "first", "redownload", 0, REDOWNLOAD_MESSAGES)
        result["disconnect_state"] = await_state(node_dir, port, FIRST_ACCEPTED, deadline, process)
        result["disconnect_tip"] = prove_tip(node_dir, port, fixture, FIRST_ACCEPTED, deadline)
    playback.record(event="disconnect", accepted_headers=FIRST_ACCEPTED)

    peer_mode = args.replacement == "queued-inv"
    start = args.expected_start
    with playback.connect(listener, "replacement", announce=peer_mode) as wire:
        observed = playback.request(wire, "replacement", "initial", start, first=True)
        peer = check_peer(rpc(node_dir, port, "getpeerinfo"), result["first_peer"]["id"])
        result["replacement_peer"] = {key: peer[key] for key in ("id", "connection_type", "permissions", "services", "servicesnames")}
        result["replacement_start"] = {"height": observed, "hash": fixture.display_hash(observed)}
        phase_batches = (MINIMUM_HEIGHT - start + BATCH - 1) // BATCH
        replay_end = start + phase_batches * BATCH
        playback.phase(wire, "replacement", "presync", start, phase_batches, final_request=start)
        result["replacement_presync_state"] = await_state(node_dir, port, FIRST_ACCEPTED, deadline, process)
        playback.phase(wire, "replacement", "redownload", start, phase_batches)
        result["replacement_redownload_state"] = await_state(node_dir, port, replay_end, deadline, process)
        result["replacement_redownload_tip"] = prove_tip(node_dir, port, fixture, replay_end, deadline)
        remaining(deadline)
        result["minimum_work_header"] = result["replacement_redownload_tip"] if replay_end == MINIMUM_HEIGHT else {
            key: value for key, value in (rpc(node_dir, port, "getblockheader", fixture.display_hash(MINIMUM_HEIGHT)) or {}).items()
            if key in ("hash", "height", "chainwork")
        }
        at_floor = result["minimum_work_header"]
        require(at_floor.get("height") == MINIMUM_HEIGHT and at_floor.get("hash") == fixture.display_hash(MINIMUM_HEIGHT)
                and int(at_floor["chainwork"], 16) == fixture.minimum_work, "Exact threshold chainwork differs from the node")

        anchor = replay_end
        while anchor < FINAL_HEIGHT:
            end = min(anchor + BATCH, FINAL_HEIGHT)
            playback.send(wire, "replacement", "ordinary", anchor, end)
            if end - anchor == BATCH:
                playback.request(wire, "replacement", "ordinary", end)
                if end == FINAL_HEIGHT:
                    wire.sendall(message(b"headers", compact_size(0)))
            anchor = end
        result["final_state"] = await_state(node_dir, port, FINAL_HEIGHT, deadline, process)
        result["final_tip"] = prove_tip(node_dir, port, fixture, FINAL_HEIGHT, deadline)
        playback.record(event="completed", state=result["final_state"], tip=result["final_tip"])


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(args, fixture):
    check_host()
    require(not args.gui or os.environ.get("GITHUB_ACTIONS") == "true", "The GUI probe requires an isolated GitHub Actions account")
    install_opener(build_opener(ProxyHandler({})))
    args.binary = args.binary.resolve(strict=True)
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    result = {
        "status": "in_progress",
        "host": {"platform": platform.platform(), "machine": platform.machine(), "logical_cpus": os.cpu_count()},
        "fixture": fixture.metadata(), "binary_sha256": sha256(args.binary.read_bytes()),
        "gui": args.gui, "replacement_mode": args.replacement, "expected_replacement_start": args.expected_start,
        "timeout_seconds": args.timeout, "workers": WORKERS, "powcache_mib": 1,
    }
    save(args.output / "result.json", result)
    try:
        with socket.socket() as listener, (args.output / "transcript.jsonl").open("w", encoding="utf-8") as transcript:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            flags = (
                f"-connect=127.0.0.1:{listener.getsockname()[1]}", "-v2transport=0",
                "-dnsseed=0", "-fixedseeds=0", "-dns=0", "-proxy=0", "-assumevalid=0", "-maxpowcache=1",
                f"-parpow={WORKERS}", f"-minimumchainwork={fixture.minimum_work:064x}", "-debug=net",
            )
            with node(args, args.output / "node", "presync", extra_flags=flags) as (process, port, started):
                run_peer_sequence(args, fixture, result, listener, process, port, started + args.timeout, transcript)
                result["protocol_wall_seconds"] = time.monotonic() - started
            result["exit_code"] = process.returncode
            debug = (args.output / "node/debug.log").read_text(encoding="utf-8", errors="replace")
            require(process.returncode == 0 and "Shutdown done" in debug, "Isolated node did not finish a clean shutdown")
            require("sending getdata" not in debug, "The node requested body data during the headers-only fixture")
        result["status"] = "verified"
    except Exception as exc:
        result.update(status="failed", error=f"{type(exc).__name__}: {exc}")
        raise
    finally:
        save(args.output / "result.json", result)
    print(json.dumps({key: result[key] for key in ("status", "replacement_start", "final_tip", "protocol_wall_seconds")}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--check-fixture-only", action="store_true")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--replacement", choices=("scheduled", "queued-inv"), default="scheduled")
    parser.add_argument("--expected-start", type=int, choices=(0, FIRST_ACCEPTED - 1, FIRST_ACCEPTED))
    parser.add_argument("--timeout", type=int, default=360)
    args = parser.parse_args()
    if not args.check_fixture_only:
        lower = FIRST_ACCEPTED if args.replacement == "queued-inv" else FIRST_ACCEPTED - 1
        if not args.binary or not args.output or args.expected_start not in (0, lower) or not 180 <= args.timeout <= 360:
            parser.error("A test requires --binary, --output, --expected-start for its replacement mode, and a deadline of 180–360 seconds")
    fixture = load_fixture(args.fixture)
    if args.check_fixture_only:
        print(json.dumps(fixture.metadata(), indent=2))
    else:
        run(args, fixture)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError) as error:
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)

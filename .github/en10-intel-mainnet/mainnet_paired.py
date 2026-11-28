#!/usr/bin/env python3
"""Paired, isolated playback of published Mainnet headers and blocks."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import platform
import secrets
import socket
import statistics
import struct
import time
from types import SimpleNamespace

from mainnet_probe import check_host, import_blocks, node, rpc

MAGIC = bytes.fromhex("9feb4b9d")
BATCH = 2_000
MAX_FRAME = 4_000_000
SERVICES = 1 | 8  # NODE_NETWORK and NODE_WITNESS
PROTOCOL_VERSION = 70016


def hash256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def fixture_headers(raw, metadata):
    headers = []
    previous = bytes.fromhex(metadata["genesis"])[::-1]
    pos = 0
    while pos < len(raw):
        if raw[pos : pos + 4] != MAGIC or len(raw) - pos < 8:
            raise ValueError("Invalid Mainnet fixture frame")
        (size,) = struct.unpack_from("<I", raw, pos + 4)
        end = pos + 8 + size
        if size < 81 or end > len(raw):
            raise ValueError("Truncated or invalid Mainnet block")
        header = raw[pos + 8 : pos + 88]
        if header[4:36] != previous:
            raise ValueError(f"Broken fixture link at height {len(headers) + 1}")
        previous = hash256(header)
        headers.append(header)
        pos = end
    if (
        metadata["chain"] != "main"
        or metadata["first_height"] != 1
        or len(headers) != metadata["last_height"]
        or previous[::-1].hex() != metadata["tip"]
        or len(headers) < 2 * BATCH
    ):
        raise ValueError("Mainnet fixture count, chain or tip mismatch")
    return headers


def sha256_file(path):
    with path.open("rb") as fh:
        return hashlib.file_digest(fh, "sha256").hexdigest()


def compact_size(count):
    if count < 0xFD:
        return struct.pack("<B", count)
    return b"\xfd" + struct.pack("<H", count)


def first_locator(data):
    if len(data) < 5:
        raise ValueError("Truncated getheaders")
    if data[4] == 0xFD and len(data) >= 7:
        size, start = struct.unpack_from("<H", data, 5)[0], 7
    else:
        size, start = data[4], 5
    if not 0 < size <= 101 or len(data) != start + size * 32 + 32:
        raise ValueError("Invalid getheaders locator")
    return data[start : start + 32]


def version_payload(peer_port):
    host = b"\0" * 10 + b"\xff\xff" + socket.inet_aton("127.0.0.1")
    endpoint = struct.pack("<Q", SERVICES) + host + struct.pack(">H", peer_port)
    agent = b"/SugarchainMainnetPlayback:1/"
    return (
        struct.pack("<iQq", PROTOCOL_VERSION, SERVICES, int(time.time()))
        + endpoint * 2
        + struct.pack("<Q", secrets.randbits(64))
        + compact_size(len(agent))
        + agent
        + struct.pack("<iB", 2 * BATCH, 0)
    )


def message(command, payload):
    return MAGIC + command.ljust(12, b"\0") + struct.pack("<I", len(payload)) + hash256(payload)[:4] + payload


def read_bytes(sock, size, deadline):
    data = bytearray()
    while len(data) < size:
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise TimeoutError("Deadline expired awaiting the node")
        sock.settimeout(seconds)
        part = sock.recv(size - len(data))
        if not part:
            raise ConnectionError("Released node closed its loopback connection")
        data.extend(part)
    return bytes(data)


def read_message(sock, deadline):
    header = read_bytes(sock, 24, deadline)
    if header[:4] != MAGIC:
        raise ValueError("Unexpected P2P magic")
    (size,) = struct.unpack_from("<I", header, 16)
    if size > MAX_FRAME:
        raise ValueError("Oversized loopback P2P message")
    payload = read_bytes(sock, size, deadline)
    if hash256(payload)[:4] != header[20:24]:
        raise ValueError("Bad P2P checksum")
    return header[4:16].rstrip(b"\0"), payload


def wait_for(sock, command, deadline, *, locator=None):
    while True:
        received, data = read_message(sock, deadline)
        if received == b"ping":
            sock.sendall(message(b"pong", data))
        if received == command and (locator is None or first_locator(data) == locator):
            return time.perf_counter()


def report_case(file, baseline, candidate, repeats, host):
    results = {
        "host": host,
        "binary_sha256": {"baseline": baseline, "candidate": candidate},
        "fixture": repeats["fixture"],
        "measurements": repeats["measurements"],
    }
    if all(len(records) == repeats["count"] for records in repeats["measurements"].values()):
        comparisons = {}
        for key in ("presync_seconds", "import_seconds"):
            baseline_times, candidate_times = (
                [sample[key] for sample in repeats["measurements"][label]]
                for label in ("baseline", "candidate")
            )
            old = statistics.median(baseline_times)
            new = statistics.median(candidate_times)
            comparisons[key] = {
                "baseline_median": old,
                "candidate_median": new,
                "throughput_change_percent": (old / new - 1) * 100,
                "wall_time_change_percent": (new / old - 1) * 100,
            }
        results["comparisons"] = comparisons
    file.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")


def replay_headers(args, root, headers, metadata):
    root.mkdir()
    node_dir = root / "presync"
    locator_hashes = [
        bytes.fromhex(metadata["genesis"])[::-1],
        hash256(headers[BATCH - 1]),
        hash256(headers[2 * BATCH - 1]),
    ]
    frames = [
        message(b"headers", compact_size(BATCH) + b"".join(header + b"\0" for header in headers[start : start + BATCH]))
        for start in (0, BATCH)
    ]

    # Leave the network's minchainwork and all proof validation enabled. Limit
    # all peer traffic to a single loopback socket and use a fresh node.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(args.timeout)
        peer_port = listener.getsockname()[1]
        flags = (
            f"-connect=127.0.0.1:{peer_port}", "-v2transport=0",
            "-dnsseed=0", "-fixedseeds=0", "-dns=0",
        )
        with node(args, node_dir, "presync", extra_flags=flags) as (proc, rpc_port, _):
            connection, _ = listener.accept()
            with connection:
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                deadline = time.monotonic() + args.timeout
                wait_for(connection, b"version", deadline)
                connection.sendall(message(b"version", version_payload(peer_port)) + message(b"verack", b""))
                wait_for(connection, b"verack", deadline)
                wait_for(connection, b"getheaders", deadline, locator=locator_hashes[0])

                batch_seconds = []
                start = time.perf_counter()
                for index, frame in enumerate(frames):
                    t0 = time.perf_counter()
                    connection.sendall(frame)
                    observed = wait_for(connection, b"getheaders", deadline, locator=locator_hashes[index + 1])
                    batch_seconds.append(observed - t0)
                seconds = observed - start

                peers = rpc(node_dir, rpc_port, "getpeerinfo")
                state = rpc(node_dir, rpc_port, "getblockchaininfo")
                genesis = rpc(node_dir, rpc_port, "getblockhash", 0)
                if (
                    proc.poll() is not None
                    or not peers
                    or len(peers) != 1
                    or peers[0].get("presynced_headers") != 2 * BATCH
                    or not state
                    or state["chain"] != "main"
                    or state["blocks"] != 0
                    or state["headers"] != 0
                    or genesis != metadata["genesis"]
                ):
                    raise RuntimeError(f"Unexpected loopback presync state: {peers!r}, {state!r}")
                return {
                    "presync_seconds": seconds,
                    "presynced_headers": 2 * BATCH,
                    "headers_per_second": (2 * BATCH) / seconds,
                    "batch_seconds": batch_seconds,
                    "admitted_headers": state["headers"],
                    "active_blocks": state["blocks"],
                    "last_presynced_hash": locator_hashes[-1][::-1].hex(),
                }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--fixture-info", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=65)
    options = parser.parse_args()
    if not 1 <= options.repeats <= 5 or not 15 <= options.timeout <= 120:
        parser.error("--repeats must be 1–5 and --timeout 15–120 seconds")
    check_host()
    metadata = json.loads(options.fixture_info.read_text(encoding="utf-8"))
    if sha256_file(options.fixture) != metadata["archive_sha256"]:
        parser.error("Fixture archive checksum mismatch")
    raw = gzip.decompress(options.fixture.read_bytes())
    if hashlib.sha256(raw).hexdigest() != metadata["blocks_sha256"]:
        parser.error("Fixture block checksum mismatch")
    headers = fixture_headers(raw, metadata)
    root = options.output.resolve()
    root.mkdir(parents=True)
    fixture = root / "first-mainnet-blocks.dat"
    fixture.write_bytes(raw)
    programs = {"baseline": options.baseline.resolve(strict=True), "candidate": options.candidate.resolve(strict=True)}
    digests = {label: sha256_file(path) for label, path in programs.items()}
    host = {"name": platform.platform(), "machine": platform.machine(), "mode": "gui" if options.gui else "daemon"}
    repeats = {"count": options.repeats, "fixture": metadata, "measurements": {"baseline": [], "candidate": []}}

    # Alternating cohorts avoids giving a fixed order advantage to one version.
    for index in range(options.repeats):
        order = ("baseline", "candidate") if index % 2 == 0 else ("candidate", "baseline")
        for label in order:
            args = SimpleNamespace(binary=programs[label], gui=options.gui,
                                   timeout=options.timeout, import_seconds=options.timeout)
            sample_dir = root / f"{index + 1:02d}-{label}"
            header_result = replay_headers(args, sample_dir, headers, metadata)
            block_result = import_blocks(args, sample_dir, fixture, metadata)
            if block_result.get("status") != "verified" or not block_result.get("import_seconds"):
                raise RuntimeError(f"Mainnet import did not finish at the expected tip: {block_result!r}")
            sample = {"repeat": index + 1, **header_result, **block_result}
            repeats["measurements"][label].append(sample)
            report_case(root / "result.json", digests["baseline"], digests["candidate"], repeats, host)
            print(
                f"{label} #{index + 1}: {header_result['presync_seconds']:.3f} s for {2 * BATCH} "
                f"presynced headers, {block_result['import_seconds']:.3f} s for {metadata['last_height']} imported blocks",
                flush=True,
            )


if __name__ == "__main__":
    main()

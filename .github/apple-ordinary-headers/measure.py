#!/usr/bin/env python3
"""Compare ordinary accepted Mainnet headers after a private work-floor setup."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import struct
import sys
import time

from runtime_receipt import SOURCES, digest, require


TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS / "apple-batch-pwx"))


def load_helper(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


native = load_helper("native_usage", TOOLS / "apple-batch-pwx/measure-native.py")
limited_wire = load_helper("limited_peer_wire", TOOLS / "en8-mainnet/reconnect/mainnet_paired.py")
sys.path.insert(0, str(TOOLS / "en8-mainnet/reconnect"))
from mainnet_reconnect import GENESIS, GENESIS_BITS, SERVICES, block_proof

BATCH = 2_000
MINIMUM = 32_000
FINAL = 72_000
ORDER = ("control", "candidate", "candidate", "control")
ARCHIVE_SHA = "1d6b46da12f732190804a276b0c457d3c0ff923733ba29294f826eea971664ce"
RAW_SHA = "f64a65677abdfa525b67d9a09291868fbfd1f9fb0d4089cdfafc3b2718dd07dd"
TIP = "b62290c6914adee9b29326b8a4567114fff1f9013acb9c3b6ff68612a2947f99"
ORDERED = re.compile(rb"Mainnet ordinary ordered proof window: peer=(\d+) headers=(\d+) cold_ordered=(\d+)")
ACCEPTED = re.compile(rb"Saw new header hash=([a-f0-9]{64}) height=(\d+) peer=(\d+)")


class OrdinaryNode(native.OwnedNode):
    def __init__(self, binary, case, port, work):
        self.case = case
        self.rpc_port = native.free_port()
        self.shutdown = "none"
        self.stop_receipt = {"rpc": "unattempted"}
        self.flags = [
            "-chain=main", f"-datadir={case}", f"-minimumchainwork={work:064x}",
            "-server=1", f"-rpcport={self.rpc_port}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
            "-disablewallet=1", "-listen=0", "-discover=0", "-listenonion=0",
            "-printtoconsole=0", "-logtimemicros=1", "-debug=validation", "-debug=bench", "-loglevel=debug",
            "-parpow=8", f"-connect=127.0.0.1:{port}", "-v2transport=0", "-dnsseed=0", "-fixedseeds=0", "-dns=0",
        ]
        env = {**os.environ, "XDG_CONFIG_HOME": str(case / "config"), "XDG_DATA_HOME": str(case / "data"),
               "CFFIXED_USER_HOME": str(case)}
        with (case / "console.log").open("xb") as stream:
            actions = [(os.POSIX_SPAWN_DUP2, stream.fileno(), fd) for fd in (1, 2)]
            native.OwnedChild.__init__(self, binary, self.flags, env, actions)


def handshake(peer, port, deadline):
    peer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    native.wait_for(peer, b"version", deadline)
    version = limited_wire.version_payload(port, starting_height=FINAL, services=SERVICES)
    peer.sendall(native.message(b"version", version) + native.message(b"verack", b""))
    native.wait_for(peer, b"verack", deadline)


def request(peer, anchor, deadline):
    while True:
        command, payload = native.read_message(peer, deadline)
        if command == b"getheaders":
            require(native.first_locator(payload) == anchor, "Unexpected fixture GETHEADERS anchor")
            return
        require(command != b"getdata", "An ordinary header-only peer was asked for a body")
        if command == b"ping":
            peer.sendall(native.message(b"pong", payload))


def state(node, height, identity, work):
    info = native.rpc(node.case, node.rpc_port, "getblockchaininfo")
    require(info and (info["chain"], info["blocks"], info["headers"], info["initialblockdownload"]) ==
            ("main", 0, height, True), "The ordinary phase did not reach the pinned accepted height")
    hdr = native.rpc(node.case, node.rpc_port, "getblockheader", identity[::-1].hex())
    require(hdr and hdr["hash"] == identity[::-1].hex() and hdr["height"] == height and int(hdr["chainwork"], 16) == work,
            "Expected indexed header and exact chainwork are absent")
    peers = native.rpc(node.case, node.rpc_port, "getpeerinfo")
    require(peers and len(peers) == 1 and peers[0].get("permissions") == [] and peers[0].get("presynced_headers", -1) <= 0,
            "A privileged peer or active low-work phase invalidates the sample")
    return {"height": height, "hash": hdr["hash"], "chainwork": hdr["chainwork"], "peer": peers[0]["id"], "blocks": 0}


def accepted_at(log, height, identity, deadline, offset):
    pattern = b"hash=" + identity[::-1].hex().encode("ascii") + f" height={height} ".encode("ascii")
    with log.open("rb") as stream:
        stream.seek(offset)
        while time.monotonic() < deadline:
            line = stream.readline()
            if not line:
                time.sleep(0.002)
                continue
            if not line.endswith(b"\n"):
                stream.seek(-len(line), os.SEEK_CUR)
                time.sleep(0.002)
            elif pattern in line and ACCEPTED.search(line):
                return time.perf_counter_ns()
    raise TimeoutError("No final accepted-header marker")


def span_work(headers):
    work = block_proof(GENESIS_BITS)
    work_at = {}
    for height, header in enumerate(headers, 1):
        work += block_proof(struct.unpack_from("<I", header, 72)[0])
        if height in (MINIMUM, FINAL):
            work_at[height] = work
    return work_at


def trial(binary, case, row, usage, frames, locators, work_at, overall_deadline):
    height = FINAL
    base, last = MINIMUM // BATCH, height // BATCH
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(25)
        port = listener.getsockname()[1]
        node = OrdinaryNode(binary, case, port, work_at[MINIMUM])
        row["node_flags"] = node.flags
        phase_error = None
        try:
            peer, _ = listener.accept()
            with peer:
                deadline = min(overall_deadline, time.monotonic() + 250)
                handshake(peer, port, deadline)
                # The genuine prefix establishes and replays the private floor.
                # The timed segment begins only after this range is indexed.
                for _ in range(2):
                    for index in range(base):
                        request(peer, locators[index], deadline)
                        peer.sendall(frames[index])
                request(peer, locators[base], deadline)
                row["before"] = state(node, MINIMUM, locators[base], work_at[MINIMUM])
                log = case / "debug.log"
                offset = log.stat().st_size
                row["cpu_before"] = native.sample(usage, node.pid)
                begin = time.perf_counter_ns()
                for index in range(base, last):
                    if index > base:
                        request(peer, locators[index], deadline)
                    peer.sendall(frames[index])
                done = accepted_at(log, height, locators[last], deadline, offset)
                row["wall_ns"] = done - begin
                row["cpu_after"] = native.sample(usage, node.pid)
                row["after"] = state(node, height, locators[last], work_at[height])
                request(peer, locators[last], deadline)
                data = log.read_bytes()
                observed = [(hash_text.decode("ascii"), int(index), int(node_id))
                            for hash_text, index, node_id in ACCEPTED.findall(data[offset:])]
                expected = [(locators[index][::-1].hex(), BATCH * index, row["before"]["peer"])
                            for index in range(base + 1, last + 1)]
                require(row["before"]["peer"] == row["after"]["peer"] and observed == expected,
                        "Observed ordinary acceptance differs from the expected segment")
                row["accepted_ends"] = observed
                ordered = [tuple(map(int, match)) for match in ORDERED.findall(data[offset:])]
                expected_ordered = [(row["before"]["peer"], BATCH, BATCH - 1)] * (last - base) if row["role"] == "candidate" else []
                require(not ORDERED.search(data[:offset]) and ordered == expected_ordered,
                        "Completed ordinary windows, cold job count or low-work exclusion differ")
                row["ordinary_windows"] = ordered
        except BaseException as error:
            phase_error = error
            raise
        finally:
            try:
                node.stop()
            except Exception as error:
                row["cleanup_error"] = f"{type(error).__name__}: {error}"
                if phase_error is None:
                    raise
            finally:
                row["exit_accounting"] = node.exit_usage
                row["shutdown"] = node.shutdown
                row["cleanup"] = node.stop_receipt
    require(b"Shutdown done" in (case / "debug.log").read_bytes(), "Node did not finish shutdown")
    for field in ("user", "system"):
        ticks = row["cpu_after"][f"{field}_ticks"] - row["cpu_before"][f"{field}_ticks"]
        row[f"node_{field}_cpu_ns"] = ticks * usage.timebase.numer // usage.timebase.denom
    row["node_cpu_ns"] = row["node_user_cpu_ns"] + row["node_system_cpu_ns"]
    native.check_accounting(row)


def evaluate(rows):
    require(len(rows) == 4 and all(row["status"] == "verified" for row in rows), "Incomplete ordinary measurement")
    comparisons = []
    for baseline, candidate in ((rows[0], rows[1]), (rows[3], rows[2])):
        cpu = candidate["node_cpu_ns"] / baseline["node_cpu_ns"]
        wall = candidate["wall_ns"] / baseline["wall_ns"]
        comparisons.append({"cpu_ratio": cpu, "wall_ratio": wall, "passed": cpu <= 1.01 and wall <= 0.95})
    return {"pairs": comparisons, "eligible": all(row["passed"] for row in comparisons)}


def run(args):
    require(platform.system() == "Darwin" and platform.machine() == "arm64", "Native Apple ARM64 is required")
    native.check_host()
    require(digest(args.headers) == ARCHIVE_SHA, "Unexpected fixture archive")
    headers = native.read_fixture(args.headers, RAW_SHA, TIP)[:FINAL]
    locators, frames = native.prepare_wire(headers)
    work_at = span_work(headers)
    native_manifest = args.runtime / "runtime.json"
    receipt = json.loads(native_manifest.read_bytes())
    binaries = {}
    for role, (source, tree) in SOURCES.items():
        record = receipt["roles"][role]
        p = args.runtime / role / "sugarchaind"
        require((record["build"]["source"], record["build"]["tree"]) == (source, tree) and
                digest(p) == record["signed"]["sugarchaind"], "Unmatched native binary")
        binaries[role] = p
    evidence, cases = args.output.resolve(), args.case_root.resolve()
    require(cases != evidence and cases not in evidence.parents and evidence not in cases.parents,
            "Test datadirs and uploaded results must remain separate")
    evidence.mkdir()
    cases.mkdir()
    usage = native.DarwinUsage()
    result = {"status": "in_progress", "raw_headers_sha256": RAW_SHA, "runtime_sha256": digest(native_manifest),
              "minimum_chainwork": f"{work_at[MINIMUM]:064x}", "scope": "isolated Mainnet with private lower work floor",
              "setup_height": MINIMUM, "timed_headers": FINAL - MINIMUM, "order": ORDER,
              "thresholds": {"max_cpu_ratio": 1.01, "max_wall_ratio": 0.95},
              "cpu_calibration": {}, "trials": []}
    deadline = time.monotonic() + 1_400
    try:
        native.calibrate(usage, result["cpu_calibration"])
        for index, role in enumerate(ORDER, 1):
            name = f"{index}-{role}"
            folder = cases / name
            folder.mkdir()
            row = {"role": role, "run": index, "status": "in_progress", "logical_cpus": os.cpu_count()}
            result["trials"].append(row)
            try:
                trial(binaries[role], folder, row, usage, frames, locators, work_at, deadline)
                row["status"] = "verified"
            except Exception as error:
                row["status"] = "incomplete"
                row["error"] = f"{type(error).__name__}: {error}"
                raise
            finally:
                native.save(evidence / "result.json", result)
                for log in ("debug.log", "console.log"):
                    if (folder / log).is_file():
                        shutil.copyfile(folder / log, evidence / f"{name}-{log}")
        result["decision"] = evaluate(result["trials"])
        result["status"] = "recorded"
    except Exception as error:
        result["status"] = "inconclusive"
        result["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        native.save(evidence / "result.json", result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("runtime", "headers", "output", "case-root"):
        parser.add_argument(f"--{field}", type=Path, required=True)
    run(parser.parse_args())

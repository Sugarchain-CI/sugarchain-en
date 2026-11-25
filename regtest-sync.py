#!/usr/bin/env python3
"""Benchmark fresh-node loopback sync using a deterministic Regtest chain."""

import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import socket
import statistics
import subprocess
import time


MOCKTIME = 1795584000
DESCRIPTOR = "raw(51)"
GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"


def available_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class RpcError(RuntimeError):
    pass


class Node:
    def __init__(self, executable, data_dir, *, listening):
        self.data_dir = data_dir
        self.executable = executable
        self.rpc_port = available_port()
        self.p2p_port = available_port()
        while self.p2p_port == self.rpc_port:
            self.p2p_port = available_port()
        self.listening = listening
        self.cookie = data_dir / "regtest/.cookie"
        self.proc = None
        self.log = None
        self.auth = None

    def __enter__(self):
        self.data_dir.mkdir()
        try:
            self.startup_seconds = self.start()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, kind, value, traceback):
        self.close()

    def start(self):
        command = [
            str(self.executable), "-regtest", f"-datadir={self.data_dir}", "-server=1",
            "-rpcbind=127.0.0.1", f"-rpcport={self.rpc_port}", "-rpcallowip=127.0.0.1",
            "-connect=0", "-discover=0", "-dnsseed=0", "-fixedseeds=0", "-listenonion=0",
            "-disablewallet=1", "-dbcache=256", "-par=1", "-parpow=1",
            f"-mocktime={MOCKTIME}", "-printtoconsole=0", "-blocksxor=0",
            f"-listen={int(self.listening)}",
        ]
        if self.listening:
            command.append(f"-bind=127.0.0.1:{self.p2p_port}")
        self.log = (self.data_dir / "console.log").open("wb")
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        start = time.perf_counter()
        self.proc = subprocess.Popen(command, stdout=self.log, stderr=self.log, creationflags=flags)
        deadline = start + 60
        while time.perf_counter() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"Node exited during startup. See {self.log.name}")
            try:
                if self.rpc("getblockhash", 0) != GENESIS:
                    raise RuntimeError("Unexpected Regtest genesis")
                return time.perf_counter() - start
            except (OSError, http.client.HTTPException, RpcError):
                time.sleep(0.02)
        raise TimeoutError(f"Node startup timed out. See {self.log.name}")

    def rpc(self, method, *params, timeout=4):
        if self.auth is None:
            self.auth = base64.b64encode(self.cookie.read_bytes().strip()).decode("ascii")
        connection = http.client.HTTPConnection("127.0.0.1", self.rpc_port, timeout=timeout)
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        try:
            connection.request("POST", "/", payload, {
                "Authorization": f"Basic {self.auth}", "Content-Type": "application/json",
            })
            response = connection.getresponse()
            body = json.loads(response.read())
            if body.get("error") is not None:
                raise RpcError(f"{method}: {body['error']['message']}")
            return body["result"]
        finally:
            connection.close()

    def close(self):
        start = time.perf_counter()
        if self.proc is not None and self.proc.poll() is None:
            try:
                self.rpc("stop", timeout=3)
                if self.proc.wait(timeout=25) != 0:
                    raise RuntimeError(f"Node shutdown failed. See {self.log.name}")
            except (OSError, http.client.HTTPException, RpcError, subprocess.TimeoutExpired):
                if self.proc.poll() is None:
                    self.proc.terminate()
                    try:
                        self.proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.proc.kill()
                        self.proc.wait(timeout=5)
                raise
            finally:
                self.log.close()
        elif self.log is not None:
            self.log.close()
        self.shutdown_seconds = time.perf_counter() - start


def sync(receiver, sender, blocks, expected_tip):
    if receiver.rpc("getblockcount") != 0:
        raise RuntimeError("The receiver must start with a fresh block index")
    start = time.perf_counter()
    receiver.rpc("addnode", f"127.0.0.1:{sender.p2p_port}", "onetry")
    deadline = start + 300
    headers_ready = None
    while time.perf_counter() < deadline:
        info = receiver.rpc("getblockchaininfo")
        now = time.perf_counter()
        if info["headers"] == blocks and headers_ready is None:
            headers_ready = now - start
        if info["blocks"] == blocks:
            if info["bestblockhash"] != expected_tip:
                raise RuntimeError("Receiver tip does not match the deterministic fixture")
            peers = receiver.rpc("getpeerinfo")
            if len(peers) != 1 or not peers[0]["addr"].startswith("127.0.0.1:"):
                raise RuntimeError("Expected only the isolated loopback peer")
            return {"headers_seconds": headers_ready, "sync_seconds": now - start,
                    "blocks_per_second": blocks / (now - start)}
        time.sleep(0.025)
    raise TimeoutError(f"Sync stopped before reaching height {blocks}: {info['blocks']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--blocks", type=int, default=10000)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.blocks <= 30_000 or not 1 <= args.repeats <= 5:
        parser.error("Specify 1–30,000 blocks and 1–5 repetitions")
    exe = args.bin_dir.resolve() / ("sugarchaind.exe" if os.name == "nt" else "sugarchaind")
    out = args.work_dir.resolve()
    out.mkdir(exist_ok=False, parents=True)
    samples = []
    with Node(exe, out / "sender", listening=True) as sender:
        started = time.perf_counter()
        hashes = sender.rpc("generatetodescriptor", args.blocks, DESCRIPTOR, 1_000_000, timeout=180)
        fixture_seconds = time.perf_counter() - started
        if len(hashes) != args.blocks:
            raise RuntimeError("Sender did not generate the expected number of blocks")
        tip = hashes[-1]
        fixture_sha256 = hashlib.sha256("".join(hashes).encode("ascii")).hexdigest()
        version = sender.rpc("getnetworkinfo")["version"]
        for i in range(args.repeats):
            with Node(exe, out / f"receiver-{i+1}", listening=False) as receiver:
                sample = sync(receiver, sender, args.blocks, tip)
            samples.append(dict(sample, startup_seconds=receiver.startup_seconds,
                                shutdown_seconds=receiver.shutdown_seconds))
    result = {
        "platform": platform.platform(), "machine": platform.machine(), "logical_cpus": os.cpu_count(),
        "node_version": version, "genesis": GENESIS, "blocks": args.blocks,
        "fixture_tip": tip, "fixture_sha256": fixture_sha256, "fixture_seconds": fixture_seconds,
        "mocktime": MOCKTIME, "dbcache_mib": 256, "repeats": samples,
        "median_sync_seconds": statistics.median(sample["sync_seconds"] for sample in samples),
        "median_blocks_per_second": statistics.median(sample["blocks_per_second"] for sample in samples),
    }
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))


if __name__ == "__main__":
    main()

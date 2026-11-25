#!/usr/bin/env python3
"""Compare historical loopback sync with two release binaries on one host."""

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
MAX_TIP_AGE = 24 * 60 * 60
RECEIVER_TIME = MOCKTIME + 2 * MAX_TIP_AGE
DESCRIPTOR = "raw(51)"
GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"


def available_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class RpcError(RuntimeError):
    pass


class Node:
    def __init__(self, executable, data_dir, *, listening=False, reopen=False):
        self.data_dir = data_dir
        self.executable = executable
        self.rpc_port = available_port()
        self.p2p_port = available_port()
        while self.p2p_port == self.rpc_port:
            self.p2p_port = available_port()
        self.listening = listening
        self.reopen = reopen
        self.cookie = data_dir / "regtest/.cookie"
        self.proc = None
        self.log = None
        self.auth = None

    def __enter__(self):
        self.data_dir.mkdir(exist_ok=self.reopen)
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
            "-checkblockindex=0", f"-maxtipage={MAX_TIP_AGE}",
            f"-mocktime={MOCKTIME if self.listening else RECEIVER_TIME}",
            "-printtoconsole=0", "-blocksxor=0",
            f"-listen={int(self.listening)}",
        ]
        if self.listening:
            command.append(f"-bind=127.0.0.1:{self.p2p_port}")
        self.log = (self.data_dir / "console.log").open("ab")
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
            if response.status == 401:
                self.auth = None
                raise RpcError(f"{method}: RPC cookie was rejected")
            try:
                body = json.loads(response.read())
            except (ValueError, UnicodeError) as exc:
                raise RpcError(f"{method}: invalid RPC response, HTTP {response.status}") from exc
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
    initial = receiver.rpc("getblockchaininfo")
    if initial["blocks"] != 0 or not initial["initialblockdownload"]:
        raise RuntimeError("The receiver must start fresh in IBD")
    start = time.perf_counter()
    receiver.rpc("addnode", f"127.0.0.1:{sender.p2p_port}", "onetry")
    deadline = start + 300
    headers_ready = None
    while time.perf_counter() < deadline:
        info = receiver.rpc("getblockchaininfo")
        now = time.perf_counter()
        if not info["initialblockdownload"]:
            raise RuntimeError("Receiver exited IBD during historical sync")
        if info["headers"] == blocks and headers_ready is None:
            headers_ready = now - start
        if info["blocks"] == blocks:
            if info["bestblockhash"] != expected_tip:
                raise RuntimeError("Receiver tip does not match the deterministic fixture")
            peers = receiver.rpc("getpeerinfo")
            if len(peers) != 1 or not peers[0]["addr"].startswith("127.0.0.1:"):
                raise RuntimeError("Expected only the isolated loopback peer")
            receiver.rpc("syncwithvalidationinterfacequeue")
            completed = time.perf_counter()
            return {"headers_seconds": headers_ready, "sync_seconds": now - start,
                    "sync_and_callbacks_seconds": completed - start,
                    "blocks_per_second": blocks / (now - start)}
        time.sleep(0.025)
    raise TimeoutError(f"Sync stopped before reaching height {blocks}: {info['blocks']}")


def verify_reload(node, blocks, expected_tip, expected_utxo):
    info = node.rpc("getblockchaininfo")
    if info["blocks"] != blocks or info["bestblockhash"] != expected_tip:
        raise RuntimeError("Unexpected block index after receiver restart")
    if not info["initialblockdownload"]:
        raise RuntimeError("Reloaded receiver exited historical IBD")
    if not node.rpc("verifychain", 4, 0, timeout=300):
        raise RuntimeError("On-disk block and undo verification failed")
    utxo = node.rpc("gettxoutsetinfo", "hash_serialized_3", timeout=60)
    if utxo["bestblock"] != expected_tip or utxo["hash_serialized_3"] != expected_utxo:
        raise RuntimeError("Unexpected UTXO state after receiver restart")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-bin-dir", type=Path, required=True)
    parser.add_argument("--candidate-bin-dir", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--blocks", type=int, default=3000)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--sender", choices=("baseline", "candidate"), default="baseline")
    args = parser.parse_args()
    if not 1 <= args.blocks <= 30_000 or not 1 <= args.repeats <= 5:
        parser.error("Specify 1–30,000 blocks and 1–5 repetitions")
    exe_name = "sugarchaind.exe" if os.name == "nt" else "sugarchaind"
    executables = {
        "baseline": args.baseline_bin_dir.resolve() / exe_name,
        "candidate": args.candidate_bin_dir.resolve() / exe_name,
    }
    variants = {}
    for label, executable in executables.items():
        if not executable.is_file():
            parser.error(f"Missing {label} daemon: {executable}")
        with executable.open("rb") as binary:
            binary_digest = hashlib.file_digest(binary, "sha256").hexdigest()
        variants[label] = {"binary_sha256": binary_digest, "samples": []}
    out = args.work_dir.resolve()
    out.mkdir(exist_ok=False, parents=True)
    with Node(executables[args.sender], out / "sender", listening=True) as sender:
        started = time.perf_counter()
        hashes = sender.rpc("generatetodescriptor", args.blocks, DESCRIPTOR, 1_000_000, timeout=180)
        fixture_seconds = time.perf_counter() - started
        if len(hashes) != args.blocks:
            raise RuntimeError("Sender did not generate the expected number of blocks")
        tip = hashes[-1]
        fixture_sha256 = hashlib.sha256("".join(hashes).encode("ascii")).hexdigest()
        source_info = sender.rpc("getblockchaininfo")
        if source_info["time"] >= RECEIVER_TIME - MAX_TIP_AGE:
            raise RuntimeError("Fixture tip is too recent for historical IBD")
        source_utxo = sender.rpc("gettxoutsetinfo", "hash_serialized_3", timeout=60)
        if source_utxo["bestblock"] != tip:
            raise RuntimeError("Sender UTXO head does not match the fixture")
        expected_utxo = source_utxo["hash_serialized_3"]
        sample_order = []
        for i in range(args.repeats):
            order = list(executables)
            if i % 2:
                order.reverse()
            for label in order:
                data_dir = out / f"{label}-{i+1}"
                executable = executables[label]
                with Node(executable, data_dir) as receiver:
                    version = receiver.rpc("getnetworkinfo")["version"]
                    sample = sync(receiver, sender, args.blocks, tip)
                sample.update(startup_seconds=receiver.startup_seconds,
                              shutdown_seconds=receiver.shutdown_seconds)
                with Node(executable, data_dir, reopen=True) as reloaded:
                    verify_reload(reloaded, args.blocks, tip, expected_utxo)
                sample["reload_verified"] = True
                variants[label]["node_version"] = version
                variants[label]["samples"].append(sample)
                sample_order.append(label)
    for variant in variants.values():
        samples = variant["samples"]
        variant["median_sync_seconds"] = statistics.median(s["sync_seconds"] for s in samples)
        variant["median_blocks_per_second"] = statistics.median(s["blocks_per_second"] for s in samples)
    result = {
        "platform": platform.platform(), "machine": platform.machine(), "logical_cpus": os.cpu_count(),
        "genesis": GENESIS, "blocks": args.blocks,
        "fixture_tip": tip, "fixture_sha256": fixture_sha256, "fixture_seconds": fixture_seconds,
        "fixture_utxo_sha256": expected_utxo, "sender_time": MOCKTIME,
        "receiver_time": RECEIVER_TIME, "max_tip_age": MAX_TIP_AGE, "dbcache_mib": 256,
        "checkblockindex": 0, "sample_order": sample_order, "variants": variants,
        "sender_variant": args.sender, "sender_binary_sha256": variants[args.sender]["binary_sha256"],
        "baseline_over_candidate": variants["baseline"]["median_sync_seconds"]
        / variants["candidate"]["median_sync_seconds"],
    }
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for label, variant in variants.items():
        print(f"{label}: {variant['median_sync_seconds']:.3f} s median, "
              f"{variant['median_blocks_per_second']:.1f} blocks/s")
    print(f"Baseline/candidate time ratio: {result['baseline_over_candidate']:.3f}")
    print(f"Full result: {out / 'result.json'}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Measure an exact release executable on its native OS and architecture."""

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
import struct
import sys
import subprocess
import time


MOCKTIME = 1795584000
MAX_TIP_AGE = 24 * 60 * 60
RECEIVER_TIME = MOCKTIME + 2 * MAX_TIP_AGE
DESCRIPTOR = "raw(51)"
GENESIS = {
    "regtest": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
    "testnet7": "14f06e88eec9b21214a1eb54eee3cc03ceaf78ead1b16e40d8a383a5ff3e5e24",
}


def available_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class RpcError(RuntimeError):
    pass


class Node:
    def __init__(self, executable, data_dir, network, *, listening=False, reopen=False, gui=False, gui_args=()):
        self.data_dir = data_dir
        self.network = network
        self.gui = gui
        self.gui_args = gui_args
        self.executable = executable
        self.rpc_port = available_port()
        self.p2p_port = available_port()
        while self.p2p_port == self.rpc_port:
            self.p2p_port = available_port()
        self.listening = listening
        self.reopen = reopen
        self.cookie = data_dir / network / ".cookie"
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
            str(self.executable), "-regtest" if self.network == "regtest" else "-testnet", f"-datadir={self.data_dir}", "-server=1",
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
        if self.network == "testnet7":
            command.append("-assumevalid=0")
        env = os.environ.copy()
        if self.gui:
            command.extend(("-splash=0", "-min", *self.gui_args))
            if platform.system() == "Linux":
                env["XDG_CONFIG_HOME"] = str(self.data_dir / "xdg-config")
                env["XDG_DATA_HOME"] = str(self.data_dir / "xdg-data")
            elif os.name == "nt":
                env["QT_QPA_PLATFORM"] = "windows"
        self.log = (self.data_dir / "console.log").open("ab")
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        start = time.perf_counter()
        self.proc = subprocess.Popen(command, stdout=self.log, stderr=self.log, creationflags=flags, env=env)
        deadline = start + 60
        while time.perf_counter() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"Node exited during startup. See {self.log.name}")
            try:
                if self.rpc("getblockhash", 0) != GENESIS[self.network]:
                    raise RuntimeError("Unexpected network genesis")
                if platform.system() == "Linux":
                    actual_executable = Path(f"/proc/{self.proc.pid}/exe")
                    if not actual_executable.exists() or not actual_executable.samefile(self.executable):
                        raise RuntimeError("Linux process is not running the requested package binary directly")
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
            return {"headers_seconds": headers_ready, "sync_seconds": now - start,
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

REGTEST_FIXTURE = {
    "blocks": 10_000,
    "fixture_sha256": "e9a32c1f46099faa4a901e1479aef2aab0bc13f1143d048d3d661564fc0ad2d9",
    "fixture_tip": "634c6ae57600a991a51009c92cba732d9ed96504d0e636df534bc45cdd3a8e28",
    "fixture_utxo_sha256": "63208d710cf03c30de2660b77a5434181b20fd1c5e70460b256ea4f4e798cb84",
}


def sha256_file(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def native_environment(system, architecture):
    machine = platform.machine().lower()
    if platform.system().lower() != {"linux": "linux", "macos": "darwin", "windows": "windows"}[system]:
        raise RuntimeError("The host OS differs from the release target")
    machines = {
        "x86_64": ("x86_64", "amd64"), "arm64": ("aarch64", "arm64"),
        "armhf": ("armv7l", "armv8l", "armv7", "armv8", "aarch64", "arm64"),
        "ppc64": ("ppc64", "powerpc64"), "riscv64": ("riscv64",),
    }
    if machine not in machines[architecture]:
        raise RuntimeError(f"Machine {machine} cannot run the {architecture} target natively")
    if system == "macos":
        probe = subprocess.run(["sysctl", "-n", "sysctl.proc_translated"], capture_output=True, text=True)
        if probe.returncode == 0 and probe.stdout.strip() != "0":
            raise RuntimeError("Translated macOS execution is not allowed")
    if system == "windows":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.IsWow64Process2.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_ushort), ctypes.POINTER(ctypes.c_ushort)]
        process = ctypes.c_ushort()
        hardware = ctypes.c_ushort()
        if not kernel.IsWow64Process2(kernel.GetCurrentProcess(), ctypes.byref(process), ctypes.byref(hardware)):
            raise ctypes.WinError(ctypes.get_last_error())
        if architecture != "x86_64" or hardware.value != 0x8664 or process.value != 0:
            raise RuntimeError("Native x86-64 Windows and Python are required")
    return machine


def verify_binary(executable, system, architecture):
    with executable.open("rb") as image:
        header = image.read(64)
        if system == "linux":
            expected = {"x86_64": (2, 1, 62), "arm64": (2, 1, 183),
                        "armhf": (1, 1, 40), "ppc64": (2, 2, 21), "riscv64": (2, 1, 243)}
            if header[:4] != b"\x7fELF" or header[5] not in (1, 2):
                raise RuntimeError(f"Not an ELF executable: {executable}")
            order = "<" if header[5] == 1 else ">"
            identity = (header[4], header[5], struct.unpack_from(order + "H", header, 18)[0])
            if identity != expected[architecture]:
                raise RuntimeError(f"ELF target mismatch: {executable}")
            if architecture == "armhf" and not struct.unpack_from("<I", header, 36)[0] & 0x400:
                raise RuntimeError("ARM ELF does not declare the hard-float ABI")
        elif system == "macos":
            flag = {"x86_64": 0x01000007, "arm64": 0x0100000C}[architecture]
            if header[:4] != b"\xcf\xfa\xed\xfe" or struct.unpack_from("<I", header, 4)[0] != flag:
                raise RuntimeError(f"Expected a single-architecture Mach-O for {architecture}: {executable}")
        else:
            if header[:2] != b"MZ":
                raise RuntimeError(f"Not a Windows executable: {executable}")
            image.seek(struct.unpack_from("<I", header, 60)[0])
            if image.read(6) != b"PE\0\0\x64\x86":
                raise RuntimeError(f"Expected a native x86-64 PE executable: {executable}")


def preload_testnet7(sender, path):
    fixture = json.loads(path.read_text(encoding="utf-8"))
    if (fixture["network"], fixture["genesis"], fixture["blocks"]) != ("testnet7", GENESIS["testnet7"], 102):
        raise RuntimeError("Unexpected Testnet7 fixture identity")
    if (fixture["sender_time"], fixture["receiver_time"], fixture["max_tip_age"]) != (MOCKTIME, RECEIVER_TIME, MAX_TIP_AGE):
        raise RuntimeError("Unexpected Testnet7 fixture clock")
    raw_blocks = [bytes.fromhex(raw) for raw in fixture["raw_blocks"]]
    hashes = fixture["block_hashes"]
    if len(raw_blocks) != len(hashes) or len(hashes) != fixture["blocks"] or any(len(raw) <= 80 for raw in raw_blocks):
        raise RuntimeError("Invalid Testnet7 block list")
    if hashlib.sha256(b"".join(raw_blocks)).hexdigest() != fixture["ordered_raw_blocks_sha256"]:
        raise RuntimeError("Unexpected Testnet7 raw-block hash")
    if hashlib.sha256(bytes.fromhex("".join(hashes))).hexdigest() != fixture["fixture_sha256"]:
        raise RuntimeError("Unexpected Testnet7 ordered block hash")
    if hashes[-1] != fixture["fixture_tip"]:
        raise RuntimeError("Unexpected Testnet7 fixture tip")
    for height, (raw, expected) in enumerate(zip(raw_blocks, hashes, strict=True), start=1):
        header_hash = hashlib.sha256(hashlib.sha256(raw[:80]).digest()).digest()[::-1].hex()
        if header_hash != expected:
            raise RuntimeError(f"Header/block hash mismatch at height {height}")
        response = sender.rpc("submitblock", raw.hex(), timeout=60)
        if response is not None:
            raise RuntimeError(f"Testnet7 block {height} rejected: {response}")
    if not sender.rpc("verifychain", 4, 0, timeout=300):
        raise RuntimeError("Testnet7 sender fixture verification failed")
    return {key: fixture[key] for key in REGTEST_FIXTURE} | {
        "fixture_file_sha256": sha256_file(path),
        "ordered_raw_blocks_sha256": fixture["ordered_raw_blocks_sha256"],
        "fixture_origin": fixture["kind"],
    }


def make_fixture(sender, network, path):
    info = sender.rpc("getblockchaininfo")
    if info["blocks"] != 0 or info["chain"] != {"regtest": "regtest", "testnet7": "test"}[network]:
        raise RuntimeError("Sender did not start on the expected fresh chain")
    started = time.perf_counter()
    if network == "regtest":
        hashes = sender.rpc("generatetodescriptor", REGTEST_FIXTURE["blocks"], DESCRIPTOR, 1_000_000, timeout=180)
        if len(hashes) != REGTEST_FIXTURE["blocks"] or hashes[-1] != REGTEST_FIXTURE["fixture_tip"]:
            raise RuntimeError("Regtest block count or tip differs from the historical fixture")
        if hashlib.sha256("".join(hashes).encode("ascii")).hexdigest() != REGTEST_FIXTURE["fixture_sha256"]:
            raise RuntimeError("Regtest ordered block hashes differ from the historical fixture")
        fixture = REGTEST_FIXTURE.copy()
    else:
        fixture = preload_testnet7(sender, path)
    info = sender.rpc("getblockchaininfo")
    if (info["blocks"], info["bestblockhash"]) != (fixture["blocks"], fixture["fixture_tip"]):
        raise RuntimeError("Sender did not reach the expected fixture tip")
    if info["time"] >= RECEIVER_TIME - MAX_TIP_AGE:
        raise RuntimeError("Fixture tip is too recent for the historical IBD run")
    utxo = sender.rpc("gettxoutsetinfo", "hash_serialized_3", timeout=60)
    if (utxo["bestblock"], utxo["hash_serialized_3"]) != (fixture["fixture_tip"], fixture["fixture_utxo_sha256"]):
        raise RuntimeError("Unexpected fixture UTXO state")
    fixture["fixture_seconds"] = time.perf_counter() - started
    return fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sender", type=Path, required=True)
    parser.add_argument("--receiver", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--platform", choices=("linux", "macos", "windows"), required=True)
    parser.add_argument("--arch", choices=("x86_64", "arm64", "armhf", "ppc64", "riscv64"), required=True)
    parser.add_argument("--network", choices=tuple(GENESIS), required=True)
    parser.add_argument("--runner", default=os.environ.get("BENCH_RUNNER", os.environ.get("RUNNER_NAME", "local")))
    parser.add_argument("--archive-sha256", default=None)
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--gui-arg", action="append", default=[])
    args = parser.parse_args()
    if (args.network == "testnet7") != (args.fixture is not None):
        parser.error("Use --fixture only for Testnet7; it is required there")
    if args.gui_arg and not args.gui:
        parser.error("--gui-arg requires --gui")
    if args.archive_sha256 is not None and (len(args.archive_sha256) != 64 or not all(c in "0123456789abcdef" for c in args.archive_sha256)):
        parser.error("--archive-sha256 requires a lower-case SHA-256 value")
    machine = native_environment(args.platform, args.arch)
    sender_path = args.sender.resolve(strict=True)
    executable = args.receiver.resolve(strict=True)
    for path in (sender_path, executable):
        verify_binary(path, args.platform, args.arch)
    out = args.work_dir.resolve()
    out.mkdir(exist_ok=False, parents=True)
    samples = []
    with Node(sender_path, out / "sender", args.network, listening=True) as sender:
        fixture = make_fixture(sender, args.network, args.fixture)
        for repeat in range(1, 4):
            directory = out / f"receiver-{repeat}"
            with Node(executable, directory, args.network, gui=args.gui, gui_args=args.gui_arg) as receiver:
                version = receiver.rpc("getnetworkinfo")["version"]
                sample = sync(receiver, sender, fixture["blocks"], fixture["fixture_tip"])
            sample.update(startup_seconds=receiver.startup_seconds, shutdown_seconds=receiver.shutdown_seconds)
            with Node(executable, directory, args.network, reopen=True, gui=args.gui, gui_args=args.gui_arg) as reloaded:
                verify_reload(reloaded, fixture["blocks"], fixture["fixture_tip"], fixture["fixture_utxo_sha256"])
            sample["reload_verified"] = True
            samples.append(sample)
            print(f"{args.network} {args.arch} sample {repeat}: {sample['sync_seconds']:.6f} s", flush=True)
    result = {
        "platform": platform.platform(), "system": platform.system(), "machine": machine,
        "logical_cpus": os.cpu_count(), "runner": args.runner, "runner_image_version": os.getenv("ImageVersion"),
        "target_platform": args.platform, "target_arch": args.arch, "network": args.network,
        "native": True, "gui": args.gui, "node_version": version,
        "archive_sha256": args.archive_sha256, "binary_sha256": sha256_file(executable),
        "sender_binary_sha256": sha256_file(sender_path),
        "genesis": GENESIS[args.network], **fixture, "sender_time": MOCKTIME,
        "receiver_time": RECEIVER_TIME, "max_tip_age": MAX_TIP_AGE, "dbcache_mib": 256,
        "checkblockindex": 0, "samples": samples,
        "median_sync_seconds": statistics.median(row["sync_seconds"] for row in samples),
        "median_blocks_per_second": statistics.median(row["blocks_per_second"] for row in samples),
    }
    path = out / "result.json"
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Verified {args.network} {args.arch} median: {result['median_sync_seconds']:.6f} s ({path})")


if __name__ == "__main__":
    main()

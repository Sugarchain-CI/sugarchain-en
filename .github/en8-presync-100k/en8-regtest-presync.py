#!/usr/bin/env python3
"""Measure startup-to-IBD-clear on a fixed En.8 regtest fixture."""

import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import socket
import statistics
import struct
import subprocess
import sys
import time

RELEASE_SOURCE = "ba6ba77698f9a0759063604c4f87ce3eab93c107"
RELEASE_TREE = "585f08d47bc953b7863d2fc3ba51f3ea762bc36f"
GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
HEIGHT = 100_000
FIXTURE_SHA = "93dd96da0a4cefa7895639f8aa64e10daf04b6f57b01e7299fd76e7b7bb5e1a6"
FIXTURE_TIP = "7ce4e878bade0534f53339c5be61cc511807b72d3701c9c363e7a7072151688b"
FIXTURE_WORK = f"{2 * (HEIGHT + 1):064x}"
FIXTURE_UTXO = "0be481090de425b71184f78a5f45dbc99d266891343b43ad8036a5712173d02f"
TRIAL_COUNT = 3


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def write_json(path, value):
    staging = path.with_suffix(".tmp")
    staging.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    staging.replace(path)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fixture_metadata(path, raw_path):
    info = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "schema": 1, "network": "regtest", "blocks": HEIGHT,
        "frame_count": HEIGHT, "genesis": GENESIS, "tip": FIXTURE_TIP,
        "chainwork": FIXTURE_WORK, "utxo_sha256": FIXTURE_UTXO,
        "fixture_sha256": FIXTURE_SHA, "raw_bytes": 23_767_090,
        "mocktime": 1_795_684_100, "max_tip_age": 86_400, "tip_time": 1_795_683_166,
        "generator_source": RELEASE_SOURCE, "coinbase_only": True,
    }
    for key, expected in required.items():
        actual = info.get(key)
        require(type(actual) is type(expected) and actual == expected, f"Unexpected fixture metadata: {key}")
    require(raw_path.stat().st_size == info["raw_bytes"], "Unexpected fixture byte size")
    require(sha256_file(raw_path) == FIXTURE_SHA, "Fixture SHA-256 mismatch")
    if "raw_file_sha256" in info:
        require(info["raw_file_sha256"] == FIXTURE_SHA, "Conflicting raw fixture digest")
    return required


def available_port(exclude=()):
    while True:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        if port not in exclude:
            return port


class RpcError(RuntimeError):
    pass


class Node:
    def __init__(self, executable, path, info, *, fixture=None, peer_port=None, gui_args=None):
        self.executable = executable
        self.path = path
        self.debug = path / "debug.log"
        self.console = path / "console.log"
        self.datadir = path / "data"
        self.cookie = self.datadir / "regtest" / ".cookie"
        self.path.mkdir()
        self.datadir.mkdir()
        self.rpc_port = available_port((peer_port,))
        self.p2p_port = available_port((self.rpc_port,)) if fixture else None
        self.auth = None
        self.proc = None
        self.started = None
        self.log = None
        flags = [
            "-regtest", f"-datadir={self.datadir}", "-server=1",
            "-rpcbind=127.0.0.1", f"-rpcport={self.rpc_port}", "-rpcallowip=127.0.0.1",
            "-discover=0", "-dnsseed=0", "-fixedseeds=0", "-listenonion=0",
            "-disablewallet=1", "-assumevalid=0", "-dbcache=256", "-par=1", "-parpow=1",
            "-checkblockindex=0", "-blocksxor=0", "-printtoconsole=0", "-shrinkdebugfile=0",
            f"-debuglogfile={self.debug}", "-debug=net", "-logtimemicros=1",
            f"-minimumchainwork={info['chainwork']}",
            f"-mocktime={info['mocktime']}", f"-maxtipage={info['max_tip_age']}",
        ]
        if fixture:
            flags.extend(("-connect=0", "-listen=1", f"-bind=127.0.0.1:{self.p2p_port}", f"-loadblock={fixture}"))
        else:
            require(peer_port is not None, "Receiver requires an isolated sender")
            flags.extend(("-listen=0", f"-connect=127.0.0.1:{peer_port}"))
        self.env = os.environ.copy()
        if gui_args is not None:
            flags.extend(("-splash=0", *gui_args))
            self.env["XDG_CONFIG_HOME"] = str(self.path / "xdg-config")
            self.env["XDG_DATA_HOME"] = str(self.path / "xdg-data")
            if os.name == "nt":
                self.env["QT_QPA_PLATFORM"] = "windows"
            if sys.platform == "darwin":
                self.env["CFFIXED_USER_HOME"] = str(self.path)
        self.argv = [str(executable), *flags]
        self.creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

    def start(self):
        self.log = self.console.open("wb")
        self.started = time.perf_counter()
        self.proc = subprocess.Popen(self.argv, stdout=self.log, stderr=self.log,
                                     creationflags=self.creation_flags, env=self.env)

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
                raise RpcError(f"{method}: RPC authentication rejected")
            try:
                body = json.loads(response.read())
            except (ValueError, UnicodeError) as exc:
                raise RpcError(f"{method}: invalid RPC response (HTTP {response.status})") from exc
            if body.get("error") is not None:
                raise RpcError(f"{method}: {body['error']['message']}")
            return body["result"]
        finally:
            connection.close()

    def verify_process(self):
        if sys.platform.startswith("linux"):
            actual = Path(f"/proc/{self.proc.pid}/exe")
            require(actual.samefile(self.executable), "Linux /proc executable identity differs from release binary")

    def close(self):
        begin = time.perf_counter()
        receipt = {
            "pid": self.proc.pid if self.proc else None,
            "rpc_ack": False, "forced": False, "reaped": False,
            "returncode": None, "clean_shutdown": False, "errors": [],
        }
        try:
            if self.proc is not None:
                if self.proc.poll() is None:
                    try:
                        self.rpc("stop", timeout=4)
                        receipt["rpc_ack"] = True
                        self.proc.wait(timeout=45)
                    except (OSError, http.client.HTTPException, RpcError, subprocess.TimeoutExpired) as exc:
                        receipt["errors"].append(f"{type(exc).__name__}: {exc}")
                    if self.proc.poll() is None:
                        receipt["forced"] = True
                        try:
                            self.proc.terminate()
                            self.proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            self.proc.kill()
                            self.proc.wait(timeout=5)
                receipt["reaped"] = self.proc.poll() is not None
                receipt["returncode"] = self.proc.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            receipt["errors"].append(f"{type(exc).__name__}: {exc}")
        finally:
            if self.log is not None:
                self.log.close()
        if self.debug.is_file():
            with self.debug.open(encoding="utf-8", errors="replace") as stream:
                shutdowns = sum("Shutdown done" in line for line in stream)
            receipt["clean_shutdown"] = shutdowns == 1
        receipt["shutdown_seconds"] = time.perf_counter() - begin
        return receipt


def await_tip(node, cap_seconds, info):
    deadline = node.started + cap_seconds
    first_rpc = None
    first_state = None
    last_state = None
    last_error = None
    while (remaining := deadline - time.perf_counter()) > 0:
        require(node.proc.poll() is None, f"Node exited before target, see {node.console}")
        try:
            state = node.rpc("getblockchaininfo", timeout=min(remaining, 1.0))
        except (OSError, http.client.HTTPException, RpcError) as exc:
            last_error = str(exc)
        else:
            received = time.perf_counter()
            if first_rpc is None:
                first_rpc = received - node.started
                first_state = {key: state[key] for key in ("blocks", "headers", "initialblockdownload")}
            last_state = {key: state[key] for key in ("blocks", "headers", "initialblockdownload")}
            require(state["chain"] == "regtest", "RPC returned the wrong active network")
            require(state["blocks"] <= HEIGHT and state["headers"] <= HEIGHT, "Node exceeded fixture height")
            if state["blocks"] == state["headers"] == HEIGHT:
                require(state["bestblockhash"] == info["tip"], "Node reached the wrong tip")
                require(state["chainwork"] == info["chainwork"], "Node reached the wrong cumulative work")
                if state["initialblockdownload"] is False and received <= deadline:
                    return {
                        "startup_to_ibd_clear_seconds": received - node.started,
                        "first_rpc_seconds": first_rpc,
                        "first_rpc_state": first_state,
                        "initialblockdownload": False,
                        "blocks": HEIGHT,
                        "headers": HEIGHT,
                        "bestblockhash": info["tip"],
                        "chainwork": info["chainwork"],
                    }
        time.sleep(0.025)
    raise TimeoutError(f"Target not reached in {cap_seconds}s, last progress {last_state}, last RPC error {last_error}")


def tip_proof(node, info):
    require(node.rpc("getblockhash", 0) == info["genesis"], "Unexpected genesis")
    raw = bytes.fromhex(node.rpc("getblockheader", info["tip"], False))
    header = node.rpc("getblockheader", info["tip"], True)
    require(len(raw) == 80, "Unexpected serialized block header size")
    digest = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
    bits = struct.unpack_from("<I", raw, 72)[0]
    exponent, mantissa = bits >> 24, bits & 0x7FFFFF
    require(exponent >= 3 and not bits & 0x800000, "Invalid compact proof target")
    target = mantissa << (8 * (exponent - 3))
    require(0 < target <= (1 << 255) - 1, "Tip proof target exceeds regtest powLimit")
    require(digest[::-1].hex() == info["tip"], "Independent SHA256d header hash mismatch")
    require(int.from_bytes(digest, "little") <= target, "Independent SHA256d proof does not meet target")
    require(header["height"] == HEIGHT and header["chainwork"] == info["chainwork"],
            "Tip header height or chainwork mismatch")
    require(header["bits"] == f"{bits:08x}" and header["time"] == info["tip_time"],
            "Tip header difficulty or timestamp mismatch")
    return {
        "height": HEIGHT, "hash": info["tip"], "chainwork": info["chainwork"], "time": header["time"],
        "algorithm": "SHA256d", "bits": f"{bits:08x}", "target": f"{target:064x}",
        "serialized_header": raw.hex(), "meets_target": True,
    }


def utxo(node, info):
    coins = node.rpc("gettxoutsetinfo", "hash_serialized_3", timeout=120)
    require(coins["height"] == HEIGHT and coins["bestblock"] == info["tip"], "UTXO tip mismatch")
    require(coins["hash_serialized_3"] == info["utxo_sha256"], "UTXO digest mismatch")
    return {key: coins[key] for key in ("height", "bestblock", "hash_serialized_3", "txouts")}


def phase_evidence(log_path):
    patterns = {
        "presync_started": r"Initial headers sync started with peer=(\d+): height=(\d+), max_commitments=\d+, min_work=([0-9a-f]{64})",
        "redownload_started": r"Initial headers sync transition with peer=(\d+): reached sufficient work at height=(\d+), redownloading from height=(\d+)",
        "redownload_completed": r"Initial headers sync complete with peer=(\d+): releasing all at height=(\d+) \(redownload phase\)",
        "body_progress": rf"UpdateTip: new best={FIXTURE_TIP}\b[^\r\n]*\bheight={HEIGHT}\b",
        "ibd_clear": r"Leaving InitialBlockDownload \(latching to false\)",
    }
    found = {key: [] for key in patterns}
    compiled = {key: re.compile(value) for key, value in patterns.items()}
    aborts = 0
    with log_path.open(encoding="utf-8", errors="replace") as stream:
        for number, line in enumerate(stream, 1):
            if "Initial headers sync aborted" in line:
                aborts += 1
            for key, pattern in compiled.items():
                if match := pattern.search(line):
                    found[key].append({"line": number, "groups": list(match.groups())})
    require(not aborts and all(len(rows) == 1 for rows in found.values()),
            f"Unexpected stock phase markers: { {k: len(v) for k, v in found.items()} }, aborts={aborts}")
    events = {key: rows[0] for key, rows in found.items()}
    peer, initial_height, minimum_work = events["presync_started"]["groups"]
    require(initial_height == "0" and minimum_work == FIXTURE_WORK, "PRESYNC started at wrong height/work")
    require(events["redownload_started"]["groups"] == [peer, str(HEIGHT), "0"],
            "REDOWNLOAD did not restart the same locked chain from genesis")
    require(events["redownload_completed"]["groups"] == [peer, str(HEIGHT)], "REDOWNLOAD did not reach full fixture")
    require(events["presync_started"]["line"] < events["redownload_started"]["line"]
            < events["redownload_completed"]["line"] < events["body_progress"]["line"]
            and events["redownload_completed"]["line"] < events["ibd_clear"]["line"],
            "Phase marker order does not match full synchronization")
    return events


def verify_chain(node, cap_seconds):
    begin = time.perf_counter()
    require(node.rpc("verifychain", 4, HEIGHT, timeout=cap_seconds) is True, "Stock verifychain 4 failed")
    elapsed = time.perf_counter() - begin
    with node.debug.open(encoding="utf-8", errors="replace") as stream:
        logs = [(number, line) for number, line in enumerate(stream, 1)
                if "Verifying last " in line or "No coin database inconsistencies" in line]
    start = [line for line, text in logs if f"Verifying last {HEIGHT} blocks at level 4" in text]
    check = [line for line, text in logs if f"No coin database inconsistencies in last {HEIGHT} blocks ({HEIGHT} transactions)" in text]
    require(len(start) == len(check) == 1 and start[0] < check[0],
            "Full level-4 depth/transaction confirmation missing in stock log")
    return {"seconds": elapsed, "level": 4, "blocks": HEIGHT, "transactions": HEIGHT,
            "start_line": start[0], "completion_line": check[0]}


def successful_close(receipt):
    return (receipt["rpc_ack"] and not receipt["forced"] and receipt["reaped"]
            and receipt["returncode"] == 0 and receipt["clean_shutdown"] and not receipt["errors"])


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


def run_trial(node, info, cap_seconds):
    result = {"status": "failed"}
    try:
        node.start()
        result["sync"] = await_tip(node, cap_seconds, info)
        node.verify_process()
        result["phases"] = phase_evidence(node.debug)
        result["tip_proof"] = tip_proof(node, info)
        result["verifychain"] = verify_chain(node, cap_seconds)
        result["utxo"] = utxo(node, info)
        result["status"] = "passed"
    except (RuntimeError, OSError, TimeoutError, ValueError, KeyError, http.client.HTTPException) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        result["cleanup"] = node.close()
        result["shutdown_seconds"] = result["cleanup"]["shutdown_seconds"]
        if not successful_close(result["cleanup"]):
            result["status"] = "failed"
            if "error" not in result:
                result["error"] = "Receiver did not complete controlled shutdown"
        write_json(node.path / "result.json", result)
    return result


def gui_arguments(values):
    allowed = {"-choosedatadir=0"}
    require(all(value in allowed for value in values),
            "Only the non-network GUI argument -choosedatadir=0 is supported")
    return tuple(dict.fromkeys(("-choosedatadir=0", *values)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sender", required=True, type=Path)
    parser.add_argument("--receiver", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--fixture-info", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--platform", choices=("linux", "windows", "macos"), required=True)
    parser.add_argument("--arch", choices=("x86_64", "arm64", "armhf", "ppc64", "riscv64"), required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--receiver-sha256", required=True)
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--gui-arg", action="append", default=[])
    parser.add_argument("--trial-seconds", type=int, default=300)
    args = parser.parse_args()
    require(args.work_dir.is_absolute(), "Use an absolute new work directory")
    work = args.work_dir.resolve()
    work.mkdir()
    attestation = {
        "schema": 1, "status": "failed", "network": "regtest", "blocks": HEIGHT,
        "interface": "gui" if args.gui else "cli", "platform": args.platform, "architecture": args.arch,
        "release_source": RELEASE_SOURCE, "release_tree": RELEASE_TREE,
        "timed_interval": "immediately before receiver Popen through first RPC reporting exact fixture tip and IBD false",
        "emulation": False, "trials": [],
    }
    sender = None
    try:
        require(1 <= args.trial_seconds <= 300, "Trial limit must be between 1 and 300 seconds")
        require(re.fullmatch(r"[0-9a-f]{64}", args.archive_sha256), "Invalid archive digest")
        require(re.fullmatch(r"[0-9a-f]{64}", args.receiver_sha256), "Invalid receiver digest")
        require(args.gui or not args.gui_arg, "GUI arguments require --gui")
        info = fixture_metadata(args.fixture_info.resolve(strict=True), args.fixture.resolve(strict=True))
        attestation["fixture"] = info
        attestation["machine"] = native_environment(args.platform, args.arch)
        attestation["os_release"] = platform.release()
        attestation["architecture_check"] = "native host and native executable image, direct Popen"
        sender_exe = args.sender.resolve(strict=True)
        receiver_exe = args.receiver.resolve(strict=True)
        for executable in (sender_exe, receiver_exe):
            verify_binary(executable, args.platform, args.arch)
        sender_hash = sha256_file(sender_exe)
        receiver_hash = sender_hash if receiver_exe == sender_exe else sha256_file(receiver_exe)
        require(receiver_hash == args.receiver_sha256, "Receiver executable SHA-256 mismatch")
        attestation["archive_sha256"] = args.archive_sha256
        attestation["sender_sha256"] = sender_hash
        attestation["receiver_sha256"] = receiver_hash
        attestation["trial_deadline_seconds"] = args.trial_seconds
        sender = Node(sender_exe, work / "sender", info, fixture=args.fixture.resolve(strict=True))
        sender.start()
        sender_tip = await_tip(sender, 300, info)
        sender.verify_process()
        attestation["sender"] = {"preparation_seconds": sender_tip["startup_to_ibd_clear_seconds"],
                                 "tip_proof": tip_proof(sender, info), "utxo": utxo(sender, info)}
        write_json(work / "result.json", attestation)
        for sequence in range(1, TRIAL_COUNT + 1):
            node = Node(receiver_exe, work / f"trial-{sequence:02}", info, peer_port=sender.p2p_port,
                        gui_args=gui_arguments(args.gui_arg) if args.gui else None)
            trial = run_trial(node, info, args.trial_seconds)
            attestation["trials"].append({"number": sequence, **trial})
            write_json(work / "result.json", attestation)
            require(trial["cleanup"]["reaped"] or trial["cleanup"]["pid"] is None,
                    "Receiver could not be reaped. No further processes will start.")
        require(all(trial["status"] == "passed" for trial in attestation["trials"]),
                "One or more fixed trials failed")
        timings = [trial["sync"]["startup_to_ibd_clear_seconds"] for trial in attestation["trials"]]
        attestation["median_startup_to_ibd_clear_seconds"] = statistics.median(timings)
        attestation["status"] = "passed"
    except (RuntimeError, OSError, TimeoutError, ValueError, KeyError, http.client.HTTPException) as exc:
        attestation["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if sender is not None:
            attestation["sender_cleanup"] = sender.close()
            if not successful_close(attestation["sender_cleanup"]):
                attestation["status"] = "failed"
                attestation.setdefault("error", "Sender did not complete controlled shutdown")
        if attestation["status"] != "passed":
            attestation.pop("median_startup_to_ibd_clear_seconds", None)
        write_json(work / "result.json", attestation)
    print(f"{attestation['status']} {work / 'result.json'}")
    return int(attestation["status"] != "passed")


if __name__ == "__main__":
    sys.exit(main())

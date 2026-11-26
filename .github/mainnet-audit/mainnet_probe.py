#!/usr/bin/env python3
"""Measure the published node on a bounded, isolated mainnet sample."""

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

IMPORT = re.compile(r"Loaded (\d+) blocks from external file in (\d+)ms")
HEADER = re.compile(
    r"^(\S+) (Pre-synchronizing|Synchronizing) blockheaders, height: (\d+)",
    re.MULTILINE,
)
MEMBERS = ("blocks", "headers", "initialblockdownload", "chain", "bestblockhash")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def rpc(path, port, method, *params):
    try:
        token = base64.b64encode((path / ".cookie").read_bytes().strip()).decode("ascii")
        body = json.dumps({"jsonrpc": "1.0", "id": "mainnet-audit", "method": method,
                           "params": params}).encode("ascii")
        request = Request(f"http://127.0.0.1:{port}/", body,
                          {"Authorization": f"Basic {token}", "Content-Type": "application/json"})
        with urlopen(request, timeout=1.3) as response:
            result = json.load(response)
            return result["result"] if not result.get("error") else None
    except (OSError, HTTPError, URLError, ValueError):
        return None


def check_host():
    if platform.system() == "Darwin":
        translated = subprocess.run(["sysctl", "-in", "sysctl.proc_translated"],
                                    capture_output=True, text=True).stdout.strip()
        if translated == "1":
            raise SystemExit("Rosetta is outside the native test scope.")


def log_text(path):
    try:
        return (path / "debug.log").read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def process_exit(path, proc):
    details = log_text(path).splitlines()
    return {"status": "exited_early", "exit_code": proc.returncode,
            "diagnostic": [line[:240] for line in details[-4:]]}


@contextmanager
def node(args, location, mode, fixture=None):
    location.mkdir()
    port = free_port()
    flags = [
        "-chain=main", f"-datadir={location}", "-server=1", f"-rpcport={port}",
        "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
        "-disablewallet=1", "-listen=0", "-discover=0", "-listenonion=0",
        "-logtimemicros=1",
    ]
    if mode == "import":
        flags += ["-networkactive=0", "-dnsseed=0", "-fixedseeds=0",
                  "-assumevalid=0", f"-loadblock={fixture}"]
    if args.gui:
        flags += ["-splash=0", "-min"]
    else:
        flags += ["-printtoconsole=0"]
    env = os.environ.copy()
    env["XDG_CONFIG_HOME"] = str(location / "gui-config")
    env["XDG_DATA_HOME"] = str(location / "gui-data")
    env["CFFIXED_USER_HOME"] = str(location)
    if args.gui and platform.system() == "Linux" and "QT_QPA_PLATFORM" not in env:
        env["QT_QPA_PLATFORM"] = "xcb"
    started = time.monotonic()
    with (location / "console.log").open("wb") as console:
        proc = subprocess.Popen([str(args.binary), *flags], env=env, stdout=console, stderr=console)
        try:
            yield proc, port, started
        finally:
            if proc.poll() is None:
                rpc(location, port, "stop")
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=4)


def import_blocks(args, root, fixture, expected):
    path = root / "import"
    with node(args, path, "import", fixture) as (process, port, start):
        while time.monotonic() - start < args.import_seconds:
            if process.poll() is not None:
                return process_exit(path, process)
            info = rpc(path, port, "getblockchaininfo")
            if info and info["blocks"] >= expected["last_height"]:
                match = IMPORT.search(log_text(path))
                if not match:
                    time.sleep(0.15)
                    continue
                count, elapsed = map(int, match.groups())
                genesis = rpc(path, port, "getblockhash", 0)
                verified = (count == expected["last_height"] and info["chain"] == "main"
                            and info["bestblockhash"] == expected["tip"]
                            and genesis == expected["genesis"])
                return {"status": "verified" if verified else "unexpected_chain",
                        "loaded_blocks": count, "import_seconds": elapsed / 1000,
                        "blocks_per_second": round(1000 * count / elapsed, 3) if elapsed else None,
                        "startup_to_observation_seconds": round(time.monotonic() - start, 3),
                        "genesis": genesis, **{k: info[k] for k in MEMBERS}}
            time.sleep(0.2)
        return {"status": "cap_reached", "observed": info,
                "elapsed_seconds": round(time.monotonic() - start, 3)}


def header_summary(rows, name):
    samples = [(stamp, height) for stamp, phase, height in rows if phase == name]
    if not samples:
        return None
    first_time, first = samples[0]
    last_time, last = max(samples, key=lambda row: row[1])
    seconds = (last_time - first_time).total_seconds()
    highest = first
    resets = 0
    for _, height in samples[1:]:
        if height < highest:
            resets += 1
            highest = height
        else:
            highest = height
    return {"first_height": first, "max_height": last, "last_logged_height": samples[-1][1],
            "elapsed_first_to_max_seconds": round(seconds, 3), "logged_samples": len(samples),
            "height_decreases": resets,
            "headers_per_second": round((last - first) / seconds, 3)
            if seconds > 0 and last > first and not resets else None}


def public_peers(args, root):
    path = root / "public"
    latest = None
    ready = None
    peer_counts = []
    with node(args, path, "public") as (process, port, start):
        deadline = start + args.network_seconds
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return process_exit(path, process)
            info = rpc(path, port, "getblockchaininfo")
            if info is not None:
                latest = {key: info[key] for key in MEMBERS}
                if ready is None:
                    ready = round(time.monotonic() - start, 3)
                peers = rpc(path, port, "getpeerinfo")
                if peers is not None:
                    peer_counts.append(sum(p.get("version", 0) > 0 for p in peers))
            time.sleep(max(0, min(2, deadline - time.monotonic())))
        elapsed = time.monotonic() - start
        rows = [(datetime.fromisoformat(stamp.replace("Z", "+00:00")), phase, int(height))
                for stamp, phase, height in HEADER.findall(log_text(path))]
        pre = header_summary(rows, "Pre-synchronizing")
        accepted = header_summary(rows, "Synchronizing")
        maximum = max(peer_counts, default=0)
        status = "progress" if pre or accepted or (latest and (latest["headers"] or latest["blocks"])) else (
            "no_header_progress" if maximum else "no_handshake" if latest else "rpc_not_ready")
        return {"status": status, "elapsed_seconds": round(elapsed, 3),
                "rpc_ready_seconds": ready, "peak_handshaken_peers": maximum,
                "observed": latest, "presync": pre, "accepted_headers": accepted}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--fixture-info", required=True, type=Path)
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--network-seconds", type=int, default=75)
    parser.add_argument("--import-seconds", type=int, default=80)
    parser.add_argument("--temp-root", type=Path)
    args = parser.parse_args()
    args.binary = args.binary.resolve(strict=True)
    check_host()
    expected = json.loads(args.fixture_info.read_text())
    archive = args.fixture.read_bytes()
    if digest(archive) != expected["archive_sha256"]:
        raise SystemExit("Fixture archive checksum mismatch.")
    blocks = gzip.decompress(archive)
    if digest(blocks) != expected["blocks_sha256"]:
        raise SystemExit("Mainnet block fixture checksum mismatch.")

    package = {"system": platform.system(), "system_release": platform.release(),
               "machine": platform.machine(), "cpu": platform.processor(),
               "logical_cpus": os.cpu_count(), "runner": os.environ.get("RUNNER_NAME"),
               "runner_image": os.environ.get("ImageOS"), "gui": args.gui,
               "binary": args.binary.name, "binary_sha256": digest(args.binary.read_bytes()),
               "fixture": expected}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="en-mainnet-", dir=args.temp_root) as tmp:
        root = Path(tmp)
        fixture = root / "mainnet-blocks.dat"
        fixture.write_bytes(blocks)
        package["offline_import"] = import_blocks(args, root, fixture, expected)
        args.output.write_text(json.dumps(package, indent=2) + "\n")
        print(f"{args.binary.name}: import {package['offline_import']['status']}", flush=True)
        package["public_peers"] = public_peers(args, root)
    args.output.write_text(json.dumps(package, indent=2) + "\n")
    print(f"{args.binary.name}: live {package['public_peers']['status']}", flush=True)


if __name__ == "__main__":
    main()

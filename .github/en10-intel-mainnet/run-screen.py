#!/usr/bin/env python3
"""Controlled body-delivery screen with the public Intel Mac release."""

import argparse
import asyncio
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import statistics
import subprocess
import sys
from types import SimpleNamespace

from mainnet_delivery import HEIGHT, NODE_COUNT, Resources, UTXO_COUNT, UTXO_SHA, block_geometry, get_fixture
from mainnet_delivery import header_chainwork, measure_case, persist
from mainnet_warm import make_batch

SOURCE = "ef4f3c07244505b8b1eb78d43f91dd5fa561b2bf"
TREE = "527d14fa0a9238828200ab643b56e718f3ba3bfb"
TAG = "v31.1.2-en.9"
BUILD_WORKFLOW = "0bcfd10eed50a2520532bf629bc0a3090bfe6c4c"
RELEASE_URL = f"https://github.com/decryp2kanon/sugarchain-en/releases/download/{TAG}"
KEY_FPR = "CF8F465D97437DA3BB25534D92F37F683E41E891"
KEY_SHA = "03c4bb8a655e61c932977d4d3ff778784e7b559a589eeb1c799a1f306d856729"
STEM = "sugarchain-en-31.1.2-macos-x86_64"
ARCHIVES = {"cli": f"{STEM}-cli.tar.gz", "gui": f"{STEM}.zip"}
PINS = {
    "SHA256SUMS": (1910, "c999c717d1d0ab96bafa11c2f2093af535012d384f7061f7d6d049f2d8435510"),
    "SHA256SUMS.asc": (2792, "e26a0ce0d721fd4ececb07c55e39c1b4dfe155c82469a32a5fa149478fbf9d60"),
    ARCHIVES["cli"]: (13742302, "1a92001c75d2a6f2c87a59b079edf19209548705c437a09d8f3e142f59a783a2"),
    ARCHIVES["gui"]: (18900189, "1d705c8c6b5def012ea77ba7264683eb6c2e2571e4e4803550679f0b2f099fc9"),
}
PROGRAM_SHA = {
    "cli": "28b2f898bcbee9e4e0ec84daa69a5de960cde86a1b0ca9adbf3c671625743cf2",
    "gui": "8c78bba9e786bf5a2816df1f83bdddb69669d33455caccc05d33f5509b343e1c",
}
ORDER = (16, 128, 16, 128, 128, 16, 16, 128, 128, 16)
DEADLINE_S = 120
MODES = ("cli", "gui")
LATENCIES = (0, 100)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def native_host():
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("RUNNER_OS") == "macOS"
            and os.environ.get("RUNNER_ARCH") == "X64", "Expected a standard GitHub-hosted Intel Mac")
    require(platform.system() == "Darwin" and platform.machine() == "x86_64", "Expected native x86_64 Darwin")
    translated = subprocess.run(["/usr/sbin/sysctl", "-n", "sysctl.proc_translated"], text=True,
                                capture_output=True, timeout=5)
    require(translated.returncode != 0 or translated.stdout.strip() == "0", "Rosetta translation is active")
    sysctl = lambda key: subprocess.check_output(["/usr/sbin/sysctl", "-n", key], text=True, timeout=5).strip()
    return {
        "platform": platform.platform(), "architecture": platform.machine(), "translated": False,
        "cpu": sysctl("machdep.cpu.brand_string"), "logical_cpus": os.cpu_count(),
        "physical_ram_bytes": int(sysctl("hw.memsize")), "runner": "macos-15-intel",
        "runner_image": os.environ.get("ImageVersion"), "workflow": os.environ["GITHUB_SHA"],
        "run_id": os.environ["GITHUB_RUN_ID"], "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
    }


def validate_release(directory, key, receipt):
    for filename, (size, checksum) in PINS.items():
        path = directory / filename
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == size
                and digest(path) == checksum, f"Wrong En.9 object {filename}")
    require(digest(key) == KEY_SHA, "Wrong trusted release keyring")
    gpgv = shutil.which("gpgv")
    require(gpgv is not None, "GnuPG's gpgv is required for the public release signature")
    receipt.mkdir(mode=0o700)
    signed = subprocess.run([gpgv, "--homedir", str(receipt), "--keyring", str(key), "--status-fd=2",
                             "--output", "-", str(directory / "SHA256SUMS.asc")],
                            capture_output=True, timeout=30)
    (receipt / "gpgv.log").write_bytes(signed.stderr)
    signed.check_returncode()
    signers = re.findall(rb"^\[GNUPG:\] VALIDSIG ([A-F0-9]+) ", signed.stderr, flags=re.MULTILINE)
    require(signers == [KEY_FPR.encode("ascii")], "Release signature uses the wrong key")
    expected = (directory / "SHA256SUMS").read_bytes()
    require(expected.endswith(b"\n") and not expected.endswith(b"\n\n"), "Wrong signed manifest terminator")
    require(signed.stdout == expected or signed.stdout + b"\n" == expected, "Wrong cleartext manifest")
    names = {}
    for line in expected.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        require(match is not None and match[2] not in names, "Malformed signed manifest")
        names[match[2]] = match[1]
    require(len(names) == 17, "Wrong En.9 signed manifest payload inventory")
    for name in ARCHIVES.values():
        require(names.get(name) == PINS[name][1], f"Signed digest differs for {name}")
    persist(receipt / "verification.json", {
        "fingerprint": KEY_FPR, "manifest_sha256": PINS["SHA256SUMS"][1],
        "cleartext": "exact" if signed.stdout == expected else "one final LF omitted by gpgv",
        "tag": TAG, "source": SOURCE, "tree": TREE, "producer_workflow": BUILD_WORKFLOW,
        "verified_archives": {name: PINS[name][1] for name in ARCHIVES.values()},
    })


def unpack(directory, runtime):
    cli, gui = (runtime / mode for mode in MODES)
    cli.mkdir(parents=True)
    gui.mkdir()
    subprocess.run(["/usr/bin/tar", "-xzf", str(directory / ARCHIVES["cli"]), "-C", str(cli)],
                   check=True, timeout=60)
    subprocess.run(["/usr/bin/ditto", "-x", "-k", str(directory / ARCHIVES["gui"]), str(gui)],
                   check=True, timeout=60)
    app = gui / "Sugarchain-Qt.app"
    binaries = {"cli": cli / f"{STEM}-cli/bin/sugarchaind", "gui": app / "Contents/MacOS/Sugarchain-Qt"}
    for mode, exe in binaries.items():
        require(exe.is_file() and not exe.is_symlink() and os.access(exe, os.X_OK)
                and digest(exe) == PROGRAM_SHA[mode], f"Wrong packaged {mode} executable")
        arch = subprocess.check_output(["/usr/bin/lipo", "-archs", str(exe)], text=True, timeout=10).strip()
        require(arch == "x86_64", f"Expected thin x86_64 Mach-O for {mode}, got {arch}")
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(binaries["cli"])], check=True, timeout=20)
    subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], check=True, timeout=20)
    return binaries


def schedule():
    return [{"interface": mode, "delay_ms": latency, "arm": "A" if ceiling == 16 else "B",
             "limit": ceiling, "slot": index, "scored": index > 2,
             "case": f"{mode}-{latency:03d}ms-{index:02d}-{ceiling}", "status": "not_started"}
            for mode in MODES for latency in LATENCIES for index, ceiling in enumerate(ORDER, 1)]


def check_output(result, trial, fixture, work, geometry):
    require(result["configured_request_limit"] == trial["limit"], "Wrong configured request ceiling")
    require(result["blocks"] == result["headers"] == result["unique_requested_blocks"] == HEIGHT,
            "End height or complete request set differs")
    require(result["initialblockdownload"] is True and result["chainwork"] == work
            and result["tip"] == fixture["tip"], "Wrong Mainnet body endpoint")
    require(result["utxo_hash"] == UTXO_SHA and result["utxo_count"] == UTXO_COUNT, "Wrong Mainnet UTXO")
    require(len(result["peer_counters"]) == NODE_COUNT, "Wrong peer count")
    require(result["block_body_bytes_received"] == geometry["raw_payload_bytes"], "Exact delivery bytes differ")
    require(1 <= result["wire_peak_pending_per_peer"] <= trial["limit"]
            and 0 <= result["peak_inflight_per_peer_sampled"] <= trial["limit"], "Observed ceiling violation")
    for key in ("verified_chain", "verified_chain_restart"):
        check = result[key]
        require(check["rpc"] is True and check["level"] == 4 and check["blocks"] == HEIGHT
                and check["transactions"] == geometry["transactions"], "Full stock VerifyDB coverage differs")
    reopened = result["offline_restart"]
    require(reopened["blocks"] == reopened["headers"] == HEIGHT and reopened["networkactive"] is False
            and reopened["initialblockdownload"] is True and reopened["chainwork"] == work
            and reopened["tip"] == fixture["tip"] and reopened["utxo_hash"] == UTXO_SHA
            and reopened["utxo_count"] == UTXO_COUNT, "Wrong clean reopened state")
    for key in ("shutdown", "shutdown_restart"):
        close = result[key]
        require(close["rpc_ack"] is True and close["reaped"] is True and close["clean_shutdown"] is True
                and close["forced"] is False and close["returncode"] == 0, "Owned node did not cleanly shut down")
    require(math.isfinite(result["seconds"]) and result["seconds"] > 0, "Invalid body duration")
    require(result["owned_node_resources"] is not None, "No owned-process CPU and I/O counters")


def apply_gate(cases):
    if [tuple(row[key] for key in ("case", "arm", "scored", "interface", "delay_ms", "limit", "slot"))
        for row in cases] != [tuple(row[key] for key in ("case", "arm", "scored", "interface", "delay_ms", "limit", "slot"))
                              for row in schedule()]:
        raise ValueError("Full frozen schedule changed")
    if any(row["status"] != "passed" for row in cases):
        return {"status": "correctness_failed", "groups": []}
    groups = []
    for mode in MODES:
        for latency in LATENCIES:
            selected = [row for row in cases if row["scored"] and row["interface"] == mode and row["delay_ms"] == latency]
            medians = {name: statistics.median(row["result"]["seconds"] for row in selected if row["arm"] == name)
                       for name in ("A", "B")}
            pairs = []
            for left, right in zip(selected[::2], selected[1::2], strict=True):
                a, b = sorted((left, right), key=lambda row: row["arm"])
                first, second = a["result"]["seconds"], b["result"]["seconds"]
                pairs.append({"order": left["arm"]+right["arm"], "a": first, "b": second, "b_minus_a": second-first,
                              "material_zero_delay_regression": second-first > max(.200, .10*first)})
            wins = sum(row["b_minus_a"] < 0 for row in pairs)
            if latency and any(row["result"]["wire_peak_pending_per_peer"] <= 16 for row in selected if row["arm"] == "B"):
                status = "inconclusive"
            elif latency:
                status = "passed" if medians["B"] < medians["A"] and wins >= 3 else "performance_failed"
            else:
                median_guard = medians["B"] - medians["A"] <= max(.100, .05*medians["A"])
                pair_guard = sum(row["material_zero_delay_regression"] for row in pairs) <= 1
                status = "passed" if median_guard and pair_guard else "performance_failed"
            groups.append({"interface": mode, "delay_ms": latency, "status": status,
                           "medians": medians, "pairs": pairs, "faster_pair_count": wins})
    statuses = [row["status"] for row in groups]
    overall = "inconclusive" if "inconclusive" in statuses else (
        "passed" if all(status == "passed" for status in statuses) else "performance_failed")
    return {"status": overall, "groups": groups}


def check_runtime(directory):
    for name in ("debug.log", "debug-restart.log"):
        raw = (directory / name).read_bytes()
        versions = re.findall(rb"Sugarchain En version v31\.1\.2-([a-f0-9]{12}) ", raw)
        require(versions == [SOURCE[:12].encode("ascii")], f"Wrong running source in {name}")


def safe_node_end(directory):
    for name in ("shutdown.json", "shutdown-restart.json"):
        receipt = directory / name
        if receipt.is_file() and json.loads(receipt.read_bytes()).get("reaped") is not True:
            return False
    return True


async def run(directory, release, runtime):
    directory.mkdir(mode=0o700)
    input_dir = Path(__file__).resolve().parent
    result_path = directory / "result.json"
    data = {
        "schema": 1, "status": "preflight", "mainnet": True, "ibd_exit": False,
        "scope": "Actual Mainnet 1..4096 early block delivery and activation, with loopback-only scripted peers",
        "time_boundary": "Owned peer announcement through first RPC observation of exact 4096-block tip",
        "excluded_from_duration": ["application launch", "header priming", "verifychain", "UTXO scans", "shutdown", "offline restart"],
        "release": TAG, "source": SOURCE, "tree": TREE, "net_debug": False,
        "minimumchainwork_override": 0, "assumevalid": 0, "peer_count": NODE_COUNT,
        "input_manifest_sha256": digest(input_dir / "inputs.sha256"),
        "cases": schedule(),
    }
    persist(result_path, data)
    try:
        data["host"] = native_host()
        validate_release(release, input_dir / "release-public.gpg", directory / "signature")
        binaries = unpack(release, runtime)
        data["programs"] = {mode: {"name": ARCHIVES[mode], "archive_sha256": PINS[ARCHIVES[mode]][1],
                                  "binary_sha256": PROGRAM_SHA[mode]} for mode in MODES}
        fixture, headers, blocks = get_fixture(input_dir / "mainnet-blocks.dat.gz", input_dir / "fixture.json")
        work = header_chainwork(headers)
        header_batch = make_batch("submitheader", [header.hex() for header in headers])
        geometry = block_geometry(blocks)
        data.update(status="running", fixture=fixture, fixture_geometry=geometry, chainwork=work)
        persist(result_path, data)
        resources = Resources()
        for trial in data["cases"]:
            case_dir = directory / trial["case"]
            mode = trial["interface"]
            cap = trial["limit"]
            plan = SimpleNamespace(binary=binaries[mode], gui=mode == "gui", timeout=DEADLINE_S,
                                   latency_ms=trial["delay_ms"])
            trial["status"] = "running"
            persist(result_path, data)
            try:
                result = await measure_case(plan, case_dir, fixture, headers, blocks, header_batch, cap, resources,
                                            request_limit=cap, verify_restart=True, require_wire_ceiling=False)
                trial["result"] = result
                check_output(result, trial, fixture, work, geometry)
                check_runtime(case_dir)
                trial["status"] = "passed"
                print(f"{trial['case']} {result['seconds']:.3f}s wire-peak={result['wire_peak_pending_per_peer']}", flush=True)
            except Exception as error:
                trial.update(status="failed", error=f"{type(error).__name__}: {error}")
                print(f"{trial['case']} {trial['error']}", file=sys.stderr, flush=True)
                if not safe_node_end(case_dir):
                    break
            finally:
                persist(result_path, data)
        data["gate"] = apply_gate(data["cases"])
        data["status"] = data["gate"]["status"]
    except Exception as error:
        data["status"] = "preflight_or_harness_failure"
        data["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        persist(result_path, data)
    return 0 if data["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-dir", required=True, type=Path)
    parser.add_argument("--runtime-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    require(args.download_dir.is_absolute() and args.runtime_dir.is_absolute() and args.output.is_absolute(),
            "Use absolute, isolated artifact directories")
    return asyncio.run(run(args.output, args.download_dir, args.runtime_dir))


if __name__ == "__main__":
    raise SystemExit(main())

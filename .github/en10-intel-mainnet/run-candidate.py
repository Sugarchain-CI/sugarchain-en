#!/usr/bin/env python3
"""Verify the Intel Mainnet request default in the exact candidate packages."""

import argparse
import asyncio
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import re
import sys
import tarfile
from types import SimpleNamespace
import zipfile

from mainnet_delivery import NODE_COUNT, Resources, block_geometry, get_fixture, header_chainwork, measure_case, persist
from mainnet_warm import make_batch

TOOLS = Path(__file__).resolve().parent
spec = spec_from_file_location("frozen_request_screen", TOOLS / "run-screen.py")
screen = module_from_spec(spec)
spec.loader.exec_module(screen)


def package_hashes(directory, source, tree, host):
    receipt = directory / "macos-x86_64-provenance.json"
    provenance = json.loads(receipt.read_bytes())
    expected = {
        "schema": 1, "status": "verified_release_packages", "arch": "x86_64", "platform": "macos",
        "source_sha": source, "source_tree": tree, "workflow_sha": host["workflow"],
        "run_id": int(host["run_id"]), "run_attempt": int(host["run_attempt"]),
        "code_signature": "ad-hoc", "apple_notarized": False,
    }
    screen.require(all(provenance.get(key) == value for key, value in expected.items()),
                   "Wrong exact-source/current-run candidate package receipt")
    screen.require(set(provenance["assets"]) == set(screen.ARCHIVES.values()), "Unexpected candidate archive list")
    hashes = {}
    assets = {}
    for mode, name in screen.ARCHIVES.items():
        package = directory / name
        assets[mode] = screen.digest(package)
        screen.require(assets[mode] == provenance["assets"][name], f"Wrong packaged SHA for {mode}")
        if mode == "cli":
            with tarfile.open(package, "r:gz") as archive:
                member = f"{screen.STEM}-cli/bin/sugarchaind"
                files = [entry for entry in archive if entry.name == member]
                screen.require(len(files) == 1 and files[0].isfile(), "Wrong daemon member in native candidate package")
                with archive.extractfile(files[0]) as program:
                    hashes[mode] = hashlib.file_digest(program, "sha256").hexdigest()
        else:
            with zipfile.ZipFile(package) as archive:
                member = "Sugarchain-Qt.app/Contents/MacOS/Sugarchain-Qt"
                files = [entry for entry in archive.infolist() if entry.filename == member]
                screen.require(len(files) == 1 and not files[0].is_dir(), "Wrong GUI member in native candidate package")
                with archive.open(files[0]) as program:
                    hashes[mode] = hashlib.file_digest(program, "sha256").hexdigest()
        screen.require(hashes[mode] != screen.PROGRAM_SHA[mode], f"Candidate {mode} still uses the baseline bytes")
    return hashes, assets, screen.digest(receipt)


def schedule():
    original = screen.schedule()
    result = []
    for index, row in enumerate(original, 1):
        row["request_limit"] = None
        row["purpose"] = "score" if row["scored"] else "warmup"
        row["release_role"] = "baseline" if row["arm"] == "A" else "candidate"
        result.append(row)
        if index % 10 == 0:
            mode, latency = row["interface"], row["delay_ms"]
            result.append({
                "interface": mode, "delay_ms": latency, "arm": "B", "limit": 16, "slot": 11, "scored": False,
                "case": f"{mode}-{latency:03d}ms-11-16-explicit", "status": "not_started",
                "request_limit": 16, "purpose": "explicit-control", "release_role": "candidate",
            })
    return result


def qualify(cases):
    defaults = screen.apply_gate([r for r in cases if r["purpose"] != "explicit-control"])
    controls = [r for r in cases if r["purpose"] == "explicit-control"]
    screen.require(len(controls) == 4, "Missing fixed explicit-16 control")
    control_passes = sum(c["status"] == "passed" for c in controls)
    status = defaults["status"] if control_passes == len(controls) else "correctness_failed"
    return {"status": status, "groups": defaults["groups"], "explicit_controls_passed": control_passes}


def check_config(directory, override):
    for name in ("debug.log", "debug-restart.log"):
        log = (directory / name).read_text(encoding="utf-8", errors="replace")
        rows = re.findall(r'^.*Command-line arg: maxibdblocksinflight="([^"\n]+)"$', log, flags=re.MULTILINE)
        expected = [] if override is None else [str(override)]
        screen.require(rows == expected, f"Unexpected request-limit option in {name}")


async def run(args):
    output = args.output
    output.mkdir(mode=0o700)
    record = output / "result.json"
    candidate_source = os.environ["RELEASE_SOURCE"]
    candidate_tree = os.environ["RELEASE_TREE"]
    report = {
        "schema": 2, "status": "preflight", "mainnet": True, "ibd_exit": False, "net_debug": False,
        "scope": "Actual early Mainnet 1..4096 body delivery and activation, fresh isolated loopback peers",
        "time_boundary": "Owned peer announcement through first RPC observation of exact 4096-block tip",
        "baseline_source": screen.SOURCE, "baseline_tree": screen.TREE, "baseline_release": screen.TAG,
        "candidate_source": candidate_source, "candidate_tree": candidate_tree, "candidate_release": "v31.1.2-en.10",
        "minimumchainwork_override": 0, "assumevalid": 0, "peer_count": NODE_COUNT,
        "input_manifest_sha256": screen.digest(TOOLS / "inputs.sha256"), "cases": schedule(),
    }
    persist(record, report)
    try:
        for val in (candidate_source, candidate_tree):
            screen.require(re.fullmatch(r"[0-9a-f]{40}", val), "Require pinned candidate commit and tree")
        screen.require(candidate_source != screen.SOURCE and candidate_tree != screen.TREE,
                       "Candidate cannot reuse the released baseline source tree")
        host = screen.native_host()
        screen.require(host["physical_ram_bytes"] >= (8 << 30), "Candidate default 128 needs at least 8 GiB physical RAM")
        report["host"] = host
        screen.validate_release(args.download_dir, TOOLS / "release-public.gpg", output / "signature")
        known, assets, receipt_sha = package_hashes(args.candidate_dir, candidate_source, candidate_tree, host)
        binaries = {"baseline": screen.unpack(args.download_dir, args.runtime_dir / "baseline"),
                    "candidate": screen.unpack(args.candidate_dir, args.runtime_dir / "candidate", known)}
        report["candidate_producer_receipt_sha256"] = receipt_sha
        report["programs"] = {
            "baseline": {mode: {"name": screen.ARCHIVES[mode], "archive_sha256": screen.PINS[screen.ARCHIVES[mode]][1],
                                "binary_sha256": screen.PROGRAM_SHA[mode]} for mode in screen.MODES},
            "candidate": {mode: {"name": screen.ARCHIVES[mode], "archive_sha256": assets[mode],
                                 "binary_sha256": known[mode]} for mode in screen.MODES},
        }
        resources = Resources()
        fixture, headers, blocks = get_fixture(TOOLS / "mainnet-blocks.dat.gz", TOOLS / "fixture.json")
        geometry, work = block_geometry(blocks), header_chainwork(headers)
        header_batch = make_batch("submitheader", [header.hex() for header in headers])
        report.update(status="running", fixture=fixture, fixture_geometry=geometry, chainwork=work)
        persist(record, report)
        for trial in report["cases"]:
            case_dir = output / trial["case"]
            role, mode, override = trial["release_role"], trial["interface"], trial["request_limit"]
            plan = SimpleNamespace(binary=binaries[role][mode], gui=mode == "gui", timeout=screen.DEADLINE_S,
                                   latency_ms=trial["delay_ms"])
            trial["status"] = "running"
            trial["program"] = report["programs"][role][mode]
            persist(record, report)
            try:
                result = await measure_case(plan, case_dir, fixture, headers, blocks, header_batch,
                                            trial["limit"], resources, request_limit=override, verify_restart=True)
                trial["result"] = result
                screen.check_output(result, trial, fixture, work, geometry)
                screen.check_runtime(case_dir, screen.SOURCE if role == "baseline" else candidate_source)
                check_config(case_dir, override)
                trial["status"] = "passed"
                print(f"{trial['case']} {result['seconds']:.3f} s, wire peak {result['wire_peak_pending_per_peer']}",
                      flush=True)
            except Exception as error:
                trial.update(status="failed", error=f"{type(error).__name__}: {error}")
                print(f"{trial['case']} {trial['error']}", file=sys.stderr, flush=True)
                if not screen.safe_node_end(case_dir):
                    break
            finally:
                persist(record, report)
        report["gate"] = qualify(report["cases"])
        report["status"] = report["gate"]["status"]
    except Exception as error:
        report["status"] = "preflight_or_harness_failure"
        report["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        persist(record, report)
    return 0 if report["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("download-dir", "candidate-dir", "runtime-dir", "output"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    args = parser.parse_args()
    screen.require(all(path.is_absolute() for path in vars(args).values()), "Use absolute isolated profiling paths")
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Capture fixed ABBA stock body-phase profiles on native Intel macOS."""

import argparse
from importlib.util import module_from_spec, spec_from_file_location
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

PAIRED_SHA = "4910cb3b9f5940132f9767ee9dad8aefea17133aaaca36ade4521839ae22b15c"
PROFILE_SHA = "71e7a133084ba844d3a038c8a5d3f22262d13715b01886be3ced0fb9e4e49a1f"
SEQUENCE = ("baseline", "candidate", "candidate", "baseline")


def load_paired(path):
    path = Path(path).resolve(strict=True)
    with path.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != PAIRED_SHA:
            raise ValueError("Paired launcher differs from frozen release helper")
    spec = spec_from_file_location("release_paired", path)
    paired = module_from_spec(spec)
    spec.loader.exec_module(paired)
    return paired


def profile_case(paired, spec):
    directory = Path(spec["directory"])
    receipt = {"status": "failed", "label": spec["label"], "roles": spec["roles"], "profiled": True}
    try:
        m = paired.load_module(spec["common"], "prof_common", paired.COMMON_SHA)
        normal = paired.load_module(spec["normal"], "prof_normal", paired.NORMAL_SHA)
        metrics = paired.load_module(spec["resources"], "prof_resources", spec["resources_sha256"])
        sampler = paired.load_module(spec["profile_module"], "prof_sampler", PROFILE_SHA)
        fixture = paired.absolute_file(spec["fixture"])
        info = m.fixture_metadata(paired.absolute_file(spec["fixture_info"]), fixture)
        binaries = {}
        for role, pins in spec["roles"].items():
            path = paired.absolute_file(pins["path"])
            paired.require(paired.sha(path) == pins["sha256"], f"{role} binary changed after preflight")
            m.verify_binary(path, "macos", "x86_64")
            binaries[role] = path
        evidence = directory / "node-evidence"
        case = normal.run_case(m, metrics, sampler, binaries["sender"], binaries["receiver"],
                               fixture, info, evidence, None, spec["trial_seconds"])
        receipt["node_evidence"] = str(evidence)
        receipt["cleanup"] = case["cleanup"]
        paired.require(case["status"] == "passed" and case["two_header_passes_verified"] is True,
                       f"Frozen correctness or profile gate failed: {case.get('error', 'unknown gate')}")
        receipt["runtime_sources"] = {
            role: paired.startup_source(evidence / role / "debug.log", build["source"])
            for role, build in spec["roles"].items()
        }
        profile = case["profile"]
        paired.require(profile["status"] == "passed" and profile["requested_seconds"] == 3
                       and set(profile["roles"]) == {"sender", "receiver"}
                       and all(row["status"] == "passed" for row in profile["roles"].values()),
                       "Missing qualified three-second owned-process sample")
        receipt["profile"] = profile
        paired.require(profile["owned_task_counters"]["status"] == "measured",
                       "Missing qualified task counter window for the owned daemons")
        receipt["verification"] = {
            "tip": case["tip_proof"]["hash"], "utxo": case["utxo"]["hash_serialized_3"],
            "verified_blocks": case["verifychain"]["blocks"],
            "header_bytes": case["timing"]["final_peer"]["header_bytes"],
        }
        receipt["status"] = "passed"
    except (OSError, ValueError, RuntimeError, TypeError, KeyError, ImportError, subprocess.SubprocessError) as exc:
        receipt["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        paired.write_json(directory / "profile-receipt.json", receipt)
    return int(receipt["status"] != "passed")


def launch(paired, config, directory, budget_end):
    directory.mkdir()
    request = directory / "profile-input.json"
    paired.write_json(request, {**config, "directory": str(directory)})
    cap = min(750, budget_end - time.monotonic())
    paired.require(cap > 0, "Total profile budget exceeded before launch")
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", str(request)]
    with (directory / "worker.log").open("wb") as log:
        worker = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            rc = worker.wait(timeout=cap)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            paired.stop_tree(worker)
            raise
    receipt = json.loads((directory / "profile-receipt.json").read_text(encoding="utf-8"))
    paired.require(receipt["roles"] == config["roles"] and receipt["label"] == config["label"]
                   and (rc == 0) == (receipt["status"] == "passed"), "Profile worker receipt mismatch")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "paired", "common", "normal", "resources", "profile-module",
                 "fixture", "fixture-info", "work-dir"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    parser.add_argument("--candidate-source", required=True)
    parser.add_argument("--candidate-tree", required=True)
    parser.add_argument("--trial-seconds", type=int, default=300)
    parser.add_argument("--total-seconds", type=int, default=1200)
    parser.add_argument("--fixed-candidate-sender", action="store_true")
    args = parser.parse_args()
    if sys.platform != "darwin" or not args.work_dir.is_absolute():
        raise ValueError("Use native Intel macOS and an absolute new work directory")
    paired_path = args.paired.resolve(strict=True)
    paired = load_paired(paired_path)
    work = args.work_dir.resolve()
    work.mkdir()
    deadline = time.monotonic() + args.total_seconds
    report = {"schema": 1, "status": "failed", "profiled": True, "scores_eligible": False,
              "fixed_candidate_sender": args.fixed_candidate_sender,
              "sequence": list(SEQUENCE), "profiles": []}
    try:
        paired.require(1 <= args.trial_seconds <= 300 and 1 <= args.total_seconds <= 1500,
                       "Invalid bounded profile durations")
        common = paired.load_module(args.common, "prof_common_preflight", paired.COMMON_SHA)
        verified = paired.verify_manifest(paired.absolute_file(args.manifest), args.candidate_source,
                                          args.candidate_tree, common)
        paired.require((verified["platform"], verified["arch"], verified["interface"]) ==
                       ("macos", "x86_64", "cli"), "Profile requires exact Intel Mac CLI release manifest")
        paths = ("common", "normal", "resources", "profile_module", "fixture", "fixture_info")
        cfg = {k: str(paired.absolute_file(getattr(args, k))) for k in paths}
        cfg.update(paired=str(paired_path), resources_sha256=paired.sha(Path(cfg["resources"])),
                   trial_seconds=args.trial_seconds)
        paired.require(paired.sha(Path(cfg["normal"])) == paired.NORMAL_SHA
                       and paired.sha(Path(cfg["profile_module"])) == PROFILE_SHA, "Pinned profile helper mismatch")
        report["manifest"] = verified
        report["profile_module_sha256"] = PROFILE_SHA
        for ordinal, variant in enumerate(SEQUENCE, 1):
            sender = "candidate" if args.fixed_candidate_sender else variant
            pins = paired.role_pins(verified, {"sender": sender, "receiver": variant})
            case = work / f"{ordinal:02}-{variant}"
            row = launch(paired, {**cfg, "roles": pins, "label": variant}, case, deadline)
            report["profiles"].append(row)
            paired.write_json(work / "result.json", report)
            paired.require(row["status"] == "passed", f"Unqualified {variant} sample")
        report["status"] = "passed"
    except (OSError, ValueError, RuntimeError, TypeError, KeyError, ImportError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        paired.write_json(work / "result.json", report)
    print(f"{report['status']} {work / 'result.json'}")
    return int(report["status"] != "passed")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        configuration = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
        sys.exit(profile_case(load_paired(configuration["paired"]), configuration))
    sys.exit(main())

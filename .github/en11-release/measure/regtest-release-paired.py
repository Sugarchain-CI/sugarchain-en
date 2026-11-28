#!/usr/bin/env python3
"""Pair pinned release binaries on one native host using the frozen Regtest harness."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
from statistics import median
from unittest.mock import patch
import subprocess
import sys
import time

BASELINE_SOURCE = "409ea3ee5f1cdb03790ec2adf5e191031a28737f"
BASELINE_TREE = "578110fc4d33962ed429171addc1d09cf5d5906f"
COMMON_SHA = "01b1ebcebf9a651f005f7646c8ae30000d7e7aa11bb16ef503addc213f7693bb"
NORMAL_SHA = "02fa87aaccb2ba5556bd6e1b01ac67cdf2f785d2e161cf95e14df4637f56a3a4"
MATCHED = ("baseline", "candidate", "candidate", "baseline",
           "candidate", "baseline", "baseline", "candidate")
ISOLATION = ("baseline", "candidate", "candidate", "baseline")
CPU_FIELDS = ("cpu_user_seconds", "cpu_system_seconds")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pin(value, length):
    return isinstance(value, str) and re.fullmatch(rf"[0-9a-f]{{{length}}}", value)


def sha(path):
    with path.open("rb") as data:
        return hashlib.file_digest(data, "sha256").hexdigest()


def absolute_file(value):
    path = Path(value)
    require(path.is_absolute(), f"Expected absolute path: {path}")
    path = path.resolve(strict=True)
    require(path.is_file(), f"Expected a regular input file: {path}")
    return path


def write_json(path, document):
    stage = path.with_suffix(".tmp")
    stage.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    stage.replace(path)


def load_module(path, name, expected=None):
    path = absolute_file(path)
    if expected:
        require(sha(path) == expected, f"Pinned module SHA-256 mismatch: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"Could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def executable_pins(spec, common, os_name, arch, checked_archives):
    binary = absolute_file(spec["path"])
    require(pin(spec["sha256"], 64) and sha(binary) == spec["sha256"], f"Executable pin mismatch: {binary}")
    require(pin(spec["archive_sha256"], 64), f"Invalid archive pin for {binary}")
    common.verify_binary(binary, os_name, arch)
    result = {"path": str(binary), "sha256": spec["sha256"], "archive_sha256": spec["archive_sha256"]}
    if "archive_path" in spec:
        archive = absolute_file(spec["archive_path"])
        if archive not in checked_archives:
            checked_archives[archive] = sha(archive)
        require(checked_archives[archive] == spec["archive_sha256"], f"Archive pin mismatch: {archive}")
        result["archive_path"] = str(archive)
    return result


def verify_manifest(path, candidate_source, candidate_tree, common):
    data = json.loads(path.read_text(encoding="utf-8"))
    require(type(data["schema"]) is int and data["schema"] == 1, "Unknown manifest schema")
    require(data["platform"] in ("linux", "windows", "macos"), "Unsupported platform")
    require(data["arch"] in ("x86_64", "arm64", "armhf", "ppc64", "riscv64"), "Unsupported architecture")
    require(data["interface"] in ("cli", "gui"), "Unsupported interface")
    require(pin(candidate_source, 40) and pin(candidate_tree, 40), "Invalid candidate source or tree pin")
    require(candidate_source != BASELINE_SOURCE and candidate_tree != BASELINE_TREE, "Candidate equals baseline")
    common.native_environment(data["platform"], data["arch"])
    manifest = {key: data[key] for key in ("schema", "platform", "arch", "interface")}
    archives = {}
    for name, source, tree in (("baseline", BASELINE_SOURCE, BASELINE_TREE),
                               ("candidate", candidate_source, candidate_tree)):
        row = data[name]
        require(row["source"] == source and row["tree"] == tree, f"Commit or tree mismatch for {name}")
        manifest[name] = {"source": source, "tree": tree}
        for kind, expected in (("source", source), ("tree", tree)):
            receipt_key = f"{kind}_receipt"
            if receipt_key in row:
                receipt = absolute_file(row[receipt_key])
                require(receipt.read_text(encoding="utf-8").strip() == expected, f"{name} {kind} receipt mismatch")
                manifest[name][receipt_key] = str(receipt)
        for role in ("sender", "receiver"):
            manifest[name][role] = executable_pins(row[role], common, data["platform"], data["arch"], archives)
        compatible = "same" if data["interface"] == "cli" else "different"
        same = manifest[name]["sender"]["sha256"] == manifest[name]["receiver"]["sha256"]
        require(same == (compatible == "same"), f"{name} expected {compatible} binaries for selected interface")
    for role in ("sender", "receiver"):
        require(manifest["baseline"][role]["sha256"] != manifest["candidate"][role]["sha256"],
                f"Release variants use the same {role} binary")
    return manifest


def schedule():
    for phase, sequence in (("warmup", ("baseline", "candidate")), ("matched", MATCHED),
                            ("receiver-isolation", ISOLATION)):
        for number, variant in enumerate(sequence, 1):
            yield {
                "case": f"{phase}-{number:02}-{variant}",
                "phase": phase, "number": number, "receiver": variant,
                "sender": "baseline" if phase == "receiver-isolation" else variant,
            }


def role_pins(manifest, run):
    return {role: {"release": run[role], "source": manifest[run[role]]["source"],
                   "tree": manifest[run[role]]["tree"], **manifest[run[role]][role]}
            for role in ("sender", "receiver")}


def startup_source(debug, expected):
    with debug.open(encoding="utf-8", errors="replace") as log:
        for number, line in enumerate(log, 1):
            if number > 60:
                break
            match = re.search(r"Sugarchain En version (v[^ ]+)-(?:g)?([0-9a-f]{12,40}) \(release build\)", line)
            if match:
                require(expected.startswith(match[2]), "Native release startup source does not match role pin")
                return {"source_prefix": match[2], "version": match[1], "line": number}
    raise ValueError("Missing release source version marker in native startup log")


def run_worker(spec_path):
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    result_path = Path(spec["directory"]) / "worker-result.json"
    result = {"case": spec["case"], "status": "failed", "roles": spec["roles"]}
    try:
        common = load_module(spec["common"], "paired_common", COMMON_SHA)
        normal = load_module(spec["normal"], "paired_normal", NORMAL_SHA)
        resources = load_module(spec["resources"], "paired_resources", spec["resources_sha256"])
        require(callable(getattr(resources, "sample", None)), "Resource module must provide sample(pid)")
        fixture = absolute_file(spec["fixture"])
        info = common.fixture_metadata(absolute_file(spec["fixture_info"]), fixture)
        binaries = {}
        for role, expected in spec["roles"].items():
            binaries[role] = absolute_file(expected["path"])
            require(sha(binaries[role]) == expected["sha256"], f"{role} executable changed after verification")
        gui = common.gui_arguments([]) if spec["interface"] == "gui" else None
        work = Path(spec["directory"]) / "node-evidence"
        checked_log = normal.info_log

        def role_log(node, _source, receiver=False):
            role = "receiver" if receiver else "sender"
            return checked_log(node,spec["roles"][role]["source"],receiver=receiver)

        with patch.object(normal, "info_log", role_log):
            receipt = normal.run_case(common, resources, None, binaries["sender"], binaries["receiver"],
                                      fixture, info, work, gui, spec["trial_seconds"],
                                      spec["roles"]["receiver"]["source"])
        result["node_receipt"] = (work / "result.json").relative_to(result_path.parent).as_posix()
        result["cleanup"] = receipt["cleanup"]
        require(receipt["status"] == "passed" and receipt["two_header_passes_verified"] is True,
                f"Frozen correctness gate failed: {receipt.get('error', 'unknown gate')}")
        result["runtime_sources"] = {role: startup_source(work / role / "debug.log", row["source"])
                                     for role, row in spec["roles"].items()}
        endpoint = receipt["timing"]["endpoint"]["startup_to_ibd_clear_seconds"]
        headers = receipt["timing"]["first_full_headers"]["seconds_since_launch"]
        require(0 < headers < endpoint <= spec["trial_seconds"], "Invalid frozen timer phase boundary")
        result["timing"] = {"startup_to_ibd_clear_seconds": endpoint,
                            "headers_ready_to_ibd_seconds": endpoint - headers, "startup_to_headers_seconds": headers}
        resources = receipt["process_resources"]
        result["cpu_seconds"] = {
            "receiver": sum(resources["receiver_since_birth"][name] for name in CPU_FIELDS),
            "sender": sum(resources["sender_during_receiver_delta"][name] for name in CPU_FIELDS),
        }
        result["verification"] = {
            "headers_bytes": receipt["timing"]["final_peer"]["header_bytes"],
            "presynced_headers_observed": receipt["timing"]["presync"]["presynced_headers"],
            "tip": receipt["tip_proof"]["hash"], "utxo_sha256": receipt["utxo"]["hash_serialized_3"],
            "verified_blocks": receipt["verifychain"]["blocks"],
        }
        result["status"] = "passed"
    except (OSError, ValueError, RuntimeError, TypeError, KeyError, ImportError, subprocess.SubprocessError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        write_json(result_path, result)
    return int(result["status"] != "passed")


def stop_tree(child):
    if os.name == "nt":
        if child.poll() is not None:
            return
        killer = subprocess.run(
            ["taskkill.exe", "/PID", str(child.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False,
        )
        if killer.returncode and child.poll() is None:
            child.kill()
            child.wait(timeout=10)
            raise RuntimeError("Windows task-tree cleanup could not be confirmed")
        child.wait(timeout=10)
        return

    if child.returncode is not None:
        return
    # The unreaped worker owns this session's PGID throughout the grace period.
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    else:
        time.sleep(4)
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=6)


def execute_case(config, case, directory, deadline):
    directory.mkdir()
    spec = directory / "worker-input.json"
    write_json(spec, {**config, "case": case["case"], "directory": str(directory)})
    log = directory / "worker.log"
    remaining = deadline - time.monotonic()
    require(remaining > 0, "Total benchmark deadline exceeded before worker launch")
    cap = min(config["case_seconds"], remaining)
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", str(spec)]
    started = time.monotonic()
    with log.open("wb") as output:
        if os.name == "nt":
            child = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                     creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        else:
            child = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = child.wait(timeout=cap)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            stop_tree(child)
            raise
    raw = directory / "worker-result.json"
    require(raw.is_file(), f"Worker returned {code} without a result receipt. See {log}")
    result = json.loads(raw.read_text(encoding="utf-8"))
    require(result["case"] == case["case"] and result["roles"] == config["roles"], "Worker provenance mismatch")
    require((code == 0) == (result["status"] == "passed"), "Worker exit status disagrees with result receipt")
    return {**case, **result, "worker_receipt": str(raw), "worker_elapsed_seconds": time.monotonic() - started}


def summarize_phase(cases, phase, sequence):
    rows = [case for case in cases if case["phase"] == phase]
    require(tuple(row["receiver"] for row in rows) == sequence and all(row["status"] == "passed" for row in rows),
            f"Incomplete or failed {phase} sequence")
    results = {"sequence": list(sequence), "by_receiver": {}, "paired": []}
    for variant in ("baseline", "candidate"):
        samples = [row["timing"]["startup_to_ibd_clear_seconds"] for row in rows if row["receiver"] == variant]
        require(all(type(x) in (int, float) and x > 0 for x in samples), "Invalid measurement")
        results["by_receiver"][variant] = {"all_seconds": samples, "median_seconds": median(samples),
                                          "min_seconds": min(samples), "max_seconds": max(samples)}
    for start in range(0, len(rows), 2):
        pair = rows[start:start + 2]
        require({x["receiver"] for x in pair} == {"baseline", "candidate"}, "Invalid matched order")
        keyed = {case["receiver"]: case["timing"]["startup_to_ibd_clear_seconds"] for case in pair}
        results["paired"].append({
            "case_order": [case["case"] for case in pair], "baseline_seconds": keyed["baseline"],
            "candidate_seconds": keyed["candidate"], "candidate_minus_baseline_seconds": keyed["candidate"] - keyed["baseline"],
            "candidate_percent_of_baseline": 100 * keyed["candidate"] / keyed["baseline"],
        })
    return results


def performance_gate(matched, isolation):
    baseline = matched["by_receiver"]["baseline"]["median_seconds"]
    candidate = matched["by_receiver"]["candidate"]["median_seconds"]
    wins = sum(row["candidate_minus_baseline_seconds"] < 0 for row in matched["paired"])
    required_gain = max(.1,.03*baseline)
    matched_pass = baseline-candidate >= required_gain and wins >= 3
    iso_base = isolation["by_receiver"]["baseline"]["median_seconds"]
    iso_candidate = isolation["by_receiver"]["candidate"]["median_seconds"]
    iso_wins = sum(row["candidate_minus_baseline_seconds"] < 0 for row in isolation["paired"])
    iso_pass = iso_candidate < iso_base and iso_wins >= 1
    return {"passed":matched_pass and iso_pass,
            "matched":{"passed":matched_pass,"baseline_seconds":baseline,"candidate_seconds":candidate,
                       "faster_pairs":wins,"minimum_faster_pairs":3,"minimum_gain_seconds":required_gain},
            "receiver_isolation":{"passed":iso_pass,"baseline_seconds":iso_base,"candidate_seconds":iso_candidate,
                                  "fixed_sender":"baseline","faster_pairs":iso_wins,"minimum_faster_pairs":1}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for item in ("manifest", "common", "normal", "resources", "fixture", "fixture-info", "work-dir"):
        parser.add_argument(f"--{item}", type=Path, required=True)
    parser.add_argument("--candidate-source", required=True)
    parser.add_argument("--candidate-tree", required=True)
    parser.add_argument("--trial-seconds", type=int, default=300)
    parser.add_argument("--case-seconds", type=int, default=750)
    parser.add_argument("--total-seconds", type=int, default=2100)
    args = parser.parse_args()
    require(args.work_dir.is_absolute(), "Work directory must be absolute")
    directory = args.work_dir.resolve()
    directory.mkdir()
    deadline = time.monotonic() + args.total_seconds
    plan = list(schedule())
    result = {"schema": 1, "status": "failed", "cases": [], "planned_cases":plan,
              "common_sha256": COMMON_SHA, "normal_sha256": NORMAL_SHA}
    try:
        require(1 <= args.trial_seconds <= 300 and 1 <= args.case_seconds <= 750 and 1 <= args.total_seconds <= 2100,
                "Invalid bounded timing limits")
        common_path = absolute_file(args.common)
        common = load_module(common_path, "paired_common_preflight", COMMON_SHA)
        normal = absolute_file(args.normal)
        require(sha(normal) == NORMAL_SHA, "Frozen normal harness SHA-256 mismatch")
        resources = absolute_file(args.resources)
        manifest_path = absolute_file(args.manifest)
        manifest = verify_manifest(manifest_path, args.candidate_source, args.candidate_tree, common)
        fixture = absolute_file(args.fixture)
        fixture_info = absolute_file(args.fixture_info)
        info = common.fixture_metadata(fixture_info, fixture)
        resource_sha = sha(resources)
        config = {"common": str(common_path), "normal": str(normal), "resources": str(resources),
                  "resources_sha256": resource_sha,
                  "fixture": str(fixture), "fixture_info": str(fixture_info), "interface": manifest["interface"],
                  "trial_seconds": args.trial_seconds, "case_seconds": args.case_seconds}
        result.update(manifest=manifest, manifest_sha256=sha(manifest_path), resources_sha256=resource_sha,
                      fixture=info, emulation=False, host={"platform": platform.platform(),
                      "machine": platform.machine(), "logical_cpus": os.cpu_count()},
                      limits_seconds={"sync": args.trial_seconds, "case": args.case_seconds, "total": args.total_seconds})
        for case in plan:
            pins = role_pins(manifest, case)
            receipt = execute_case({**config, "roles": pins}, case, directory / case["case"], deadline)
            result["cases"].append(receipt)
            write_json(directory / "result.json", result)
            cleanup = receipt.get("cleanup",{})
            require(set(cleanup) == {"sender","receiver"} and
                    all(row.get("pid") is None or row.get("reaped") is True for row in cleanup.values()),
                    f"Owned process cleanup remains unconfirmed at {case['case']}")
        require(all(case["status"] == "passed" for case in result["cases"]), "One or more required cases failed")
        result["release_matched"] = summarize_phase(result["cases"], "matched", MATCHED)
        result["receiver_isolation"] = summarize_phase(result["cases"], "receiver-isolation", ISOLATION)
        result["performance_gate"] = performance_gate(result["release_matched"],result["receiver_isolation"])
        result["status"] = "passed" if result["performance_gate"]["passed"] else "performance_failed"
    except (OSError, ValueError, RuntimeError, TypeError, KeyError, ImportError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        write_json(directory / "result.json", result)
    print(f"{result['status']} {directory / 'result.json'}")
    return int(result["status"] != "passed")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        sys.exit(run_worker(Path(sys.argv[2])))
    sys.exit(main())

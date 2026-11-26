#!/usr/bin/env python3
"""Run the fixed native UCRT cache comparison on one host."""

import argparse
import gzip
import json
from pathlib import Path
import shutil
import tempfile
import time
from types import SimpleNamespace

from qualify_mature_checkpoint_candidate import CACHE_MARKER, CacheRuntime, guard, persist, run

FIXTURE_SHA = "234d86232dc76cc86045b0f6cba2988a140562a112ecbbb454e82fa3f20a30f3"
ORDER = ("default", "zero", "bounded32", "bounded32", "zero", "default")
SEQUENCE_SECONDS = 45 * 60
ARM_SECONDS = 12 * 60
LOG_LIMIT = 64 << 20
RUNTIMES = {
    "default": CacheRuntime(
        "9c502574b652804905d2533d51742ca91f694532", "f44aa1b47f9701996046bbb396106f1d5c365e66",
        "04ccedd40133b40011ca1a4be688fbe8eb7553b4f5846f488a087b11581fedbb", None, "default",
    ),
    "zero": CacheRuntime(
        "85383ffc382a7984c42467f6fa3c545db7ee392d", "23893fa2c7126699f9c33bf35716159656da9447",
        "41e7e8a5a9513fc6821aae7780faee148f2c310c611d947ccba3b9ccf25c4e28", CACHE_MARKER, "zero",
    ),
    "bounded32": CacheRuntime(
        "1ee8a457660ba1917e9ff7074fcbac900eacd242", "1c2425aa5dd7245a6317d887d83d4ea84c6f4c92",
        None, "LevelDB bounded block index table cache enabled on Windows x64 (table_cache_target=32).", "bounded32",
    ),
}


def retain_logs(profile, output):
    records = {}
    for name in ("debug-restart.log", "console-restart.log"):
        source = profile / name
        if not source.is_file():
            continue
        size = source.stat().st_size
        if size > LOG_LIMIT:
            records[name] = {"status": "exceeds_artifact_limit", "bytes": size}
            continue
        with source.open("rb") as original, gzip.open(output / f"{name}.gz", "wb") as destination:
            shutil.copyfileobj(original, destination, length=1 << 20)
        records[name] = {"status": "retained_losslessly", "bytes": size}
    if output.is_dir():
        persist(output / "logs.json", records)


def execute(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    scratch = args.scratch.resolve(strict=True)
    guard(scratch.is_dir(), "scratch_not_directory", "An owned runner scratch directory is required")
    paths = {
        "default": args.default_runtime, "zero": args.zero_runtime, "bounded32": args.bounded32_runtime,
    }
    report_path = output / "sequence.json"
    report = {
        "status": "in_progress", "order": list(ORDER), "arms": [], "target": "windows-ucrt",
        "fixture_manifest_sha256": FIXTURE_SHA, "sequence_seconds_limit": SEQUENCE_SECONDS, "arm_seconds_limit": ARM_SECONDS,
    }
    persist(report_path, report)
    end = time.monotonic() + SEQUENCE_SECONDS
    try:
        for position, choice in enumerate(ORDER, 1):
            now = time.monotonic()
            arm_seconds = min(ARM_SECONDS, end - now)
            guard(arm_seconds > 0, "sequence_timeout", "The scheduled comparison reached its total deadline")
            arm_output = output / f"{position:02d}-{choice}"
            entry = {"position": position, "choice": choice, "status": "running", "result": f"{arm_output.name}/result.json"}
            report["arms"].append(entry)
            persist(report_path, report)
            with tempfile.TemporaryDirectory(prefix="en8-win-index-cache-", dir=scratch) as owned:
                profile = Path(owned) / "node"
                inputs = SimpleNamespace(
                    target="windows-ucrt", runtime=paths[choice], fixture=args.fixture,
                    output=arm_output, manifest_name="manifest.json", fixture_manifest_sha256=FIXTURE_SHA,
                    deadline_epoch=time.time() + arm_seconds,
                )
                try:
                    run(inputs, runtime=RUNTIMES[choice], profile=profile)
                finally:
                    retain_logs(profile, arm_output)
                arm = json.loads((arm_output / "result.json").read_text(encoding="utf-8"))
                memory = json.loads((arm_output / "windows-startup-memory.json").read_text(encoding="utf-8"))
                guard(arm["status"] == "verified" and isinstance(arm.get("historical_scan"), dict),
                      "arm_unverified", "Mature checkpoint or fixed historical scan evidence unavailable")
                guard(memory["status"] == "verified_metadata" and memory["observer_stopped_before_core_timing"],
                      "memory_evidence_unavailable", "Required startup memory evidence is unavailable")
                entry.update(
                    startup_seconds=arm["startup_seconds"], historical_scan=arm["historical_scan"],
                    binary_sha256=arm["binary"]["binary_sha256"], memory=arm["capacity"], passes=arm["passes"],
                )
            entry["status"] = "verified"
            persist(report_path, report)
        report["status"] = "verified"
    except Exception as error:
        for entry in report["arms"]:
            if entry["status"] == "running":
                entry["status"] = "failed"
        report.update(status="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        persist(report_path, report)
    print(f"Completed the six scheduled UCRT cache arms. Evidence at {report_path}.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("default-runtime", "zero-runtime", "bounded32-runtime", "fixture", "scratch", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    execute(parser.parse_args())


if __name__ == "__main__":
    main()

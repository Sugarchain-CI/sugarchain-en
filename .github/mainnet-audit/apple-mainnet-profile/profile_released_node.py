#!/usr/bin/env python3
"""Capture one unscored stack sample from a released Apple Silicon node."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
from types import SimpleNamespace

from mainnet_probe import check_host
from presync_sweep import DarwinUsage, SCREEN_HEADERS, prepare_wire, read_fixture, timed_presync


def capture(options):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("Native Apple Silicon is required")
    check_host()
    usage = DarwinUsage()
    with options.binary.open("rb") as stream:
        binary_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
    if binary_sha256 != options.binary_sha256:
        raise ValueError("The release executable does not match its pinned digest")
    headers = read_fixture(options.headers, options.headers_sha256, options.fixture_tip)
    locators, frames = prepare_wire(headers[:SCREEN_HEADERS])
    args = SimpleNamespace(binary=options.binary.resolve(), gui=False)
    options.results.mkdir()
    summary = {"scored": False, "binary_sha256": binary_sha256, "headers_sha256": options.headers_sha256,
               "profile_seconds": 10, "sampling_interval_ms": 5, "phase": "Mainnet localhost PRESYNC"}
    sampler = None

    def start_sampler(pid):
        nonlocal sampler
        with (options.results / "sample-command.log").open("wb") as log:
            sampler = subprocess.Popen(["/usr/bin/sample", str(pid), "10", "5", "-file",
                                        str(options.results / "node-stacks.txt")],
                                       stdout=log, stderr=subprocess.STDOUT)

    try:
        summary["presync"] = timed_presync(args, options.datadir, locators, frames, "default", usage, start_sampler)
    finally:
        if sampler is not None:
            try:
                summary["sample_exit_code"] = sampler.wait(timeout=5)
            except subprocess.TimeoutExpired:
                sampler.terminate()
                summary["sample_exit_code"] = sampler.wait(timeout=5)
                summary["sample_timeout"] = True
        (options.results / "node-profile.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if summary.get("sample_exit_code") != 0 or not (options.results / "node-stacks.txt").is_file():
        raise RuntimeError("No stack sample was available. Inspect the archived sample command diagnostics.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--headers", type=Path, required=True)
    parser.add_argument("--headers-sha256", required=True)
    parser.add_argument("--fixture-tip", required=True)
    parser.add_argument("--datadir", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    capture(parser.parse_args())

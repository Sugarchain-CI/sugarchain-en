#!/usr/bin/env python3
"""Prepare untampered En.8 packages and run the shared native Regtest benchmark."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


TAG = "v31.1.2-en.8"
SOURCE = "ba6ba77698f9a0759063604c4f87ce3eab93c107"
TREE = "585f08d47bc953b7863d2fc3ba51f3ea762bc36f"
MANIFEST_SHA256 = "687595190828e35453b775c5fadf48a3be5cbf334f91c26e45b76f79af95dbe2"
PACKAGE_SHA256 = {
    "arm64": {
        "cli": "74aeb08fc55b3f4cea727ad8f2935ec2dc52845cedebfd6fdfa39ce77b16925a",
        "gui": "e62c570e39044408cbf0b75ffdc0549c85b3099982513a306f1164d66bd0965d",
    },
    "x86_64": {
        "cli": "4be59ff2c2f29a646c6012282633dd1089c2e3bfee946656874d87f284cf1f08",
        "gui": "c62d108f1a726db8935eeb9c898b6cf1a4b3df111ea250fc4d2f65fbf19e4bb3",
    },
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256(path):
    require(path.is_file() and not path.is_symlink(), f"Expected a regular file: {path}")
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def names(arch):
    prefix = f"sugarchain-en-31.1.2-macos-{arch}"
    return {"cli": f"{prefix}-cli.tar.gz", "gui": f"{prefix}.zip"}


def confirm_host(arch):
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
            "Use a fresh standard GitHub-hosted macOS runner")
    require(platform.system() == "Darwin" and platform.machine() == arch, f"Expected native macOS {arch}")
    probe = subprocess.run(["/usr/sbin/sysctl", "-n", "sysctl.proc_translated"],
                           text=True, capture_output=True, timeout=5)
    require(probe.returncode != 0 or probe.stdout.strip() == "0", "Rosetta translation is active")
    real_home = Path.home()
    preferences = real_home / "Library" / "Preferences"
    support = real_home / "Library" / "Application Support"
    require(not any("sugarchain" in path.name.casefold() for path in preferences.glob("*.plist"))
            and not any("sugarchain" in path.name.casefold() for path in support.glob("*")),
            "The runner already contains a Sugarchain profile")
    return {
        "platform": platform.platform(),
        "architecture": arch,
        "translated": False,
        "cpu": subprocess.check_output(["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"], text=True, timeout=5).strip(),
        "logical_cpus": os.cpu_count(),
        "workflow_sha": os.environ["GITHUB_SHA"],
        "run_id": os.environ["GITHUB_RUN_ID"],
    }


def verify_archives(downloads, arch):
    manifest = downloads / "SHA256SUMS"
    require(sha256(manifest) == MANIFEST_SHA256, "En.8 checksum manifest differs from the signed release")
    declarations = dict(line.split("  ", 1)[::-1] for line in manifest.read_text(encoding="ascii").splitlines())
    archives = {}
    for mode, filename in names(arch).items():
        path = downloads / filename
        require(declarations[filename] == PACKAGE_SHA256[arch][mode] == sha256(path),
                f"The downloaded package differs from En.8: {filename}")
        archives[mode] = path
    return archives


def unpack(archives, runtime, arch):
    cli_stage = runtime / "cli"
    gui_stage = runtime / "gui"
    cli_stage.mkdir()
    gui_stage.mkdir()
    subprocess.run(["/usr/bin/tar", "-xzf", str(archives["cli"]), "-C", str(cli_stage)], check=True, timeout=60)
    subprocess.run(["/usr/bin/ditto", "-x", "-k", str(archives["gui"]), str(gui_stage)], check=True, timeout=60)
    app = gui_stage / "Sugarchain-Qt.app"
    binaries = {
        "cli": cli_stage / names(arch)["cli"].removesuffix(".tar.gz") / "bin" / "sugarchaind",
        "gui": app / "Contents" / "MacOS" / "Sugarchain-Qt",
    }
    for executable in binaries.values():
        require(executable.is_file() and not executable.is_symlink() and os.access(executable, os.X_OK),
                f"Missing signed executable: {executable}")
        actual = subprocess.check_output(["/usr/bin/lipo", "-archs", str(executable)], text=True, timeout=10).strip()
        require(actual == arch, f"Expected a thin Mach-O {arch}: {executable}")
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(binaries["cli"])], check=True, timeout=20)
    subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], check=True, timeout=20)
    return binaries


def benchmark(args):
    host = confirm_host(args.arch)
    output = args.output.resolve()
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(output.is_relative_to(runner_temp) and output != runner_temp, "Use a fresh output under RUNNER_TEMP")
    output.mkdir()
    archives = verify_archives(args.downloads.resolve(strict=True), args.arch)
    runtime = output.with_name(output.name + "-runtime")
    runtime.mkdir()
    binaries = unpack(archives, runtime, args.arch)
    receipt = output / "adapter-result.json"
    report = {
        "schema": 1,
        "status": "in_progress",
        "release": TAG,
        "source": SOURCE,
        "tree": TREE,
        "host": host,
        "signed_release_manifest_sha256": MANIFEST_SHA256,
        "fixture_info_sha256": sha256(args.fixture_info),
        "modes": {},
    }
    for mode, executable in binaries.items():
        report["modes"][mode] = {
            "asset": archives[mode].name,
            "asset_sha256": PACKAGE_SHA256[args.arch][mode],
            "executable_sha256": sha256(executable),
            "status": "unstarted",
        }

    def save():
        receipt.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    save()
    for mode, executable in binaries.items():
        row = report["modes"][mode]
        home = runtime / f"{mode}-home"
        home.mkdir(mode=0o700)
        environment = os.environ.copy()
        for variable in ("QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH"):
            environment.pop(variable, None)
        environment.update(HOME=str(home), CFFIXED_USER_HOME=str(home), QT_QPA_PLATFORM="cocoa")
        command = [
            sys.executable, "-B", str(args.harness.resolve(strict=True)),
            "--sender", str(binaries["cli"]), "--receiver", str(executable),
            "--fixture", str(args.fixture.resolve(strict=True)),
            "--fixture-info", str(args.fixture_info.resolve(strict=True)),
            "--work-dir", str(output / mode), "--platform", "macos", "--arch", args.arch,
            "--archive-sha256", row["asset_sha256"], "--receiver-sha256", row["executable_sha256"],
            "--trial-seconds", "300",
        ]
        if mode == "gui":
            command.extend(("--gui", "--gui-arg=-choosedatadir=0"))
        row["status"] = "in_progress"
        save()
        with (output / f"{mode}-driver.log").open("wb") as log:
            finished = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT)
        result = output / mode / "result.json"
        row["exit_code"] = finished.returncode
        if result.is_file():
            row["result_sha256"] = sha256(result)
        row["status"] = "completed" if finished.returncode == 0 and result.is_file() else "incomplete"
        save()
    report["status"] = ("completed" if all(row["status"] == "completed" for row in report["modes"].values())
                        else "incomplete")
    save()
    print(f"macOS {args.arch} benchmark {report['status']}: {receipt}", flush=True)
    return report["status"] != "completed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=PACKAGE_SHA256, required=True)
    for option in ("downloads", "harness", "fixture", "fixture-info", "output"):
        parser.add_argument(f"--{option}", type=Path, required=True)
    return benchmark(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())

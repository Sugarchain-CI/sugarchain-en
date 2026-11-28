#!/usr/bin/env python3
"""Authenticate the public En.10 Mac archives and run the common native benchmark."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

TOOLS = Path(__file__).resolve().parent
PINS_SHA = "ee6b18fe6e1c92950c514a078aaec53a847ace956247faef3a10d6aebae9bc11"
RUNNERS = {"arm64": ("macos-15", "ARM64"), "x86_64": ("macos-15-intel", "X64")}
MODES = ("cli", "gui")


def require(condition, description):
    if not condition:
        raise RuntimeError(description)


def digest(path):
    require(path.is_file() and not path.is_symlink(), f"Expected regular input {path.name}")
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def save(path, receipt):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def pins():
    source = TOOLS / "asset-pins.json"
    require(digest(source) == PINS_SHA, "Trusted per-asset provenance pins changed")
    return json.loads(source.read_bytes())


def host_metadata(arch):
    label, target = RUNNERS[arch]
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("RUNNER_OS") == "macOS"
            and os.environ.get("RUNNER_ARCH") == target,
            "Expected standard GitHub-hosted Mac runner matching the release architecture")
    require(platform.system() == "Darwin" and platform.machine() == arch, "Wrong native process architecture")
    translated = subprocess.run(["/usr/sbin/sysctl", "-n", "sysctl.proc_translated"],
                                capture_output=True, text=True, timeout=5)
    require(translated.returncode != 0 or translated.stdout.strip() == "0", "Rosetta translation is active")
    actual_machine = subprocess.check_output(["/usr/bin/uname", "-m"], text=True, timeout=5).strip()
    require(actual_machine == arch, "Kernel and Python architectures differ")
    sysctl = lambda variable: subprocess.check_output(["/usr/sbin/sysctl", "-n", variable],
                                                       text=True, timeout=5).strip()
    return {"runner": label, "arch": arch, "platform": platform.platform(), "translated": False,
            "cpu": sysctl("machdep.cpu.brand_string"), "physical_ram_bytes": int(sysctl("hw.memsize")),
            "logical_cpus": int(sysctl("hw.logicalcpu")), "runner_image": os.environ.get("ImageVersion"),
            "workflow_sha": os.environ["GITHUB_SHA"], "run_id": os.environ["GITHUB_RUN_ID"],
            "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"]}


def required_assets(config, arch):
    return (*config["manifests"].values(), *(config["packages"][arch][mode] for mode in MODES))


def fetch_release(config, arch, directory):
    directory.mkdir(mode=0o700)
    for row in required_assets(config, arch):
        path = directory / row["name"]
        expected = f'https://github.com/{config["repository"]}/releases/download/{config["tag"]}/{row["name"]}'
        require(row["url"] == expected, f"Unexpected release asset origin: {row['name']}")
        subprocess.run(["/usr/bin/curl", "--fail", "--silent", "--show-error", "--location", "--retry", "2",
                        "--max-time", "120", "--max-filesize", str(row["bytes"]), "--proto", "=https",
                        "--proto-redir", "=https", "--output", str(path), row["url"]],
                       check=True, timeout=400)


def authenticate(config, arch, downloads, evidence):
    for pin in required_assets(config, arch):
        path = downloads / pin["name"]
        require(digest(path) == pin["sha256"] and path.stat().st_size == pin["bytes"],
                f"Published release digest or size differs: {pin['name']}")
    evidence.mkdir(mode=0o700)
    keyring = TOOLS / "release-public.gpg"
    require(digest(keyring) == config["keyring_sha256"], "Wrong trusted release keyring")
    gpgv = shutil.which("gpgv")
    require(gpgv is not None, "Expected GnuPG gpgv for the public release signature")
    verification = subprocess.run([gpgv, "--homedir", str(evidence), "--keyring", str(keyring), "--status-fd=2",
                                   "--output", "-", str(downloads / "SHA256SUMS.asc")],
                                  capture_output=True, timeout=30)
    (evidence / "gpgv.log").write_bytes(verification.stderr)
    verification.check_returncode()
    signers = re.findall(rb"^\[GNUPG:\] VALIDSIG ([A-F0-9]+) ", verification.stderr, flags=re.MULTILINE)
    require(signers == [config["signer_fingerprint"].encode("ascii")], "Wrong OpenPGP release signer")
    manifest = (downloads / "SHA256SUMS").read_bytes()
    require(manifest.endswith(b"\n") and not manifest.endswith(b"\n\n"), "Wrong checksum manifest terminator")
    require(verification.stdout == manifest or verification.stdout + b"\n" == manifest,
            "Signature check did not recover the pinned checksum manifest")
    rows = {}
    for line in manifest.decode("ascii").splitlines():
        parsed = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        require(parsed is not None and parsed[2] not in rows, "Malformed or repeated checksum inventory row")
        rows[parsed[2]] = parsed[1]
    require(len(rows) == config["signed_payload_count"] == 17, "Unexpected signed payload count")
    for pin in config["packages"][arch].values():
        require(rows.get(pin["name"]) == pin["sha256"], f"Wrong signed hash for {pin['name']}")
    result = {
        "signer": config["signer_fingerprint"], "tag": config["tag"],
        "sha256sums_sha256": config["manifests"]["SHA256SUMS"]["sha256"],
        "clearsign_sha256": config["manifests"]["SHA256SUMS.asc"]["sha256"],
        "cleartext": "exact" if verification.stdout == manifest else "final LF omitted",
    }
    save(evidence / "verification.json", result)
    return result


def unpack(downloads, runtime, arch, packages):
    cli, gui = (runtime / mode for mode in MODES)
    cli.mkdir()
    gui.mkdir()
    subprocess.run(["/usr/bin/tar", "-xzf", str(downloads / packages["cli"]["name"]), "-C", str(cli)],
                   check=True, timeout=90)
    subprocess.run(["/usr/bin/ditto", "-x", "-k", str(downloads / packages["gui"]["name"]), str(gui)],
                   check=True, timeout=90)
    binaries = {"cli": cli / packages["cli"]["member"], "gui": gui / packages["gui"]["member"]}
    app = gui / "Sugarchain-Qt.app"
    for mode, executable in binaries.items():
        require(digest(executable) == packages[mode]["executable_sha256"] and os.access(executable, os.X_OK),
                f"The extracted native {mode} executable failed identity validation")
        slices = subprocess.check_output(["/usr/bin/lipo", "-archs", str(executable)], text=True, timeout=10).strip()
        require(slices == arch, f"Expected one {arch} Mach-O slice for {mode}, found {slices}")
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(binaries["cli"])], check=True, timeout=20)
    subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], check=True, timeout=20)
    for target in (binaries["cli"], app):
        code = subprocess.run(["/usr/bin/codesign", "-dvv", str(target)], capture_output=True, text=True, timeout=20,
                              check=True)
        require("Signature=adhoc" in code.stderr, f"Expected the ad hoc release signature on {target.name}")
    return binaries


def isolated_env(path):
    path.mkdir(mode=0o700)
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("DYLD_", "QT_", "XDG_"))}
    environment.update(HOME=str(path), CFFIXED_USER_HOME=str(path), QT_QPA_PLATFORM="cocoa")
    return environment


def benchmark(args):
    output = args.output
    runtime = args.runtime
    require(output.is_absolute() and runtime.is_absolute(), "Use absolute test output and runtime roots")
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(output.resolve().parent == runner and runtime.resolve().parent == runner and output != runtime,
            "Use separate fresh directories directly under RUNNER_TEMP")
    output.mkdir(mode=0o700)
    runtime.mkdir(mode=0o700)
    path = output / "adapter-result.json"
    report = {"schema": 1, "status": "incomplete", "emulation": False, "architecture": args.arch,
              "modes": {mode: {"status": "not_started"} for mode in MODES}}
    save(path, report)
    try:
        config = pins()
        packages = config["packages"][args.arch]
        report["host"] = host_metadata(args.arch)
        report.update({key: config[key] for key in ("repository", "tag", "release_source", "release_tree",
                                                    "asset_provenance_sha256")})
        report["asset_pins_sha256"] = PINS_SHA
        report["fixture_info_sha256"] = digest(args.fixture_info)
        report["common_harness_sha256"] = digest(args.common_dir / "regtest-normal.py")
        downloads = runtime / "downloads"
        fetch_release(config, args.arch, downloads)
        report["signature"] = authenticate(config, args.arch, downloads, output / "signature")
        binaries = unpack(downloads, runtime, args.arch, packages)
        for mode in MODES:
            row = report["modes"][mode]
            row["package"] = packages[mode]
            row["status"] = "running"
            save(path, report)
            receipt_dir = output / mode
            env = isolated_env(runtime / f"{mode}-home")
            command = [
                sys.executable, "-B", str(args.common_dir / "regtest-normal.py"),
                "--common", str(args.common_dir / "en8-regtest-presync.py"),
                "--resources", str(args.common_dir / "resource_metrics.py"),
                "--sender", str(binaries["cli"]), "--receiver", str(binaries[mode]),
                "--fixture", str(args.fixture), "--fixture-info", str(args.fixture_info),
                "--work-dir", str(receipt_dir), "--platform", "macos", "--arch", args.arch,
                "--archive-sha256", packages[mode]["sha256"],
                "--sender-sha256", packages["cli"]["executable_sha256"],
                "--receiver-sha256", packages[mode]["executable_sha256"],
                "--runtime-source", packages[mode]["source"], "--runtime-tree", packages[mode]["tree"],
                "--trials", "3", "--trial-seconds", "300",
            ]
            if mode == "gui":
                command += ["--gui", "--gui-arg=-choosedatadir=0"]
            with (output / f"{mode}-driver.log").open("wb") as log:
                finished = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
            row["exit_code"] = finished.returncode
            result = receipt_dir / "result.json"
            if result.is_file():
                row["result_sha256"] = digest(result)
            row["status"] = "completed" if result.is_file() and finished.returncode == 0 else "incomplete"
            save(path, report)
        report["status"] = "completed" if all(x["status"] == "completed" for x in report["modes"].values()) else "incomplete"
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        save(path, report)
    return 0 if report["status"] == "completed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", required=True, choices=RUNNERS)
    for item in ("common-dir", "fixture", "fixture-info", "output", "runtime"):
        parser.add_argument(f"--{item}", required=True, type=Path)
    args = parser.parse_args()
    for name in ("common_dir", "fixture", "fixture_info"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    raise SystemExit(benchmark(args))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Run signed Sugarchain En.10 distributions on native x86-64 Windows."""

import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import math
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
from statistics import median
import subprocess
import sys
import time
from urllib.request import urlopen
import zipfile

TAG = "v31.1.2-en.10"
SOURCE = "b68f5bf6844c52501f77a674d8cd8cfff2fabeb9"
TREE = "a77026814986c5ab2950c4674f390f1a6b3a582a"
RUNTIME_SOURCE = "409ea3ee5f1cdb03790ec2adf5e191031a28737f"
RUNTIME_TREE = "578110fc4d33962ed429171addc1d09cf5d5906f"
REPO = "decryp2kanon/sugarchain-en"
ROOT = f"https://github.com/{REPO}/releases/download/{TAG}"
KEY = "CF8F465D97437DA3BB25534D92F37F683E41E891"
KEY_SHA = "03c4bb8a655e61c932977d4d3ff778784e7b559a589eeb1c799a1f306d856729"
SIGNED_FILES = {"SHA256SUMS": "e900138702a377c40e7234f7e33af8ddf09de7ab7f5c8c1cc29f422cb3e9e959",
                "SHA256SUMS.asc": "e86f6c06da8b4543c35c503174ffcfaaeed31eb44641f83f6d131bbd1fd2bc6c"}
PACKAGES = {
    "ucrt": {"portable": "2e6338e0504a1a11589d0d8d6b3db6b92a3b8b2577dba3a1cdc4c6c0f24fa4b3",
             "installer": "c79b315f5c73d73c01cc7c5b863dfeb9d242504a5267c30fa9d2076e8b106c85"},
    "msvcrt": {"portable": "18cba038d19a89e92ab699b03253c985d6fd912bc66cdc5281ef7253a299b040",
               "installer": "bfbe0a84ba24d1324819726e829ffad8c484658f2ba805f1c7926cd5b33adcbc"},
}
PROGRAMS = {"sugarchain.exe", "sugarchain-qt.exe", *(f"daemon/{name}.exe" for name in
    ("sugarchaind", "sugarchain-cli", "sugarchain-tx", "sugarchain-util", "sugarchain-wallet"))}
LIMIT = 128 << 20


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(path):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= LIMIT,
            f"Expected bounded regular file: {path}")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")


def executable(name, *defaults):
    for option in (shutil.which(name), *defaults):
        if option and Path(option).is_file():
            return str(option)
    raise ValueError(f"Required tool not available: {name}")


def download(name, directory, expected, local=None):
    if local:
        path = local / name
    else:
        path = directory / name
        deadline = time.monotonic() + 300
        size = 0
        with urlopen(f"{ROOT}/{name}", timeout=30) as incoming, path.open("xb") as output:
            while chunk := incoming.read(1 << 20):
                size += len(chunk)
                require(size <= LIMIT and time.monotonic() <= deadline, f"Release download exceeds bounds: {name}")
                output.write(chunk)
    require(digest(path) == expected, f"Pinned release asset hash differs: {name}")
    return path


def run_signature_command(command, work, prefix):
    try:
        result = subprocess.run(command, cwd=work, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        (work / f"{prefix}-stdout.log").write_bytes(getattr(error, "stdout", None) or b"")
        diagnostic = getattr(error, "stderr", None) or b""
        (work / f"{prefix}-stderr.log").write_bytes(diagnostic + f"\n{error}\n".encode("utf-8"))
        raise
    (work / f"{prefix}-stdout.log").write_bytes(result.stdout)
    (work / f"{prefix}-stderr.log").write_bytes(result.stderr)
    result.check_returncode()
    return result


def verify_signature(manifest, signed, keyring, directory):
    require(digest(keyring) == KEY_SHA, "Pinned release keyring hash differs")
    git = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "usr" / "bin"
    home = directory / "public-signature"
    home.mkdir(mode=0o700)
    shutil.copyfile(keyring, home / "release-public.gpg")
    shutil.copyfile(signed, home / "SHA256SUMS.asc")
    gpgv = shutil.which("gpgv") or (str(git / "gpgv.exe") if (git / "gpgv.exe").is_file() else None)
    if gpgv:
        command = [gpgv, "--homedir", ".", "--keyring", "./release-public.gpg", "--status-fd=2",
                   "--output", "-", "./SHA256SUMS.asc"]
    else:
        gpg = executable("gpg", git / "gpg.exe")
        common = [gpg, "--no-options", "--homedir", ".", "--batch"]
        run_signature_command([*common, "--import", "./release-public.gpg"], home, "import")
        command = [*common, "--status-fd=2", "--output", "-", "--decrypt", "./SHA256SUMS.asc"]
    verified = run_signature_command(command, home, "verify")
    signers = re.findall(rb"(?m)^\[GNUPG:\] VALIDSIG ([A-F0-9]{40}) ", verified.stderr)
    require(signers == [KEY.encode("ascii")], "The clearsigned release signer did not match")
    expected = manifest.read_bytes()
    require(expected.endswith(b"\n") and not expected.endswith(b"\n\n"),
            "The pinned checksum manifest must end in exactly one LF")
    comparison = "exact"
    if verified.stdout != expected:
        # The Windows Git runner's gpgv omitted only the final LF on the valid clearsigned output.
        require(sys.platform == "win32" and verified.stdout + b"\n" == expected,
                "The clearsigned release manifest did not match")
        comparison = "missing_final_lf"
    write_json(directory / "release-signature-verification.json", {"signer_fingerprint": KEY,
               "recovered_plaintext_comparison": comparison, "recovered_plaintext_bytes": len(verified.stdout),
               "pinned_manifest_sha256": SIGNED_FILES["SHA256SUMS"]})
    (directory / "release-signature-status.log").write_bytes(verified.stderr)
    hashes = {}
    for line in manifest.read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        require(match and match[2] not in hashes, "Invalid or duplicate release manifest entry")
        hashes[match[2]] = match[1]
    require(len(hashes) == 17, "Unexpected signed payload count")
    return hashes


def native_host():
    from ctypes import wintypes
    require(sys.platform == "win32", "A native AMD64 Windows runner is required")
    require(platform.machine().lower() in {"amd64", "x86_64"}, "Windows machine is not AMD64")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.IsWow64Process2.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_ushort), ctypes.POINTER(ctypes.c_ushort)]
    kernel.IsWow64Process2.restype = wintypes.BOOL
    process, hardware = ctypes.c_ushort(), ctypes.c_ushort()
    if not kernel.IsWow64Process2(kernel.GetCurrentProcess(), ctypes.byref(process), ctypes.byref(hardware)):
        raise ctypes.WinError(ctypes.get_last_error())
    require(process.value == 0 and hardware.value == 0x8664, "Translated Windows execution is out of scope")
    return {"system": platform.platform(), "machine": platform.machine(), "processor": platform.processor(),
            "logical_cpus": os.cpu_count(), "runner": os.environ.get("RUNNER_NAME"),
            "runner_image": os.environ.get("ImageOS"), "runner_image_version": os.environ.get("ImageVersion"),
            "gha_run_id": os.environ.get("GITHUB_RUN_ID"), "gha_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "gha_workflow_sha": os.environ.get("GITHUB_SHA"), "native": True}


def amd64_pe(path):
    sha = digest(path)
    with path.open("rb") as image:
        header = image.read(64)
        require(len(header) == 64 and header[:2] == b"MZ", f"Missing DOS header: {path}")
        pos = int.from_bytes(header[60:64], "little")
        require(64 <= pos <= path.stat().st_size - 26, f"Invalid PE offset: {path}")
        image.seek(pos)
        header = image.read(26)
    require(header[:6] == b"PE\x00\x00\x64\x86" and header[24:] == b"\x0b\x02", f"Expected AMD64 PE32+: {path}")
    return sha


def unpack_portable(path, output):
    output.mkdir()
    with zipfile.ZipFile(path) as archive:
        for name in sorted(PROGRAMS):
            entry = f"{path.stem}/{name}"
            matches = [row for row in archive.infolist() if row.filename == entry]
            require(len(matches) == 1, f"Missing or duplicate portable runtime: {entry}")
            member = matches[0]
            require(0 < member.file_size <= LIMIT and stat.S_IFMT(member.external_attr >> 16) in (0, stat.S_IFREG),
                    f"Invalid portable program: {entry}")
            destination = output / name
            destination.parent.mkdir(exist_ok=True)
            with archive.open(member) as incoming, destination.open("xb") as stream:
                shutil.copyfileobj(incoming, stream, 1 << 20)


def unpack_installer(path, output, seven_zip):
    output.mkdir()
    subprocess.run([seven_zip, "x", "-y", "-bd", f"-o{output}", "--", str(path), *sorted(PROGRAMS)],
                   capture_output=True, timeout=120, check=True)
    inventory = {item.relative_to(output).as_posix() for item in output.rglob("*") if not item.is_dir()}
    require(inventory == PROGRAMS, "The installer did not contain exactly the selected runtime paths")


ARCHIVE_BYTES = {
    "ucrt": {"portable": 40_740_527, "installer": 28_680_238},
    "msvcrt": {"portable": 36_270_994, "installer": 25_936_331},
}
FORWARD = (("ucrt", "portable"), ("msvcrt", "portable"),
           ("ucrt", "installer"), ("msvcrt", "installer"))


def verify_packages(args, host):
    out = args.output
    release = out / "release"
    release.mkdir()
    manifest = {name: download(name, release, expected, args.assets) for name, expected in SIGNED_FILES.items()}
    signed = verify_signature(manifest["SHA256SUMS"], manifest["SHA256SUMS.asc"], args.keyring, release)
    payload = out / "payload"
    payload.mkdir()
    seven_zip = args.seven_zip or executable(
        "7z", Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "7-Zip" / "7z.exe",
        shutil.which("7zz"))
    packages = {}
    for crt, forms in PACKAGES.items():
        runtime = payload / crt
        runtime.mkdir()
        stem = f"sugarchain-en-31.1.2-windows-x86_64-{crt}"
        names = {"portable": f"{stem}-portable.zip", "installer": f"{stem}-setup.exe"}
        archive_receipts = {}
        members = {}
        for kind, expected in forms.items():
            name = names[kind]
            require(signed.get(name) == expected, f"Signed and frozen archive pins differ: {name}")
            path = download(name, release, expected, args.assets)
            size = path.stat().st_size
            require(size == ARCHIVE_BYTES[crt][kind], f"Unexpected archive size: {name}")
            archive_receipts[kind] = {"name": name, "sha256": expected, "bytes": size}
            if kind == "portable":
                unpack_portable(path, runtime / kind)
            else:
                unpack_installer(path, runtime / kind, seven_zip)
            members[kind] = {name: amd64_pe(runtime / kind / name) for name in sorted(PROGRAMS)}
        require(members["portable"] == members["installer"],
                f"The installer and portable executable hashes differ: {crt}")
        packages[crt] = {"archives": archive_receipts, "programs_sha256": members,
                         "installer_members_equal": True, "installer_executed": False}
    write_json(out / "package-identity.json", {
        "release": TAG, "release_source": SOURCE, "release_tree": TREE,
        "runtime_source": RUNTIME_SOURCE, "runtime_tree": RUNTIME_TREE,
        "signature_fingerprint": KEY, "authority": SIGNED_FILES, "host": host, "packages": packages,
    })
    return packages


def fixed_schedule():
    return [
        (mode, trial, crt, kind)
        for mode in ("cli", "gui")
        for trial, order in enumerate((FORWARD, FORWARD[::-1], FORWARD), 1)
        for crt, kind in order
    ]


def terminate_harness(process):
    if process.poll() is not None:
        return None
    try:
        killed = subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                                capture_output=True, timeout=30)
        return killed.returncode
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=15)


def inspect_result(target, row):
    receipt = json.loads((target / "result.json").read_text(encoding="utf-8"))
    cases = receipt.get("cases")
    require(isinstance(cases, list) and len(cases) == 1, "Missing one fresh trial receipt")
    case = cases[0]
    cleanup = case["cleanup"]
    require(set(cleanup) == {"sender", "receiver"} and all(
        item["pid"] is None or item["reaped"] is True for item in cleanup.values()),
        "Owned node cleanup is unconfirmed")
    row["nodes_exited"] = True
    require(row["exit_code"] == 0 and receipt["status"] == case["status"] == "passed",
            receipt.get("error") or case.get("error") or "Common measurement failed")
    for name in ("archive_sha256", "sender_sha256", "receiver_sha256"):
        require(receipt.get(name) == row[name], f"Common measurement provenance differs: {name}")
    require(receipt.get("release_tag") == TAG and receipt.get("release_source") == row["runtime_source"]
            and receipt.get("release_tree") == row["runtime_tree"],
            "Common measurement provenance differs from the Windows runtime origin")
    require(all(item["pid"] and item["rpc_ack"] is True and item["clean_shutdown"] is True
                and item["returncode"] == 0 and item["forced"] is False and not item["errors"]
                for item in cleanup.values()), "A node did not complete clean shutdown")
    require(case["two_header_passes_verified"] is True, "Two header passes were not verified")
    require(case["verifychain"]["level"] == 4 and case["verifychain"]["blocks"] == 100_000,
            "Full level-4 verification was not recorded")
    endpoint = case["timing"]["endpoint"]
    require(endpoint["blocks"] == endpoint["headers"] == 100_000
            and endpoint["initialblockdownload"] is False, "Receiver did not reach the synchronized endpoint")
    seconds = endpoint["startup_to_ibd_clear_seconds"]
    require(type(seconds) in (int, float) and math.isfinite(seconds) and seconds > 0,
            "Invalid benchmark duration")
    row["startup_to_ibd_clear_seconds"] = seconds


def measure(args, mode, trial, crt, kind, package):
    output = args.output
    sender_name = "daemon/sugarchaind.exe"
    receiver_name = "sugarchain-qt.exe" if mode == "gui" else sender_name
    runtime = output / "payload" / crt / kind
    name = f"{mode}-{trial:02}-{crt}-{kind}"
    target = output / "measurements" / name
    log_path = target.with_suffix(".log")
    archive_sha = package["archives"][kind]["sha256"]
    members = package["programs_sha256"][kind]
    row = {
        "crt": crt, "package": kind, "receiver": mode, "trial": trial, "status": "failed",
        "archive_sha256": archive_sha, "sender_sha256": members[sender_name],
        "receiver_sha256": members[receiver_name], "runtime_source": RUNTIME_SOURCE,
        "runtime_tree": RUNTIME_TREE, "nodes_exited": False,
        "result": (target / "result.json").relative_to(output).as_posix(),
        "command_log": log_path.relative_to(output).as_posix(),
        "started_utc": datetime.now(timezone.utc).isoformat(),
    }
    cmd = [sys.executable, "-B", str(args.harness), "--common", str(args.common),
           "--resources", str(args.resources), "--sender", str(runtime / sender_name),
           "--receiver", str(runtime / receiver_name), "--fixture", str(args.fixture),
           "--fixture-info", str(args.fixture_info), "--work-dir", str(target),
           "--platform", "windows", "--arch", "x86_64", "--archive-sha256", archive_sha,
           "--sender-sha256", row["sender_sha256"], "--receiver-sha256", row["receiver_sha256"],
           "--runtime-source", RUNTIME_SOURCE, "--runtime-tree", RUNTIME_TREE,
           "--trials", "1", "--trial-seconds", str(args.trial_seconds)]
    if mode == "gui":
        cmd.extend(("--gui", "--gui-arg=-choosedatadir=0"))
    env = {**os.environ, "QT_QPA_PLATFORM": "windows", "PYTHONUTF8": "1"}
    try:
        with log_path.open("xb") as stream:
            process = subprocess.Popen(cmd, stdout=stream, stderr=subprocess.STDOUT, env=env)
            try:
                row["exit_code"] = process.wait(timeout=3 * args.trial_seconds + 120)
            except BaseException:
                row["taskkill_exit_code"] = terminate_harness(process)
                raise
        inspect_result(target, row)
        row["status"] = "passed"
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
    write_json(target.with_suffix(".adapter.json"), row)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("harness", "common", "resources", "fixture", "fixture-info", "assets"):
        parser.add_argument(f"--{option}", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--keyring", type=Path, required=True)
    parser.add_argument("--seven-zip")
    parser.add_argument("--trial-seconds", type=int, default=300)
    parser.add_argument("--verify-only", action="store_true",
                        help="Verify signed archives and payload parity without running Windows binaries")
    args = parser.parse_args()
    for name in ("output", "keyring", "harness", "common", "resources", "fixture", "fixture_info", "assets"):
        if path := getattr(args, name):
            setattr(args, name, path.resolve())
    if not args.verify_only and not all(path and path.is_file() for path in (
        args.harness, args.common, args.resources, args.fixture, args.fixture_info,
    )):
        parser.error("Measurements require --harness, --common, --resources, --fixture and --fixture-info")
    require(10 <= args.trial_seconds <= 300, "Trial deadline must be between 10 and 300 seconds")
    out = args.output
    out.mkdir()
    schedule = fixed_schedule()
    result = {"release": TAG, "release_source": SOURCE, "release_tree": TREE,
              "runtime_source": RUNTIME_SOURCE, "runtime_tree": RUNTIME_TREE,
              "status": "incomplete", "cases": [], "summaries": [],
              "schedule": [{"receiver": mode, "trial": trial, "crt": crt, "package": kind}
                           for mode, trial, crt, kind in schedule]}
    try:
        packages = verify_packages(args, None if args.verify_only else native_host())
        if args.verify_only:
            result["status"] = "archives_verified"
            return 0
        (out / "measurements").mkdir()
        for mode, trial, crt, kind in schedule:
            row = measure(args, mode, trial, crt, kind, packages[crt])
            result["cases"].append(row)
            print(f"{crt} {kind} {mode} trial {trial}: {row['status']}", flush=True)
            require(row["nodes_exited"], "Owned node cleanup is unconfirmed. Further trials were not launched.")
        for mode in ("cli", "gui"):
            for crt, kind in FORWARD:
                times = [row["startup_to_ibd_clear_seconds"] for row in result["cases"]
                         if (row["receiver"], row["crt"], row["package"]) == (mode, crt, kind)
                         and row["status"] == "passed"]
                result["summaries"].append({"crt": crt, "package": kind, "receiver": mode,
                    "sample_seconds": times, "median_seconds": median(times) if len(times) == 3 else None})
        if all(len(summary["sample_seconds"]) == 3 for summary in result["summaries"]):
            result["status"] = "passed"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        print(f"Windows adapter failed: {exc}", file=sys.stderr)
    finally:
        write_json(out / "adapter-result.json", result)
    return int(result["status"] != "passed")


if __name__ == "__main__":
    sys.exit(main())

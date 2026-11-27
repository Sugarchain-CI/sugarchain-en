#!/usr/bin/env python3
"""Run preserved Sugarchain En.8 test payloads on native x86-64 Windows."""

import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
from urllib.request import urlopen
import zipfile

TAG = "v31.1.2-en.8"
SOURCE = "ba6ba77698f9a0759063604c4f87ce3eab93c107"
TREE = "585f08d47bc953b7863d2fc3ba51f3ea762bc36f"
ROOT = f"https://github.com/decryp2kanon/sugarchain-en/releases/download/{TAG}"
KEY = "CF8F465D97437DA3BB25534D92F37F683E41E891"
KEY_SHA = "03c4bb8a655e61c932977d4d3ff778784e7b559a589eeb1c799a1f306d856729"
SIGNED_FILES = {"SHA256SUMS": "687595190828e35453b775c5fadf48a3be5cbf334f91c26e45b76f79af95dbe2",
                "SHA256SUMS.asc": "fa38edbe60e1d1c07b1c181aeb53b4e85c9b6281ca8ec32986379e069619dffc"}
PACKAGES = {
    "ucrt": {"portable": "a983e1f59fe0a97247dc74452575d7de3e6ab17cecdca64aa9c729a57df3b770",
             "installer": "d4eb27908c24517c1fb0bf502ea82ab4165e6cf55dc093015bf2a63a248a18cf"},
    "msvcrt": {"portable": "bbd13a10dc75900c69dd4cf5b6534b2778afabdfbd29bb198002d6400adc40d5",
               "installer": "d8fa547c20006396be61843d0a4919c31207dae19fa8df8f1e62830ae9221ea3"},
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
    # Git for Windows may translate stdout line endings through its C runtime.
    require(signers == [KEY.encode("ascii")] and verified.stdout.replace(b"\r\n", b"\n") == manifest.read_bytes(),
            "The clearsigned release manifest and pinned signer did not match")
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


def package_paths(crt, local, output, keyring, pins=None):
    output.mkdir()
    manifest = {name: download(name, output, expected, local) for name, expected in SIGNED_FILES.items()}
    signed = verify_signature(manifest["SHA256SUMS"], manifest["SHA256SUMS.asc"], keyring, output)
    stem = f"sugarchain-en-31.1.2-windows-x86_64-{crt}"
    names = {"portable": f"{stem}-portable.zip", "installer": f"{stem}-setup.exe"}
    if pins:
        with pins.open(encoding="utf-8") as source:
            selection = json.load(source)
        expected_identity = {"schema": 1, "repository": "decryp2kanon/sugarchain-en", "tag": TAG,
                             "source": SOURCE, "sha256sums_sha256": SIGNED_FILES["SHA256SUMS"]}
        require(all(selection.get(key) == value for key, value in expected_identity.items()),
                "The common asset pins differ from the exact En.8 release")
    files = {}
    for kind, name in names.items():
        expected = PACKAGES[crt][kind]
        require(signed.get(name) == expected, f"Signed release and pinned package differ: {name}")
        files[kind] = download(name, output, expected, local)
        if pins:
            require(selection["assets"].get(name) == {"sha256": expected, "bytes": files[kind].stat().st_size,
                                                       "url": f"{ROOT}/{name}"},
                    f"The common asset pin differs from the signed package: {name}")
    return files


def terminate_harness(process):
    if process.poll() is not None:
        return None
    try:
        killed = subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, timeout=30)
        return killed.returncode
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=15)


def measure(args, directory, kind, mode, programs):
    runtime = directory / "payload" / kind
    sender = runtime / "daemon" / "sugarchaind.exe"
    gui = mode == "gui"
    receiver = runtime / "sugarchain-qt.exe" if gui else sender
    target = directory / "measurements" / f"{kind}-{mode}"
    log_path = target.with_suffix(".log")
    archive_sha256 = PACKAGES[args.crt][kind]
    receiver_sha256 = programs[receiver.relative_to(runtime).as_posix()]
    cmd = [sys.executable, "-B", str(args.harness), "--sender", str(sender), "--receiver", str(receiver),
           "--fixture", str(args.fixture), "--fixture-info", str(args.fixture_info), "--work-dir", str(target),
           "--platform", "windows", "--arch", "x86_64", "--archive-sha256", archive_sha256,
           "--receiver-sha256", receiver_sha256, "--trial-seconds", str(args.trial_seconds)]
    env = {**os.environ, "QT_QPA_PLATFORM": "windows", "PYTHONUTF8": "1"}
    if gui:
        cmd.extend(("--gui", "--gui-arg=-choosedatadir=0"))
    started = datetime.now(timezone.utc).isoformat()
    row = {"package": kind, "receiver": mode, "archive_sha256": archive_sha256, "receiver_sha256": receiver_sha256,
           "result": f"measurements/{target.name}/result.json", "command_log": f"measurements/{log_path.name}",
           "started_utc": started, "status": "failed"}
    with log_path.open("xb") as stream:
        process = subprocess.Popen(cmd, stdout=stream, stderr=subprocess.STDOUT, env=env)
        try:
            row["exit_code"] = process.wait(timeout=3 * args.trial_seconds + 240)
        except subprocess.TimeoutExpired:
            row["taskkill_exit_code"] = terminate_harness(process)
            row["status"] = "case_deadline_exceeded"
        except BaseException:
            terminate_harness(process)
            raise
    if row.get("exit_code") == 0 and (target / "result.json").is_file():
        row["status"] = "completed"
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crt", choices=tuple(PACKAGES), required=True)
    parser.add_argument("--harness", type=Path)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--fixture-info", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--keyring", type=Path, required=True)
    parser.add_argument("--pins", type=Path, help="Parent workflow signed release asset pins")
    parser.add_argument("--assets", type=Path, help="Use independently downloaded release assets")
    parser.add_argument("--seven-zip")
    parser.add_argument("--trial-seconds", type=int, default=300)
    parser.add_argument("--verify-only", action="store_true", help="Verify archives and extraction without running payloads")
    args = parser.parse_args()
    for arg in ("output", "keyring", "harness", "fixture", "fixture_info", "assets", "pins"):
        if path := getattr(args, arg):
            setattr(args, arg, path.resolve())
    if not args.verify_only and not all(path and path.is_file() for path in (args.harness, args.fixture, args.fixture_info)):
        parser.error("Runtime measurement requires --harness, --fixture and --fixture-info")
    require(10 <= args.trial_seconds <= 300, "Trial deadline must be between 10 and 300 seconds")
    if not args.verify_only:
        host = native_host()
    else:
        host = None
    out = args.output
    out.mkdir()
    files = package_paths(args.crt, args.assets, out / "release", args.keyring, args.pins)
    payload = out / "payload"
    payload.mkdir()
    seven_zip = args.seven_zip or executable("7z", Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "7-Zip" / "7z.exe",
                                           shutil.which("7zz"))
    unpack_portable(files["portable"], payload / "portable")
    unpack_installer(files["installer"], payload / "installer", seven_zip)
    members = {kind: {name: amd64_pe(payload / kind / name) for name in sorted(PROGRAMS)} for kind in files}
    require(members["portable"] == members["installer"], "The installer and portable executable hashes differ")
    write_json(out / "package-identity.json", {"release": TAG, "source": SOURCE, "tree": TREE, "crt": args.crt,
               "signature_fingerprint": KEY, "authority": dict(SIGNED_FILES), "host": host,
               "archives": {kind: {"name": file.name, "sha256": PACKAGES[args.crt][kind]} for kind, file in files.items()},
               "programs_sha256": members, "installer_executed": False, "installer_members_equal": True})
    if args.verify_only:
        print(f"{args.crt}: signed assets and seven installer/portable AMD64 payload hashes verified")
        return 0
    (out / "measurements").mkdir()
    rows = []
    for kind in ("portable", "installer"):
        for mode in ("daemon", "gui"):
            try:
                row = measure(args, out, kind, mode, members[kind])
            except (OSError, subprocess.SubprocessError) as exc:
                row = {"package": kind, "receiver": mode, "status": "adapter_error", "error_type": type(exc).__name__,
                       "reason": str(exc)}
            rows.append(row)
            write_json(out / "measurements" / f"{kind}-{mode}.adapter.json", row)
            print(f"{args.crt} {kind} {mode}: {row['status']}", flush=True)
    complete = all(row["status"] == "completed" for row in rows)
    write_json(out / "adapter-result.json", {"release": TAG, "crt": args.crt,
               "status": "completed" if complete else "incomplete", "cases": rows})
    return 0 if complete else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        print(f"Windows adapter failed: {error}", file=sys.stderr)
        sys.exit(1)

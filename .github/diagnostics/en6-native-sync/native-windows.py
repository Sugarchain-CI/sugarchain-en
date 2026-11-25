#!/usr/bin/env python3
"""Benchmark the published Windows archives on disposable native CI workers."""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
from zipfile import ZipFile


RELEASE = "https://github.com/decryp2kanon/sugarchain-en/releases/download/v31.1.2-en.6"
ARCHIVES = {
    "ucrt": {
        "portable.zip": "acc8926e6ff11d6a5c230c86b27c7c953ea612afa236b259dfb70b47f29193b6",
        "setup.exe": "9356ef69d42891b8d580223eaf8daa743b3e08d592d68905dd870feb88b81e83",
    },
    "msvcrt": {
        "portable.zip": "03fd8d51520b5548bb079b2ef763177dea44b873292955971b76ada393b4f7ba",
        "setup.exe": "f3aef947c3d0e4950092ae5b919593d9ac88b16b9888d8516a590756e7794eff",
    },
}
AMD64 = 0x8664
PROGRAMS = {"daemon": "daemon/sugarchaind.exe", "gui": "sugarchain-qt.exe", "cli": "daemon/sugarchain-cli.exe"}
INSTALL_KEY = r"Software\Sugarchain En"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def verify_native_host():
    if (sys.platform != "win32" or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("RUNNER_ARCH") != "X64"):
        raise RuntimeError("A disposable native x64 GitHub-hosted Windows runner is required")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.IsWow64Process2.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ushort), ctypes.POINTER(ctypes.c_ushort)]
    kernel.IsWow64Process2.restype = ctypes.c_int
    process, native = ctypes.c_ushort(), ctypes.c_ushort()
    if not kernel.IsWow64Process2(kernel.GetCurrentProcess(), ctypes.byref(process), ctypes.byref(native)):
        raise ctypes.WinError(ctypes.get_last_error())
    if process.value != 0 or native.value != AMD64 or hasattr(ctypes.WinDLL("ntdll"), "wine_get_version"):
        raise RuntimeError("The Windows process must execute on native AMD64 without a compatibility layer")

    import winreg

    for key in (r"Software\Sugarchain", INSTALL_KEY, r"Software\Sugarchain Komorebi",
                r"Software\Sugarchain Komorebi (64-bit)"):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key):
                raise RuntimeError(f"Existing Sugarchain profile: {key}")
        except FileNotFoundError:
            pass
    for variable in ("APPDATA", "LOCALAPPDATA", "ProgramFiles"):
        if (Path(os.environ[variable]) / "Sugarchain").exists():
            raise RuntimeError(f"Existing Sugarchain data or installation under {variable}")
    return {"platform": platform.platform(), "machine": platform.machine(),
            "processor": os.environ.get("PROCESSOR_IDENTIFIER"), "logical_cpus": os.cpu_count(),
            "runner": os.environ.get("ImageOS"), "image_version": os.environ.get("ImageVersion"),
            "native_machine": f"0x{native.value:04x}", "process_machine": process.value}


def fetch(archive, expected):
    subprocess.run(["curl.exe", "--fail", "--silent", "--show-error", "--location", "--retry", "3",
                    "--retry-all-errors", "--connect-timeout", "15", "--max-time", "180",
                    "--proto", "=https", "--output", str(archive), f"{RELEASE}/{archive.name}"],
                   check=True, timeout=300)
    if digest(archive) != expected:
        raise RuntimeError(f"Signed release checksum mismatch: {archive.name}")


def programs(directory):
    paths = {name: directory / relpath for name, relpath in PROGRAMS.items()}
    for path in paths.values():
        with path.open("rb") as stream:
            header = stream.read(64)
            if header[:2] != b"MZ" or len(header) < 64:
                raise RuntimeError(f"Invalid PE header: {path.name}")
            stream.seek(struct.unpack_from("<I", header, 60)[0])
            if stream.read(6) != b"PE\0\0" + struct.pack("<H", AMD64):
                raise RuntimeError(f"Expected AMD64 executable: {path.name}")
    return paths


def nsis(binary, directory, *, uninstall=False):
    # The final NSIS directory option consumes the entire remaining command line.
    option = "_?=" if uninstall else "/D="
    subprocess.run(f'"{binary}" /S {option}{directory}', check=True, timeout=180)


def measure(harness, fixture, folder, label, asset_hash, sender, receivers):
    rows = []
    for network in ("regtest", "testnet7"):
        for kind in ("daemon", "gui"):
            case = f"{label}-{kind}-{network}"
            work = folder / case
            command = [sys.executable, str(harness), "--sender", str(sender), "--receiver", str(receivers[kind]),
                       "--work-dir", str(work), "--platform", "windows", "--arch", "x86_64",
                       "--network", network, "--archive-sha256", asset_hash]
            if kind == "gui":
                command += ["--gui"]
            if network == "testnet7":
                command += ["--fixture", str(fixture)]
            row = {"case": case, "archive_sha256": asset_hash, "binary_sha256": digest(receivers[kind])}
            try:
                subprocess.run(command, env={**os.environ, "QT_QPA_PLATFORM": "windows"},
                               check=True, timeout=600)
                result = work / "result.json"
                shutil.copyfile(result, folder / "evidence" / f"{case}.json")
                row["status"] = "pass"
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                row.update(status="failed", error=str(exc))
                print(f"{case} failed: {exc}", flush=True)
            rows.append(row)
            write_json(folder / "evidence" / f"{label}-measurements.json", rows)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crt", choices=ARCHIVES, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--harness", type=Path, default=Path(__file__).with_name("native-sync.py"))
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    host = verify_native_host()
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    folder = args.work_dir.resolve()
    if folder == root or not folder.is_relative_to(root):
        parser.error("--work-dir must designate a fresh subdirectory of RUNNER_TEMP")
    folder.mkdir()
    evidence = folder / "evidence"
    evidence.mkdir()
    fixture, harness = (path.resolve(strict=True) for path in (args.fixture, args.harness))
    hashes = ARCHIVES[args.crt]
    stem = f"sugarchain-en-31.1.2-windows-x86_64-{args.crt}"
    portable = folder / f"{stem}-portable.zip"
    setup = folder / f"{stem}-setup.exe"
    manifest = {"release": "v31.1.2-en.6", "crt": args.crt, "host": host, "archives": {}, "checks": {}}
    status = evidence / "package-identity.json"
    write_json(status, manifest)
    fetch(portable, hashes["portable.zip"])
    manifest["archives"][portable.name] = hashes["portable.zip"]
    with ZipFile(portable) as archive:
        archive.extractall(folder)
    portable_programs = programs(folder / portable.stem)
    portable_sha = {kind: digest(path) for kind, path in portable_programs.items()}
    manifest["checks"]["portable_programs"] = portable_sha
    write_json(status, manifest)
    rows = measure(harness, fixture, folder, "portable", hashes["portable.zip"],
                   portable_programs["daemon"], portable_programs)

    fetch(setup, hashes["setup.exe"])
    manifest["archives"][setup.name] = hashes["setup.exe"]
    write_json(status, manifest)
    import winreg

    install = folder / "Sugarchain En test installation"
    nsis(setup, install)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INSTALL_KEY) as key:
        registered = Path(winreg.QueryValueEx(key, "Path")[0])
    if registered.resolve(strict=True) != install:
        raise RuntimeError("Installer wrote outside the dedicated installation directory")
    manifest["checks"]["installed_in_requested_directory"] = True
    uninstaller = install / "uninstall.exe"
    try:
        installed_programs = programs(install)
        installed_sha = {kind: digest(path) for kind, path in installed_programs.items()}
        manifest["checks"]["installed_programs"] = installed_sha
        manifest["checks"]["installed_equals_portable"] = installed_sha == portable_sha
        write_json(status, manifest)
        rows += measure(harness, fixture, folder, "installed", hashes["setup.exe"],
                        portable_programs["daemon"], installed_programs)
    finally:
        nsis(uninstaller, install, uninstall=True)
        manifest["checks"]["uninstalled"] = all(not (install / relpath).exists() for relpath in PROGRAMS.values())
        write_json(status, manifest)
    if not manifest["checks"]["uninstalled"] or any(row["status"] != "pass" for row in rows):
        sys.exit(1)


if __name__ == "__main__":
    main()

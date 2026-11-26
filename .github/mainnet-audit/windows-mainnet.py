#!/usr/bin/env python3
"""Measure the signed Windows release payload on a disposable native runner."""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
from zipfile import ZipFile


RELEASE = "v31.1.2-en.7"
DOWNLOAD = f"https://github.com/decryp2kanon/sugarchain-en/releases/download/{RELEASE}"
IDENTITY_CI = "https://github.com/Sugarchain-CI/sugarchain-en/actions/runs/45705737606"
PACKAGE = {
    "ucrt": {
        "portable.zip": "acc8926e6ff11d6a5c230c86b27c7c953ea612afa236b259dfb70b47f29193b6",
        "setup.exe": "9356ef69d42891b8d580223eaf8daa743b3e08d592d68905dd870feb88b81e83",
        "cli": "dd42ac39df4f52605751c610383432c81c497b44103912f90527bcd29c03da2a",
        "gui": "e5da8475f78d87988eb37b057087e8475280d76603bdd6a315938192151e8d6f",
    },
    "msvcrt": {
        "portable.zip": "03fd8d51520b5548bb079b2ef763177dea44b873292955971b76ada393b4f7ba",
        "setup.exe": "f3aef947c3d0e4950092ae5b919593d9ac88b16b9888d8516a590756e7794eff",
        "cli": "e5ad7945b13e38d93a512287d6cfeca125da6546f0404b655e95c3b7d55c37a4",
        "gui": "05ab826eec9de89589649253d00861e7c2dc4b8a2b92cf96111f883c2aaf7648",
    },
}
AMD64 = 0x8664
PROGRAMS = {"cli": Path("daemon/sugarchaind.exe"), "gui": Path("sugarchain-qt.exe")}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_host():
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
        raise RuntimeError("Windows benchmark requires native AMD64 without an emulation layer")
    return {
        "platform": platform.platform(), "machine": platform.machine(),
        "processor": os.environ.get("PROCESSOR_IDENTIFIER"), "logical_cpus": os.cpu_count(),
        "image": os.environ.get("ImageOS"), "image_version": os.environ.get("ImageVersion"),
        "native_machine": f"0x{native.value:04x}", "process_machine": f"0x{process.value:04x}",
    }


def verify_executable(path, expected):
    with path.open("rb") as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:2] != b"MZ":
            raise RuntimeError(f"Invalid PE executable: {path.name}")
        stream.seek(struct.unpack_from("<I", header, 60)[0])
        if stream.read(6) != b"PE\0\0" + struct.pack("<H", AMD64):
            raise RuntimeError(f"Unexpected executable architecture: {path.name}")
    found = digest(path)
    if found != expected:
        raise RuntimeError(f"Installed/portable binary identity check failed: {path.name}")
    return found


def download(path, expected):
    subprocess.run([
        "curl.exe", "--fail", "--silent", "--show-error", "--location", "--retry", "2",
        "--retry-all-errors", "--connect-timeout", "12", "--max-time", "55",
        "--proto", "=https", "--output", str(path), f"{DOWNLOAD}/{path.name}",
    ], check=True, timeout=120)
    if digest(path) != expected:
        raise RuntimeError(f"Verified release checksum mismatch: {path.name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crt", choices=PACKAGE, required=True)
    parser.add_argument("--harness", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--fixture-info", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--network-seconds", type=int, default=75)
    args = parser.parse_args()
    host = verify_host()
    work = args.work_dir.resolve()
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if work == runner_temp or not work.is_relative_to(runner_temp):
        parser.error("--work-dir must be a fresh subdirectory of RUNNER_TEMP")
    work.mkdir()
    evidence = work / "evidence"
    evidence.mkdir()
    temp_root = work / "nodes"
    temp_root.mkdir()
    stem = f"sugarchain-en-31.1.2-windows-x86_64-{args.crt}"
    verified = PACKAGE[args.crt]
    portable = work / f"{stem}-portable.zip"
    setup = work / f"{stem}-setup.exe"
    for path, extension in ((portable, "portable.zip"), (setup, "setup.exe")):
        download(path, verified[extension])
    with ZipFile(portable) as archive:
        archive.extractall(work)
    binaries = {kind: work / stem / path for kind, path in PROGRAMS.items()}
    runtime_sha256 = {kind: verify_executable(path, verified[kind]) for kind, path in binaries.items()}
    metadata = {
        "release": RELEASE, "host": host, "crt": args.crt,
        "archives": {portable.name: verified["portable.zip"], setup.name: verified["setup.exe"]},
        "runtime_sha256": runtime_sha256, "installer_parity_ci": IDENTITY_CI,
        "measurement_scope": "Portable runtime measured directly. The byte-identical installer runtime shares these results.",
    }
    (evidence / "package-identity.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    results = {}
    for kind, binary in binaries.items():
        command = [
            sys.executable, str(args.harness.resolve(strict=True)), "--binary", str(binary),
            "--output", str(evidence / f"{kind}.json"), "--fixture", str(args.fixture.resolve(strict=True)),
            "--fixture-info", str(args.fixture_info.resolve(strict=True)),
            "--network-seconds", str(args.network_seconds), "--temp-root", str(temp_root),
        ]
        if kind == "gui":
            command.append("--gui")
        log = evidence / f"{kind}.log"
        with log.open("wb") as output:
            try:
                result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT,
                                        env={**os.environ, "QT_QPA_PLATFORM": "windows"}, timeout=300)
                results[kind] = {"returncode": result.returncode, "output": f"{kind}.json"}
            except (OSError, subprocess.TimeoutExpired) as exc:
                results[kind] = {"error": str(exc)}
        print(kind, results[kind], flush=True)
    (evidence / "status.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return int(any(row.get("returncode") != 0 for row in results.values()))


if __name__ == "__main__":
    sys.exit(main())

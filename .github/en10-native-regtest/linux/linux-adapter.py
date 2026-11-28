#!/usr/bin/env python3
"""Measure the signed En.10 Linux packages on matching native hardware."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import runpy
import signal
import struct
import subprocess
import tarfile
import time
import urllib.request


TOOLS = Path(__file__).resolve().parent
COMMON = TOOLS.parent / "common"
TAG = "v31.1.2-en.10"
RELEASE = f"https://github.com/decryp2kanon/sugarchain-en/releases/download/{TAG}"
PROGRAMS = {"cli": "sugarchaind", "gui": "sugarchain-qt"}
ELF = {"x86_64": ("x86_64", 2, 62), "arm64": ("aarch64", 2, 183), "armhf": ("aarch64", 1, 40)}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with path.open("rb") as data:
        return hashlib.file_digest(data, "sha256").hexdigest()


def persist(path, receipt):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def download(directory, pin):
    url = f"{RELEASE}/{pin['name']}"
    request = urllib.request.Request(url, headers={"User-Agent": "Sugarchain-En-native-Regtest"})
    path = directory / pin["name"]
    copied = 0
    with urllib.request.urlopen(request, timeout=45) as response, path.open("xb") as target:
        require(response.url.startswith("https://"), "Release download redirected outside HTTPS")
        while chunk := response.read(1024**2):
            copied += len(chunk)
            require(copied <= pin["size"], f"Download exceeds pinned length: {pin['name']}")
            target.write(chunk)
    require(copied == pin["size"] and digest(path) == pin["sha256"], f"Wrong release bytes: {pin['name']}")
    return path


def validate_manifest(downloads, signature, package, evidence):
    key = TOOLS / "release-public.gpg"
    require(digest(key) == signature["keyring_sha256"], "Release keyring SHA differs")
    for description in ("manifest", "clearsigned"):
        pin = signature[description]
        path = downloads / pin["name"]
        require(path.stat().st_size == pin["size"] and digest(path) == pin["sha256"],
                f"Signed manifest inputs differ: {description}")
    home = evidence / "gpg-home"
    home.mkdir(mode=0o700)
    signed = subprocess.run(
        ["gpgv", "--homedir", str(home), "--keyring", str(key), "--status-fd=2", "--output", "-",
         str(downloads / "SHA256SUMS.asc")], capture_output=True, timeout=20,
    )
    (evidence / "gpgv.log").write_bytes(signed.stderr)
    signed.check_returncode()
    signers = re.findall(rb"(?m)^\[GNUPG:\] VALIDSIG ([A-F0-9]+) ", signed.stderr)
    require(signers == [signature["fingerprint"].encode("ascii")], "Wrong release signature fingerprint")
    manifest = (downloads / "SHA256SUMS").read_bytes()
    require(manifest.endswith(b"\n") and (signed.stdout == manifest or signed.stdout + b"\n" == manifest),
            "Clear-signed manifest differs")
    rows = {}
    for line in manifest.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        require(match is not None and match[2] not in rows, "Invalid signed manifest entry")
        rows[match[2]] = match[1]
    require(len(rows) == 17 and rows.get(package["name"]) == package["sha256"], "Wrong signed runtime archive")
    return {"fingerprint": signature["fingerprint"], "manifest_sha256": signature["manifest"]["sha256"],
            "signed_archive_sha256": rows[package["name"]]}


def unpack(archive, directory, package, arch):
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        require(len(members) <= 512 and sum(row.size for row in members) <= 200 * 1024**2,
                "Unexpected Linux package inventory or size")
        paths = set()
        for member in members:
            path = PurePosixPath(member.name)
            require(path.parts and path.parts[0] == package["root"] and ".." not in path.parts
                    and not path.is_absolute() and "\\" not in member.name and path not in paths
                    and (member.isfile() or member.isdir()), "Unexpected member in signed Linux package")
            paths.add(path)
        source.extractall(directory, members=members, filter="data")
    binaries = {}
    for mode, name in PROGRAMS.items():
        program = directory / package["root"] / "bin" / name
        require(program.is_file() and not program.is_symlink() and os.access(program, os.X_OK)
                and digest(program) == package["executables"][name], f"Wrong pinned executable: {name}")
        with program.open("rb") as stream:
            header = stream.read(24)
        _, elf_class, machine = ELF[arch]
        require(len(header) == 24 and header[:7] == b"\x7fELF" + bytes((elf_class, 1, 1))
                and struct.unpack_from("<HHI", header, 16) in ((2, machine, 1), (3, machine, 1)),
                f"Unexpected executable architecture: {name}")
        binaries[mode] = str(program)
    return binaries


def execute(argv, log):
    with log.open("xb") as output:
        proc = subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return proc.wait(timeout=1100)
        except subprocess.TimeoutExpired:
            # Keep the leader unreaped until both signals target the owned group.
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(proc.pid, sig)
                except ProcessLookupError:
                    pass
                if sig == signal.SIGTERM:
                    time.sleep(4)
            proc.wait(timeout=6)
            raise


def measure(args, package, programs, mode):
    command = [
        "python3", "-B", str(COMMON / "regtest-normal.py"),
        "--common", str(COMMON / "en8-regtest-presync.py"),
        "--resources", str(COMMON / "resource_metrics.py"),
        "--sender", programs["cli"], "--receiver", programs[mode],
        "--fixture", str(args.fixture_dir / "regtest-100000.dat"),
        "--fixture-info", str(args.fixture_dir / "fixture-info.json"),
        "--work-dir", str(args.output / mode),
        "--platform", "linux", "--arch", args.arch,
        "--archive-sha256", package["sha256"],
        "--sender-sha256", package["executables"]["sugarchaind"],
        "--receiver-sha256", package["executables"][PROGRAMS[mode]],
        "--runtime-source", package["runtime_source"], "--runtime-tree", package["runtime_tree"],
        "--trials", "3", "--trial-seconds", "300",
    ]
    if mode == "gui":
        command = ["xvfb-run", "-a", "-s", "-screen 0 1280x800x24", *command, "--gui", "--gui-arg=-choosedatadir=0"]
    code = execute(command, args.output / f"{mode}-harness.log")
    return {"mode": mode, "exit": code, "status": "passed" if code == 0 else "failed",
            "evidence": f"{mode}/result.json"}


def host_evidence(machine):
    proc_fields = {}
    with Path("/proc/cpuinfo").open(encoding="utf-8") as stream:
        for line in stream:
            key, _, value = line.partition(":")
            key = key.strip()
            if key in {"model name", "CPU implementer", "CPU part"} and value.strip():
                proc_fields.setdefault(key, value.strip())
    return {"platform": platform.platform(), "machine": machine, "logical_cpus": os.cpu_count(),
            "guest_memory_bytes": os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE"),
            "cpu": proc_fields, "runner": os.environ.get("RUNNER_ARCH"), "virtual_display": "Xvfb for GUI"}


def run(args):
    out = args.output
    out.mkdir(mode=0o700)
    file = out / "platform-summary.json"
    pins = json.loads((TOOLS / "linux-assets.json").read_bytes())
    package = pins["archives"][args.arch]
    report = {"schema": 1, "status": "preflight", "platform": "linux", "arch": args.arch,
              "release_tag": TAG, "release_source": pins["release_source"], "release_tree": pins["release_tree"],
              "runtime_source": package["runtime_source"], "runtime_tree": package["runtime_tree"],
              "package": package["name"], "archive_sha256": package["sha256"], "cases": []}
    persist(file, report)
    try:
        expected, elf_class, elf_machine = ELF[args.arch]
        require(platform.system() == "Linux" and platform.machine() == expected, "Wrong native Linux host")
        report["host"] = host_evidence(expected)
        if args.arch == "armhf":
            helper = runpy.run_path(str(TOOLS / "check-native-armhf.py"))
            proof = helper["run_aarch32_probe"](out / "armhf-native.json")
            persist(out / "armhf-native.json", proof)
            require(proof["supported"] is True, proof["reason"])
        report.update(native=True, emulation=False, elf_class=elf_class, elf_machine=elf_machine,
                      executables=package["executables"])
        downloads = out / "downloads"
        downloads.mkdir(mode=0o700)
        for key in ("manifest", "clearsigned"):
            download(downloads, pins["signature"][key])
        report["signature"] = validate_manifest(downloads, pins["signature"], package, out)
        archive = download(downloads, package)
        programs = unpack(archive, downloads, package, args.arch)
        for mode in PROGRAMS:
            try:
                report["cases"].append(measure(args, package, programs, mode))
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                report["cases"].append({"mode": mode, "status": "failed", "error": f"{type(exc).__name__}: {exc}"})
            persist(file, report)
        report["status"] = "passed" if all(row["status"] == "passed" for row in report["cases"]) else "failed"
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        report.update(status="preflight_failed", error=f"{type(exc).__name__}: {exc}")
        print(report["error"])
    finally:
        persist(file, report)
    print(json.dumps({"arch": args.arch, "status": report["status"], "cases": report["cases"]}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=list(ELF), required=True)
    parser.add_argument("--fixture-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(args.fixture_dir.is_absolute() and args.output.is_absolute(), "Use absolute fixture and output directories")
    raise SystemExit(run(args))

#!/usr/bin/env python3
"""Package exact En.8 Windows deploy outputs and qualify the staged native inputs."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile


SOURCE = "409ea3ee5f1cdb03790ec2adf5e191031a28737f"
TREE = "578110fc4d33962ed429171addc1d09cf5d5906f"
DEPENDS = "8b718f7e3c034fcaf999ea3373a43112509f67d1"
TAG = "v31.1.2-en.9"
PREFIX = "sugarchain-en-31.1.2-"
NOTICE_STEM = PREFIX + "windows-third-party-notices"
NOTICE_SHA = "5b3d1cd0a0efe0c0ea883457b0f6663afc8e1d8123853df364672d40b7454fc5"
NOTICE_OLD_SOURCE = b"692f7f6c91450d3bc707e2ad85dd99d993a7b3b5"
INSTALLER = "Sugarchain-En-31.1.2-win64-setup.exe"
PROGRAMS = ("sugarchain.exe", "sugarchain-qt.exe", *(f"daemon/{name}.exe" for name in (
    "sugarchaind", "sugarchain-cli", "sugarchain-tx", "sugarchain-wallet", "sugarchain-util",
)))
DOCS = {"COPYING.txt": "COPYING", "readme.txt": "doc/README_windows.txt",
        "sugarchain.conf": "share/examples/sugarchain.conf", "share/rpcauth/README.md": "share/rpcauth/README.md",
        "share/rpcauth/rpcauth.py": "share/rpcauth/rpcauth.py"}
TEST_INPUTS = {"bin/test_bitcoin.exe": "test_bitcoin.exe", "test/config.ini": "config.ini"}
LOGS = ("unit-tests.log", "yespower-golden-vectors.log", "sha256-testvectors.log", "header-protocol.log",
        "binary-version.log", "portable-smoke.log", "installer-smoke.log")


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size > 0, f"Invalid artifact file: {path}")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def git(source, *args):
    return subprocess.check_output(["git", "-C", source, *args], timeout=30)


def pin(source):
    values = git(source, "rev-parse", "HEAD", "HEAD^{tree}", "HEAD:depends").decode("ascii").splitlines()
    require(values == [SOURCE, TREE, DEPENDS], "Product source, tree or dependencies differ")
    return datetime.fromtimestamp(int(git(source, "show", "-s", "--format=%ct", SOURCE)), timezone.utc).timetuple()[:6]


def windows_pe(path, amd64=True):
    with path.open("rb") as stream:
        dos = stream.read(64)
        require(len(dos) == 64 and dos[:2] == b"MZ", f"Not a Windows image: {path}")
        offset = int.from_bytes(dos[60:64], "little")
        require(64 <= offset < 1 << 20, f"Unexpected PE header offset: {path}")
        stream.seek(offset)
        pe = stream.read(26)
    require(len(pe) == 26 and pe[:4] == b"PE\0\0" and
            (not amd64 or pe[4:6] == b"\x64\x86" and pe[24:26] == b"\x0b\x02"), f"Unexpected PE type: {path}")


def asset_names(crt):
    stem = PREFIX + f"windows-x86_64-{crt}"
    return stem + "-portable.zip", stem + "-setup.exe"


def read_notices(path):
    require(digest(path) == NOTICE_SHA, "Prior signed Windows notice archive differs")
    notices = {}
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(len(entries) == 77 and sum(item.file_size for item in entries) < 2 << 20, "Unexpected notice archive size")
        for item in entries:
            name = PurePosixPath(item.filename)
            require(name.parts[0] == NOTICE_STEM and len(name.parts) > 1 and name.as_posix() == item.filename and
                    ".." not in name.parts and "\\" not in item.filename and not item.is_dir() and
                    stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG), "Invalid notice member")
            relative = PurePosixPath(*name.parts[1:]).as_posix()
            require(relative not in notices, "Duplicate notice member")
            notices[relative] = archive.read(item)
    readme = notices["README.txt"]
    require(readme.count(NOTICE_OLD_SOURCE) == 2, "Unexpected prior notice source references")
    notices["README.txt"] = readme.replace(NOTICE_OLD_SOURCE, SOURCE.encode("ascii"))
    return notices


def make_zip(out, payload, stamp):
    with zipfile.ZipFile(out, "x") as package:
        for relative, data in sorted(payload.items()):
            item = zipfile.ZipInfo(f"{out.stem}/{relative}", stamp)
            item.create_system = 3
            item.compress_type = zipfile.ZIP_DEFLATED
            item.compress_level = 9
            item.external_attr = (stat.S_IFREG | (0o755 if relative.endswith(".exe") else 0o644)) << 16
            with package.open(item, "w") as target:
                if isinstance(data, Path):
                    with data.open("rb") as stream:
                        shutil.copyfileobj(stream, target, 1 << 20)
                else:
                    target.write(data)
    with zipfile.ZipFile(out) as package:
        require(set(package.namelist()) == {f"{out.stem}/{name}" for name in payload} and
                package.testzip() is None, "Portable archive does not match its input inventory")


def write_json(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")


def sha_manifest(names):
    return "".join(f"{names[name]}  {name}\n" for name in sorted(names))


def stage(args):
    stamp = pin(args.source)
    notices = read_notices(args.notices)
    require(not args.out.exists(), "Use new output for the Windows package")
    installer = args.build / INSTALLER
    require(Path((args.build / "windows-installer-path.txt").read_text().strip()).name == INSTALLER,
            "CMake deployment identified an unexpected installer")
    windows_pe(installer, amd64=False)
    args.out.mkdir()
    portable, setup = asset_names(args.crt)
    with tempfile.TemporaryDirectory(dir=args.out.parent, prefix="nsis-en9-") as work:
        directory = Path(work)
        requested = set(PROGRAMS) | DOCS.keys()
        subprocess.run([args.seven_zip, "x", "-y", "-bd", f"-o{directory}", "--", str(installer), *sorted(requested)],
                       check=True, timeout=120)
        actual = {file.relative_to(directory).as_posix() for file in directory.rglob("*") if file.is_file()}
        require(actual == requested, "Unexpected installer payload path")
        for relative, source in DOCS.items():
            require((directory / relative).read_bytes() == git(args.source, "show", f"{SOURCE}:{source}"),
                    f"Installer document differs from the product source: {relative}")
        members = {relative: digest(directory / relative) for relative in PROGRAMS}
        for relative in members:
            windows_pe(directory / relative)
        make_zip(args.out / portable, {**{name: directory / name for name in requested},
                                      **{f"licenses/{name}": data for name, data in notices.items()}}, stamp)
    shutil.copyfile(installer, args.out / setup)
    release = {name: digest(args.out / name) for name in (portable, setup)}
    (args.out / "SHA256SUMS").write_text(sha_manifest(release), encoding="ascii")
    (args.out / "RELEASE_SOURCE_SHA").write_text(SOURCE + "\n", encoding="ascii")
    (args.out / "RELEASE_SOURCE_TREE").write_text(TREE + "\n", encoding="ascii")
    test_dir = args.out / "test-inputs"
    test_dir.mkdir()
    for relative, name in TEST_INPUTS.items():
        shutil.copyfile(args.build / relative, test_dir / name)
    shutil.copyfile(args.codegen, args.out / "codegen.json")
    native_tests = {name: digest(test_dir / name) for name in TEST_INPUTS.values()}
    receipt = {"schema": 1, "release_tag": TAG, "crt": args.crt, "source": SOURCE, "tree": TREE,
               "depends": DEPENDS, "runtime_sha256": release, "installer_members_sha256": members,
               "test_inputs_sha256": native_tests, "codegen_sha256": digest(args.out / "codegen.json"),
               "notice_reference_sha256": NOTICE_SHA}
    if args.crt == "ucrt":
        notice = NOTICE_STEM + ".zip"
        make_zip(args.out / notice, notices, stamp)
        receipt["windows_notices"] = {notice: digest(args.out / notice)}
        (args.out / "SHA256SUMS.notices").write_text(sha_manifest(receipt["windows_notices"]), encoding="ascii")
    write_json(args.out / "windows-build.json", receipt)


def verify(args):
    pin(args.source)
    receipt = json.loads((args.staged / "windows-build.json").read_bytes())
    require((receipt["schema"], receipt["release_tag"], receipt["crt"], receipt["source"], receipt["tree"], receipt["depends"]) ==
            (1, TAG, args.crt, SOURCE, TREE, DEPENDS), "Package receipt does not identify the exact product")
    require((args.staged / "RELEASE_SOURCE_SHA").read_text().strip() == SOURCE and
            (args.staged / "RELEASE_SOURCE_TREE").read_text().strip() == TREE and
            digest(args.staged / "codegen.json") == receipt["codegen_sha256"], "Source marker or code generation evidence differs")
    runtime = receipt["runtime_sha256"]
    require(set(runtime) == set(asset_names(args.crt)) and all(digest(args.staged / p) == sh for p, sh in runtime.items()) and
            (args.staged / "SHA256SUMS").read_text() == sha_manifest(runtime), "Windows runtime checksums differ")
    if args.crt == "ucrt":
        notices = receipt["windows_notices"]
        require(set(notices) == {NOTICE_STEM + ".zip"} and all(digest(args.staged / p) == sh for p, sh in notices.items()) and
                (args.staged / "SHA256SUMS.notices").read_text() == sha_manifest(notices), "Standalone notices differ")
    return receipt


def prepare(args):
    require(platform.system() == "Windows" and platform.machine() in ("AMD64", "x86_64"), "Expected native Windows AMD64")
    receipt = verify(args)
    portable, setup = asset_names(args.crt)
    windows_pe(args.staged / setup, amd64=False)
    source = args.source.resolve(strict=True)
    bindir = source / "bin"
    bindir.mkdir()
    members = receipt["installer_members_sha256"]
    require(set(members) == set(PROGRAMS), "Unexpected installer executable inventory")
    with zipfile.ZipFile(args.staged / portable) as package:
        for relative in PROGRAMS:
            member = f"{Path(portable).stem}/{relative}"
            binary = bindir / Path(relative).name
            size = package.getinfo(member).file_size
            require(0 < size <= 128 << 20, f"Invalid portable program size: {member}")
            with package.open(member) as incoming, binary.open("xb") as target:
                shutil.copyfileobj(incoming, target, 1 << 20)
            require(digest(binary) == members[relative], f"Portable executable differs from setup: {relative}")
            windows_pe(binary)
    test_inputs = receipt["test_inputs_sha256"]
    require(set(test_inputs) == set(TEST_INPUTS.values()), "Unexpected focused test-input inventory")
    for relative, name in TEST_INPUTS.items():
        built = args.staged / "test-inputs" / name
        require(digest(built) == test_inputs[name], f"Focused test input checksum differs: {name}")
        shutil.copyfile(built, source / relative)
    windows_pe(bindir / "test_bitcoin.exe")
    config = source / "test/config.ini"
    replacements = {"SRCDIR": source, "BUILDDIR": source, "RPCAUTH": source / "share/rpcauth/rpcauth.py"}
    lines = config.read_text(encoding="utf-8").splitlines()
    for name, value in replacements.items():
        require(sum(line.startswith(f"{name}=") for line in lines) == 1, f"Missing test configuration key: {name}")
        lines = [f"{name}={value}" if line.startswith(f"{name}=") else line for line in lines]
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")


def conclude(args):
    receipt = verify(args)
    evidence = {name: digest(args.logs / name) for name in LOGS}
    counts = {}
    for name in LOGS[:3]:
        log = (args.logs / name).read_bytes()
        executed = re.search(rb"Running (\d+) test cases?\.\.\.", log)
        require(executed and int(executed[1]) > 0 and re.search(rb'Test module "[^"\r\n]+" has passed with:', log),
                f"Focused success missing from {name}")
        counts[name] = int(executed[1])
    require(counts[LOGS[1]] == counts[LOGS[2]] == 1, "Unexpected crypto case selection")
    version = (args.logs / "binary-version.log").read_text(encoding="utf-8")
    require(SOURCE[:12] in version or TAG in version, "Packaged daemon does not identify the final product")
    write_json(args.staged / "windows-native.json", {"schema": 1, "status": "passed", "crt": args.crt,
               "source": SOURCE, "tree": TREE, "run_id": args.run_id,
               "build_receipt_sha256": digest(args.staged / "windows-build.json"), "runtime_sha256": receipt["runtime_sha256"],
               "installer_members_sha256": receipt["installer_members_sha256"], "unit_test_cases": counts,
               "test_logs_sha256": evidence})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, action in (("stage", stage), ("prepare", prepare), ("conclude", conclude)):
        command = commands.add_parser(name)
        command.set_defaults(action=action)
        command.add_argument("--source", required=True, type=Path)
        command.add_argument("--crt", required=True, choices=("ucrt", "msvcrt"))
        if name == "stage":
            for argument in ("build", "out", "notices", "codegen"):
                command.add_argument(f"--{argument}", required=True, type=Path)
            command.add_argument("--seven-zip", required=True)
        else:
            command.add_argument("--staged", required=True, type=Path)
            if name == "conclude":
                command.add_argument("--logs", required=True, type=Path)
                command.add_argument("--run-id", required=True)
    options = parser.parse_args()
    options.action(options)

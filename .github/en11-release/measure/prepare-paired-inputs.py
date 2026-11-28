#!/usr/bin/env python3
"""Prepare signed En.10 and exact candidate packages for native paired tests."""

import argparse
import gzip
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

BASELINE_SOURCE = "409ea3ee5f1cdb03790ec2adf5e191031a28737f"
BASELINE_TREE = "578110fc4d33962ed429171addc1d09cf5d5906f"
BASELINE_REPOSITORY = "decryp2kanon/sugarchain-en"
BASELINE_TAG = "v31.1.2-en.10"
BASELINE_PINS_SHA = "5f92879169479c1cc29d7d985d2768d7a6bac85b4c13905422fda2510297889b"
BASELINE_SIGNED_SUMS_SHA = "e900138702a377c40e7234f7e33af8ddf09de7ab7f5c8c1cc29f422cb3e9e959"
MAX_JSON_BYTES = 1 << 20
MAX_ARCHIVE_BYTES = 256 << 20
MAX_EXPANDED_BYTES = 256 << 20
MAX_MEMBERS = 512
SHA256 = re.compile(r"[a-f0-9]{64}")
GIT_OID = re.compile(r"[a-f0-9]{40}")
VERSION = r"[0-9]+\.[0-9]+\.[0-9]+"
RESERVED = {"con", "prn", "aux", "nul"} | {f"{p}{i}" for p in ("com", "lpt") for i in range(1, 10)}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def regular_size(path, limit):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit, f"Invalid regular file or size: {path}")
    return info.st_size


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def json_input(path):
    regular_size(path, MAX_JSON_BYTES)
    return json.loads(path.read_bytes())


def verify_asset(path, expected, size=None):
    require(isinstance(expected, str) and SHA256.fullmatch(expected), f"Invalid SHA-256 pin: {path.name}")
    actual_size = regular_size(path, MAX_ARCHIVE_BYTES)
    require(size is None or size == actual_size, f"Asset size mismatch: {path.name}")
    require(digest(path) == expected, f"Asset digest mismatch: {path.name}")


def baseline_pins(path):
    regular_size(path, MAX_JSON_BYTES)
    # Treat Git's LF/CRLF checkout conversion as text encoding only. The
    # canonical bytes must still be the exact independently verified pin file.
    canonical = path.read_bytes().replace(b"\r\n", b"\n")
    require(hashlib.sha256(canonical).hexdigest() == BASELINE_PINS_SHA, "Signed baseline pin file digest mismatch")
    record = json.loads(canonical)
    require((record["schema"], record["repository"], record["tag"], record["source"],
             record["sha256sums_sha256"]) == (1, BASELINE_REPOSITORY, BASELINE_TAG, BASELINE_SOURCE,
                                            BASELINE_SIGNED_SUMS_SHA), "Baseline release identity mismatch")
    return record["assets"]


def verify_baseline_signature(tools, keyring, directory, local, names, pins):
    expected = "bf5767544dc7c39dfbde6721a83b5c61625c04a355b00d4619ead56ee21e50de"
    require(digest(tools) == expected, "Baseline signature verifier differs")
    definition = spec_from_file_location("published_en10_support", tools)
    module = module_from_spec(definition)
    definition.loader.exec_module(module)
    directory.mkdir()
    signed = {name:module.download(name,directory,sha,local) for name,sha in module.SIGNED_FILES.items()}
    declarations = module.verify_signature(signed["SHA256SUMS"],signed["SHA256SUMS.asc"],keyring,directory)
    for name in names:
        require(declarations.get(name) == pins[name]["sha256"], f"Signed baseline pin differs: {name}")


def release_names(platform, crt, version="31.1.2"):
    if platform == "windows":
        prefix = f"sugarchain-en-{version}-windows-x86_64-{crt}"
        return [f"{prefix}-portable.zip", f"{prefix}-setup.exe"]
    prefix = f"sugarchain-en-{version}-macos-x86_64"
    return [f"{prefix}-cli.tar.gz", f"{prefix}.zip"]


def check_candidate(directory, platform, crt, source, tree):
    if platform == "windows":
        build_path = directory / "windows-build.json"
        build = json_input(build_path)
        receipt = json_input(directory / "windows-native.json")
        require((build["schema"], build["source"], build["tree"], build["crt"]) == (1, source, tree, crt),
                "Windows build receipt identity mismatch")
        require((receipt["schema"], receipt["status"], receipt["source"], receipt["tree"], receipt["crt"]) ==
                (1, "passed", source, tree, crt), "Windows native receipt identity mismatch")
        require(receipt["build_receipt_sha256"] == digest(build_path), "Windows native/build receipt binding mismatch")
        require(receipt["runtime_sha256"] == build["runtime_sha256"] and
                receipt["installer_members_sha256"] == build["installer_members_sha256"],
                "Windows native archive or installer inventory mismatch")
        for name, expected in (("RELEASE_SOURCE_SHA", source), ("RELEASE_SOURCE_TREE", tree)):
            marker = directory / name
            regular_size(marker, 128)
            require(marker.read_text(encoding="ascii").strip() == expected, f"Windows marker mismatch: {name}")
        asset_hashes = receipt["runtime_sha256"]
        members = receipt["installer_members_sha256"]
        windows_version = re.fullmatch(rf"v({VERSION})-en\.[0-9]+", build["release_tag"])
        require(windows_version and build["release_tag"] == "v31.1.2-en.11", "Wrong Windows candidate release tag")
        names = release_names(platform, crt, windows_version[1])
    else:
        receipt = json_input(directory / "macos-x86_64-provenance.json")
        require((receipt["schema"], receipt["status"], receipt["platform"], receipt["arch"],
                 receipt["source_sha"], receipt["source_tree"], receipt["code_signature"]) ==
                (1, "verified_release_packages", "macos", "x86_64", source, tree, "ad-hoc"),
                "macOS native release receipt identity mismatch")
        asset_hashes = receipt["assets"]
        members = {}
        versions = [match[1] for name in asset_hashes
                    if (match := re.fullmatch(rf"sugarchain-en-({VERSION})-macos-x86_64-cli\.tar\.gz", name))]
        require(len(versions) == 1, "macOS candidate CLI archive name is ambiguous")
        names = release_names(platform, crt, versions[0])
    raw_run_id = receipt["run_id"]
    require(type(raw_run_id) in (int, str) and re.fullmatch(r"[1-9][0-9]{0,17}", str(raw_run_id)),
            "Invalid native build run ID")
    require(set(asset_hashes) == set(names), "Unexpected candidate runtime asset inventory")
    for name in names:
        verify_asset(directory / name, asset_hashes[name])
    return names, asset_hashes, members, int(raw_run_id)


def copy_baseline(name, pin, destination, local):
    size = pin["bytes"]
    url = f"https://github.com/{BASELINE_REPOSITORY}/releases/download/{BASELINE_TAG}/{name}"
    require(type(size) is int and 0 < size <= MAX_ARCHIVE_BYTES and pin["url"] == url,
            f"Invalid baseline asset metadata: {name}")
    if local:
        verify_asset(local / name, pin["sha256"], size)
        shutil.copyfile(local / name, destination)
    else:
        request = urllib.request.Request(url, headers={"User-Agent": "Sugarchain-native-paired-preparation"})
        with urllib.request.urlopen(request, timeout=45) as response, destination.open("xb") as target:
            final = urllib.parse.urlsplit(response.url)
            require(final.scheme == "https" and final.hostname in {
                "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"},
                "Unexpected release redirect destination")
            write_exact(response, target, size)
    verify_asset(destination, pin["sha256"], size)


def write_exact(source, target, size):
    remaining = size
    while remaining:
        chunk = source.read(min(remaining, 1 << 20))
        require(chunk, "Truncated input stream")
        target.write(chunk)
        remaining -= len(chunk)
    require(not source.read(1), "Input stream exceeds declared length")


def member_parts(name):
    if name.endswith("/"):
        name = name[:-1]
    parts = name.split("/")
    require(len(name) <= 512 and len(parts) <= 20, "Oversized archive path")
    for part in parts:
        require(re.fullmatch(r"[A-Za-z0-9_+(). -]{1,128}", part) and
                part not in {".", ".."} and part[-1] not in " ." and
                part.split(".", 1)[0].lower() not in RESERVED,
                f"Unsafe archive path: {name!r}")
    return tuple(parts)


class Extraction:
    def __init__(self, root):
        self.root = root
        root.mkdir()
        self.names = set()
        self.parents = {}
        self.bytes = 0

    def add(self, name, is_dir, size, mode, stream=None):
        parts = member_parts(name)
        require(parts not in self.names and len(self.names) < MAX_MEMBERS, f"Duplicate or excess archive member: {name}")
        self.names.add(parts)
        self.bytes += size
        require(0 <= size <= MAX_EXPANDED_BYTES and self.bytes <= MAX_EXPANDED_BYTES,
                "Expanded archive exceeds byte limit")
        for end in range(1, len(parts) + 1):
            prefix = parts[:end]
            lookup = tuple(part.casefold() for part in prefix)
            expected = (prefix, end < len(parts) or is_dir)
            require(self.parents.setdefault(lookup, expected) == expected, f"Archive path collision: {name}")
        output = self.root.joinpath(*parts)
        if is_dir:
            require(size == 0, f"Nonempty archive directory: {name}")
            output.mkdir(exist_ok=True, parents=True)
            return
        output.parent.mkdir(exist_ok=True, parents=True)
        with output.open("xb") as target:
            write_exact(stream, target, size)
        output.chmod(0o755 if mode & 0o111 else 0o644)


class BoundedTarStream:
    def __init__(self, stream):
        self.stream = stream
        self.remaining = MAX_EXPANDED_BYTES

    def read(self, size):
        require(0 <= size <= self.remaining, "Expanded tar stream exceeds byte limit")
        data = self.stream.read(size)
        self.remaining -= len(data)
        return data


def extract_package(path, destination):
    output = Extraction(destination)
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            require(0 < len(infos) <= MAX_MEMBERS, "Invalid ZIP member count")
            for member in infos:
                require(member.orig_filename == member.filename, "Truncated ZIP path")
                mode = member.external_attr >> 16
                directory = member.is_dir()
                require(stat.S_IFMT(mode) in (0, stat.S_IFDIR if directory else stat.S_IFREG),
                        f"Special ZIP member: {member.filename}")
                if directory:
                    output.add(member.filename, True, member.file_size, mode)
                else:
                    with archive.open(member) as stream:
                        output.add(member.filename, False, member.file_size, mode, stream)
        return
    require(path.name.endswith(".tar.gz"), f"Unknown archive kind: {path.name}")
    with gzip.open(path, "rb") as decompressed, tarfile.open(fileobj=BoundedTarStream(decompressed), mode="r|") as archive:
        for member in archive:
            require((member.isfile() or member.isdir()) and not member.issparse(),
                    f"Special tar member: {member.name}")
            if member.isdir():
                output.add(member.name, True, member.size, member.mode)
            else:
                with archive.extractfile(member) as stream:
                    output.add(member.name, False, member.size, member.mode, stream)
    require(output.names, "Empty CLI archive")


def verify_program(path, platform):
    regular_size(path, MAX_EXPANDED_BYTES)
    with path.open("rb") as stream:
        header = stream.read(64)
        if platform == "windows":
            require(len(header) == 64 and header[:2] == b"MZ", f"Invalid PE: {path}")
            offset = struct.unpack_from("<I", header, 60)[0]
            require(64 <= offset <= 65536, f"Invalid PE header offset: {path}")
            stream.seek(offset)
            pe = stream.read(26)
            require(len(pe) == 26 and pe[:6] == b"PE\0\0\x64\x86" and pe[24:] == b"\x0b\x02",
                    f"Not an AMD64 PE32+ program: {path}")
        else:
            require(header[:8] == b"\xcf\xfa\xed\xfe\x07\x00\x00\x01" and path.stat().st_mode & 0o111,
                    f"Not an executable x86_64 Mach-O: {path}")
    return digest(path)


def role(path, archive, archive_hash, platform, member_hash=None):
    executable_hash = verify_program(path, platform)
    require(member_hash is None or member_hash == executable_hash, f"Installer/portable member digest mismatch: {path.name}")
    return {"path": str(path), "sha256": executable_hash, "archive_sha256": archive_hash, "archive_path": str(archive)}


def unpack_roles(root, platform, names, hashes, members=None):
    archives = root / "archives"
    first = archives / names[0]
    extract_package(first, root / "programs")
    if platform == "windows":
        program_dir = root / "programs" / first.stem
        daemon = "daemon/sugarchaind.exe"
        gui = "sugarchain-qt.exe"
        if members is not None:
            require(daemon in members and gui in members, "Windows installer executable evidence missing")
        return (role(program_dir / daemon, first, hashes[first.name], platform, members[daemon] if members else None),
                role(program_dir / gui, first, hashes[first.name], platform, members[gui] if members else None))
    second = archives / names[1]
    extract_package(second, root / "application")
    app = root / "application" / "Sugarchain-Qt.app"
    daemon = root / "programs" / first.name.removesuffix(".tar.gz") / "bin/sugarchaind"
    gui = app / "Contents/MacOS/Sugarchain-Qt"
    execute = (role(daemon, first, hashes[first.name], platform), role(gui, second, hashes[second.name], platform))
    if sys.platform == "darwin":
        for path in (daemon, app):
            subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(path)], check=True, timeout=45)
    return execute


def write_manifest_pair(output, platform, source, tree, baseline_roles, candidate_roles):
    for index, interface in enumerate(("cli", "gui")):
        receipt = {
            "schema": 1, "platform": platform, "arch": "x86_64", "interface": interface,
            "baseline": {"source": BASELINE_SOURCE, "tree": BASELINE_TREE,
                         "sender": baseline_roles[0], "receiver": baseline_roles[index]},
            "candidate": {"source": source, "tree": tree,
                          "sender": candidate_roles[0], "receiver": candidate_roles[index]},
        }
        (output / f"{interface}.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("windows", "macos"), required=True)
    parser.add_argument("--crt", choices=("ucrt", "msvcrt"))
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--baseline-pins", type=Path, required=True)
    parser.add_argument("--release-tools", type=Path, required=True)
    parser.add_argument("--keyring", type=Path, required=True)
    parser.add_argument("--baseline-assets", type=Path, help="Use local copies of the pinned baseline release assets")
    parser.add_argument("--candidate-source", required=True)
    parser.add_argument("--candidate-tree", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require((args.platform == "windows") == bool(args.crt), "--crt is required only for Windows")
    require(GIT_OID.fullmatch(args.candidate_source) and GIT_OID.fullmatch(args.candidate_tree) and
            args.candidate_source != BASELINE_SOURCE and args.candidate_tree != BASELINE_TREE,
            "Invalid or baseline candidate source/tree")
    names, candidate_hashes, members, run_id = check_candidate(args.candidate_dir, args.platform, args.crt,
                                                             args.candidate_source, args.candidate_tree)
    pins = baseline_pins(args.baseline_pins)
    baseline_names = release_names(args.platform, args.crt)
    if args.platform == "windows":
        names = names[:1]
        baseline_names = baseline_names[:1]
    require(str(run_id) == os.environ["GITHUB_RUN_ID"], "Candidate producer must be the actual current native run")
    args.output.mkdir()
    output = args.output.resolve(strict=True)
    for side in ("baseline", "candidate"):
        (output / side / "archives").mkdir(parents=True)
    verify_baseline_signature(args.release_tools,args.keyring,output/"baseline-signature",args.baseline_assets,
                              baseline_names,pins)
    for name in names:
        staged = output / "candidate" / "archives" / name
        shutil.copyfile(args.candidate_dir / name, staged)
        verify_asset(staged, candidate_hashes[name])
    for name in baseline_names:
        copy_baseline(name, pins[name], output / "baseline" / "archives" / name, args.baseline_assets)
    baseline_hashes = {name: pins[name]["sha256"] for name in baseline_names}
    base_roles = unpack_roles(output / "baseline", args.platform, baseline_names, baseline_hashes)
    new_roles = unpack_roles(output / "candidate", args.platform, names, candidate_hashes,
                             members if args.platform == "windows" else None)
    write_manifest_pair(output, args.platform, args.candidate_source, args.candidate_tree, base_roles, new_roles)
    print(f"Prepared byte-verified CLI and GUI packages from native candidate run {run_id}: {output}")


if __name__ == "__main__":
    main()

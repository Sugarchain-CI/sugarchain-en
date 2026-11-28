"""Verify transferred macOS inputs and bind the final release payloads."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re


CROSS_FILES = {"app.zip", "cli.tar.gz", "test_bitcoin", "release-source-sha.txt", "release-source-tree.txt"}
CROSS_MANIFEST = "SHA256SUMS.cross-inputs"
VALIDATION_LOGS = ("native-tests.log", "native-datadir.log", "native-runtime.log", "protocol/functional.log")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size > 0, f"Missing regular payload: {path}")
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def check_cross(directory):
    require({p.name for p in directory.iterdir()} == CROSS_FILES | {CROSS_MANIFEST}, "Unexpected cross artifact members")
    manifest = directory / CROSS_MANIFEST
    require(manifest.is_file() and not manifest.is_symlink(), "Missing regular cross manifest")
    hashes = {}
    for line in manifest.read_text().splitlines():
        row = re.fullmatch(r"([0-9a-f]{64})  ([\w.-]+)", line, re.ASCII)
        require(row and row[2] in CROSS_FILES and row[2] not in hashes, "Invalid cross checksum row")
        hashes[row[2]] = row[1]
    require(hashes.keys() == CROSS_FILES, "Incomplete cross checksum set")
    for file, sha in hashes.items():
        require(digest(directory / file) == sha, f"Cross checksum differs: {file}")
    require((directory / "release-source-sha.txt").read_text().strip() == os.environ["RELEASE_SOURCE"],
            "Cross-build source commit differs")
    require((directory / "release-source-tree.txt").read_text().strip() == os.environ["RELEASE_TREE"],
            "Cross-build source tree differs")
    return hashes


def finalize(release, arch, work, incoming):
    prefix = f"sugarchain-en-31.1.2-macos-{arch}"
    names = [f"{prefix}-cli.tar.gz", f"{prefix}.zip"]
    require({p.name for p in release.iterdir()} == set(names), "Unexpected release package members")
    assets = {name: digest(release / name) for name in names}
    record = {
        "schema": 1,
        "status": "verified_release_packages",
        "platform": "macos",
        "arch": arch,
        "source_sha": os.environ["RELEASE_SOURCE"],
        "source_tree": os.environ["RELEASE_TREE"],
        "workflow_sha": os.environ["GITHUB_SHA"],
        "run_id": int(os.environ["GITHUB_RUN_ID"]),
        "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
        "native_host": platform.platform(),
        "code_signature": "ad-hoc",
        "apple_notarized": False,
        "assets": assets,
        "cross_input_sha256": check_cross(incoming),
        "validation_log_sha256": {name: digest(work / name) for name in VALIDATION_LOGS},
        "validation": ["native_architecture", "strict_signature", "focused_units", "header_pow_protocol",
                       "native_datadir_sharing", "offline_mainnet_and_regtest_startup"],
    }
    (release / "SHA256SUMS.release-inputs").write_text(
        "".join(f"{sha}  {name}\n" for name, sha in assets.items()), encoding="ascii")
    (release / f"macos-{arch}-provenance.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("verify-cross", "finalize"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("arch", choices=("arm64", "x86_64"))
    parser.add_argument("--work", type=Path)
    parser.add_argument("--incoming", type=Path)
    args = parser.parse_args()
    if args.action == "verify-cross":
        check_cross(args.directory)
    else:
        if args.work is None or args.incoming is None:
            parser.error("Finalization requires the validation and cross-input directories")
        finalize(args.directory, args.arch, args.work, args.incoming)


if __name__ == "__main__":
    main()

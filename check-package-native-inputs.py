#!/usr/bin/env python3
"""Verify the failed-gate Intel package without modifying its signed bytes."""
import hashlib
import json
from pathlib import Path
import tarfile

SOURCE = "8400a011d8d4879fb606d50c263b6e4801213605"
TREE = "5f379fc7f32383077053a5d4cb47414ce53af5f2"
PREFIX = "sugarchain-en-31.1.2-macos-x86_64-cli"
ARCHIVE_HASH = "57de3c41d12818c4c4cd491b87b0d1d4f8f2be6862ddab63643d875c8e9a00bc"
DAEMON_HASH = "dbeaded1222b46af40b534122c06d27d79e6dfaa3871ff3e151a46061a142972"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify(folder):
    assert (folder / "release-source-sha.txt").read_text().strip() == SOURCE
    assert (folder / "release-source-tree.txt").read_text().strip() == TREE
    manifest = {}
    for line in (folder / "package.sha256").read_text().splitlines():
        sha, name = line.split("  ")
        assert name not in manifest and Path(name).name == name
        assert digest(folder / name) == sha, name
        manifest[name] = sha
    assert set(manifest) == {
        PREFIX + ".tar.gz", "sugarchain-en-31.1.2-macos-x86_64.zip",
        "release-source-sha.txt", "release-source-tree.txt", "regtest-benchmark.json",
    }
    assert manifest[PREFIX + ".tar.gz"] == ARCHIVE_HASH
    with tarfile.open(folder / (PREFIX + ".tar.gz")) as archive:
        members = [entry for entry in archive if entry.name == PREFIX + "/bin/sugarchaind"]
        assert len(members) == 1 and members[0].isfile()
        with archive.extractfile(members[0]) as daemon:
            assert hashlib.file_digest(daemon, "sha256").hexdigest() == DAEMON_HASH
    record = json.loads((folder / "regtest-benchmark.json").read_text())
    assert record["variants"]["candidate"]["binary_sha256"] == DAEMON_HASH
    assert record["variants"]["candidate"]["archive_sha256"] == ARCHIVE_HASH
    print("Verified exact packaged source, archive and signed daemon hashes")


if __name__ == "__main__":
    import sys
    verify(Path(sys.argv[1]))

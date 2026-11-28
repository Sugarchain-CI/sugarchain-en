#!/usr/bin/env python3
"""Collect only expected macOS/Windows benchmark receipts and owned-node logs."""

import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path
import stat
import tarfile

MAX_FILE_BYTES = 16 * 1024**2
MAX_TOTAL_BYTES = 256 * 1024**2


def trial_evidence(root):
    yield root / "result.json"
    for role in ("sender", "receiver"):
        for log in ("debug.log", "console.log"):
            yield root / role / log


def allowed_paths():
    yield from map(Path, (
        "adapter-result.json", "package-identity.json", "cli-driver.log", "gui-driver.log",
        "signature/gpgv.log", "signature/verification.json",
        "release/release-signature-verification.json", "release/release-signature-status.log",
    ))
    for mode in ("cli", "gui"):
        root = Path(mode)
        yield root / "result.json"
        for slot in range(1, 4):
            trial = f"trial-{slot:02d}"
            yield from trial_evidence(root / trial)
            for crt in ("ucrt", "msvcrt"):
                for package in ("portable", "installer"):
                    case = Path("measurements") / f"{mode}-{slot:02d}-{crt}-{package}"
                    yield case.with_suffix(".log")
                    yield case.with_suffix(".adapter.json")
                    yield case / "result.json"
                    yield from trial_evidence(case / "trial-01")


def regular_file(root, relative):
    path = root / relative
    for node in reversed(path.parents[:len(relative.parts)]):
        try:
            info = node.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISDIR(info.st_mode) or node.is_symlink():
            raise ValueError(f"Unsafe evidence directory: {node.name}")
        is_junction = getattr(node, "is_junction", None)
        if is_junction is not None and is_junction():
            raise ValueError(f"Unexpected evidence junction: {node.name}")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError(f"Expected a regular evidence file with one link: {relative.as_posix()}")
    if info.st_size > MAX_FILE_BYTES:
        raise ValueError(f"Evidence file exceeds limit: {relative.as_posix()}")
    return path, info.st_size


def collect(root, output):
    if root.resolve() == output.resolve() or output.resolve().is_relative_to(root.resolve()):
        raise ValueError("Use a distinct evidence output outside the run tree")
    entries = []
    total = 0
    for relative in sorted(allowed_paths()):
        info = regular_file(root, relative)
        if info is not None:
            path, size = info
            entries.append((relative, path, size))
            total += size
            if total > MAX_TOTAL_BYTES:
                raise ValueError("Evidence exceeds total size cap")
    output.mkdir(mode=0o700)
    archive = output / "evidence.tar.gz"
    files = []
    with tarfile.open(archive, "x:gz", compresslevel=6) as stream:
        for relative, path, expected_size in entries:
            payload = path.read_bytes()
            if len(payload) != expected_size:
                raise ValueError(f"Evidence changed during collection: {relative.as_posix()}")
            member = tarfile.TarInfo(relative.as_posix())
            member.size = len(payload)
            member.mode = 0o600
            stream.addfile(member, BytesIO(payload))
            files.append({"name": member.name, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
    with archive.open("rb") as stream:
        archive_sha = hashlib.file_digest(stream, "sha256").hexdigest()
    receipt = {"schema": 1, "status": "collected" if files else "empty", "file_count": len(files),
               "uncompressed_bytes": total, "archive_bytes": archive.stat().st_size, "sha256": archive_sha,
               "files": files}
    (output / "collection.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: receipt[key] for key in ("status", "file_count", "uncompressed_bytes", "sha256")}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    collect(args.input.absolute(), args.output.absolute())


if __name__ == "__main__":
    main()

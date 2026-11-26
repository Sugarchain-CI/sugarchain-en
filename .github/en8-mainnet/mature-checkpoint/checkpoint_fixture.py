"""Receive a checksum-pinned public chain fixture into a new owned datadir."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import time

CHECKPOINT = {
    "height": 44_946_197,
    "hash": "e67e0b48cb20a99db213f2618001d9c43a8c40dfa33a1ea6bf057c9644cf50cf",
    "utxo_hash": "bbf9db53b89be011b67f5fdc246292a534e41f292cde07f949f7994c04b2ec1a",
    "txouts": 7_268_394,
    "total_amount": "979500524.16225280",
}
DATA_ROOTS = {"blocks", "chainstate"}
DATABASE = re.compile(r"CURRENT|LOCK|MANIFEST-[0-9]+|[0-9]+\.(?:ldb|sst|log)")
FLATFILES = {"blk00169.dat", "rev00169.dat", "xor.dat"}
CURRENT = re.compile(rb"(MANIFEST-[0-9]+)\n")
SHA = re.compile(r"[0-9a-f]{64}")
COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
DECOMPRESSORS = {"tar": "r|", "tar.gz": "r|gz", "tar.zst": "r|zst"}
DISK_RESERVE = 8 << 30


class QualificationError(RuntimeError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def require(value, message):
    if not value:
        raise QualificationError("fixture_integrity_failure", message)


def load_manifest(path, expected_sha):
    require(SHA.fullmatch(expected_sha), "Supply the full approved fixture manifest SHA-256")
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected_sha, "Public fixture manifest SHA-256 differs")
    metadata = json.loads(raw)
    require(isinstance(metadata, dict), "Expected a checkpoint manifest object")
    require(metadata.get("schema") == 1 and metadata.get("checkpoint") == CHECKPOINT,
            "Unexpected public checkpoint identity or manifest schema")
    require(metadata.get("archive_format") in DECOMPRESSORS, "Unsupported checkpoint archive format")
    size = metadata.get("unpacked_file_bytes")
    require(type(size) is int and size > 0, "Missing positive uncompressed fixture byte count")
    parts = metadata.get("archive_parts")
    require(isinstance(parts, list) and parts, "Missing checkpoint archive parts")
    names = set()
    for part in parts:
        name = part.get("name")
        require(isinstance(name, str) and COMPONENT.fullmatch(name) and name.casefold() not in names,
                "Invalid or duplicate checkpoint archive member")
        count = part.get("bytes")
        require(type(count) is int and 0 < count <= 1 << 30 and SHA.fullmatch(part.get("sha256", "")),
                f"Invalid checkpoint archive size/checksum metadata for {name}")
        names.add(name.casefold())
    members = metadata.get("file_members")
    require(isinstance(members, list) and members, "Missing public fixture file manifest")
    total = 0
    names = set()
    for entry in members:
        name = entry["name"]
        count = entry["bytes"]
        relative = member_path(name)
        require(regular_member(relative) and relative.as_posix().casefold() not in names
                and type(count) is int and count >= 0 and SHA.fullmatch(entry.get("sha256", "")),
                f"Unexpected or duplicate fixture file manifest entry: {name}")
        names.add(relative.as_posix().casefold())
        total += count
    require(total == size, "Manifest file sizes differ from the recorded expansion")
    return metadata


class CheckedArchive(io.RawIOBase):
    """Verify each compressed part on its open descriptor before passing it to tarfile."""

    def __init__(self, folder, parts, deadline):
        self.folder = folder
        self.parts = iter(parts)
        self.deadline = deadline
        self.current = None

    def readable(self):
        return True

    def check_deadline(self):
        if time.monotonic() >= self.deadline:
            raise QualificationError("extract_timeout", "Public checkpoint extraction exceeded its budget")

    def open_verified(self, info):
        self.current = (self.folder / info["name"]).open("rb")
        require(os.fstat(self.current.fileno()).st_size == info["bytes"], f"Archive size differs for {info['name']}")
        checksum = hashlib.sha256()
        count = 0
        while chunk := self.current.read(1 << 20):
            self.check_deadline()
            checksum.update(chunk)
            count += len(chunk)
        require(count == info["bytes"] and checksum.hexdigest() == info["sha256"],
                f"Archive checksum differs for {info['name']}")
        self.current.seek(0)

    def readinto(self, buffer):
        while True:
            self.check_deadline()
            if self.current is None:
                info = next(self.parts, None)
                if info is None:
                    return 0
                self.open_verified(info)
            count = self.current.readinto(buffer)
            if count:
                return count
            self.current.close()
            self.current = None

    def close(self):
        if self.current is not None:
            self.current.close()
        super().close()


def member_path(name):
    name = name.removeprefix("./").rstrip("/")
    path = PurePosixPath(name)
    require(path.parts and path.parts[0] in DATA_ROOTS and path.as_posix() == name
            and all(COMPONENT.fullmatch(part) for part in path.parts), f"Non-public or unsafe fixture member {name!r}")
    return path


def regular_member(path):
    parts = path.parts
    if parts[:-1] == ("blocks",):
        return parts[-1] in FLATFILES
    return parts[:-1] in (("blocks", "index"), ("chainstate",)) and bool(DATABASE.fullmatch(parts[-1]))


def verify_current(directory):
    current = directory / "CURRENT"
    require(current.is_file(), f"Missing LevelDB CURRENT in {directory.name}")
    with current.open("rb") as handle:
        manifest = CURRENT.fullmatch(handle.read(65))
        require(manifest and not handle.read(1), f"Invalid LevelDB CURRENT in {directory.name}")
    require((directory / manifest[1].decode("ascii")).is_file(),
            f"LevelDB CURRENT names a missing local manifest in {directory.name}")


def extract(folder, manifest, profile, deadline, *, reserve=DISK_RESERVE):
    estimated = manifest["unpacked_file_bytes"]
    free = shutil.disk_usage(profile.parent).free
    if free < estimated + reserve:
        raise QualificationError("disk_capacity_inconclusive", "Insufficient disk for verified expansion and reserve")
    profile.mkdir()
    consumed = 0
    expected_files = iter(manifest["file_members"])
    files = 0
    compression = DECOMPRESSORS[manifest["archive_format"]]
    with io.BufferedReader(CheckedArchive(folder, manifest["archive_parts"], deadline), buffer_size=1 << 20) as stream:
        with tarfile.open(fileobj=stream, mode=compression, bufsize=1 << 20) as archive:
            for member in archive:
                if time.monotonic() >= deadline:
                    raise QualificationError("extract_timeout", "Public checkpoint extraction exceeded its budget")
                relative = member_path(member.name)
                destination = profile.joinpath(*relative.parts)
                if member.isdir():
                    require(relative.as_posix() in DATA_ROOTS | {"blocks/index"}, f"Unexpected checkpoint folder: {relative}")
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                require(member.isfile() and regular_member(relative), f"Unexpected entry type: {relative}")
                expected = next(expected_files, None)
                require(expected and (expected["name"], expected["bytes"]) == (relative.as_posix(), member.size),
                        f"Checkpoint file order or size differs: {relative}")
                consumed += member.size
                require(consumed <= estimated, f"Manifest size exceeded: {relative}")
                checksum = hashlib.sha256()
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, destination.open("xb") as output:
                    while chunk := source.read(1 << 20):
                        if time.monotonic() >= deadline:
                            raise QualificationError("extract_timeout", "Public checkpoint extraction exceeded its budget")
                        checksum.update(chunk)
                        output.write(chunk)
                require(destination.stat().st_size == member.size and checksum.hexdigest() == expected["sha256"],
                        f"Checkpoint file size or checksum differs: {relative}")
                files += 1
        # Tar can stop before compressed frame padding. Verify any remaining parts.
        while stream.read(1 << 20):
            pass
    require(next(expected_files, None) is None and consumed == estimated, "Checkpoint payload size differs")
    require(all((profile / "blocks" / name).is_file() for name in FLATFILES), "Missing expected checkpoint block or undo files")
    verify_current(profile / "blocks/index")
    verify_current(profile / "chainstate")
    return {"unpacked_file_bytes": consumed, "regular_files": files, "free_before_bytes": free,
            "free_after_bytes": shutil.disk_usage(profile).free}


def main():
    parser = argparse.ArgumentParser(description="Verify the checkpoint manifest and plan disk usage before download")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True, help="New directory for the preflight record and part list")
    args = parser.parse_args()
    metadata = load_manifest(args.manifest, args.manifest_sha256)
    args.output.mkdir(parents=True, exist_ok=False)
    free = shutil.disk_usage(args.output).free
    compressed = sum(part["bytes"] for part in metadata["archive_parts"])
    required = compressed + metadata["unpacked_file_bytes"] + DISK_RESERVE
    report = {"status": "ready" if free >= required else "disk_capacity_inconclusive", "disk_free_bytes": free,
              "archive_bytes": compressed, "unpacked_file_bytes": metadata["unpacked_file_bytes"],
              "reserve_bytes": DISK_RESERVE, "required_free_bytes": required, "manifest_sha256": args.manifest_sha256}
    (args.output / "preflight.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if free < required:
        raise SystemExit("Insufficient disk for compressed parts, extraction and the 8 GiB reserve")
    (args.output / "parts.txt").write_text("".join(part["name"] + "\n" for part in metadata["archive_parts"]), encoding="utf-8")


if __name__ == "__main__":
    main()

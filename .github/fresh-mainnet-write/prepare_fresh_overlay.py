#!/usr/bin/env python3
"""Build one independent pre-anchor Mainnet fixture from exact public fixture members."""

import argparse
from contextlib import contextmanager
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile

BASE_SHA = "234d86232dc76cc86045b0f6cba2988a140562a112ecbbb454e82fa3f20a30f3"
MANIFEST_SHA = "192106468fdbd61d15b6d96057d26314f54425a82f37fed6b2fb855f748e560d"
ARCHIVE_SHA = "c988648ec20751d68aa9b34686a73bb6a06b8a4d42a99702e62b4e30b31e399f"
ANCHOR = "78ab162387ae1c1274b1607e2845bfff1e6048a8400083f3b897e2e6a523d55c"
TIP = "e67e0b48cb20a99db213f2618001d9c43a8c40dfa33a1ea6bf057c9644cf50cf"
ANCHOR_HEIGHT = 44_942_101
TIP_HEIGHT = 44_946_197
ARCHIVE_BYTES = 301_713
EXPANDED_LIMIT = 1 << 20
MANIFEST_LIMIT = 256 << 10
RESERVE = 8 << 30
CHUNK = 1 << 20
DIRS = ("blocks", "blocks/index", "chainstate")
FLAT_FILES = {"blocks/blk00169.dat", "blocks/rev00169.dat", "blocks/xor.dat"}
DB_FILE = re.compile(r"(blocks/index|chainstate)/(CURRENT|LOCK|MANIFEST-[0-9]+|[0-9]+\.(ldb|sst|log))", re.ASCII)
DIGEST = re.compile(r"[0-9a-f]{64}", re.ASCII)
CURRENT = re.compile(rb"MANIFEST-[0-9]+\n")


def require(condition, explanation):
    if not condition:
        raise ValueError(explanation)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def regular(info, label):
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
            not getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT,
            f"Expected an independent regular file: {label}")


def directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and
            not getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT,
            f"Expected a plain directory: {path}")


def signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_mode, info.st_nlink, getattr(info, "st_file_attributes", 0))


def signed_input(path, digest, limit, exact_size=None):
    info = path.lstat()
    regular(info, path)
    require(info.st_size <= limit and (exact_size is None or exact_size == info.st_size), f"Unexpected byte size: {path}")
    with open_source(path, signature(info)) as stream:
        data = stream.read(limit + 1)
    require(len(data) == info.st_size and sha(data) == digest, f"Unexpected SHA-256: {path}")
    return data


def json_no_duplicates(data):
    def unique(pairs):
        result = {}
        for field, value in pairs:
            require(field not in result, f"Duplicate manifest JSON key: {field!r}")
            result[field] = value
        return result

    return json.loads(data, object_pairs_hook=unique)


def name_allowed(name):
    return isinstance(name, str) and (name in FLAT_FILES or DB_FILE.fullmatch(name) is not None)


def members(rows):
    require(isinstance(rows, list), "Expected manifest member list")
    result = {}
    for row in rows:
        require(isinstance(row, dict) and set(row) == {"name", "bytes", "sha256"}, "Invalid manifest row")
        name, size, checksum = row["name"], row["bytes"], row["sha256"]
        require(name_allowed(name) and name not in result and
                type(size) is int and 0 <= size <= 128 << 20 and
                isinstance(checksum, str) and DIGEST.fullmatch(checksum), "Invalid, duplicate or unsafe manifest member")
        if name.endswith("/LOCK"):
            require(size == 0 and checksum == sha(b""), "Manifest declares populated LevelDB lock")
        result[name] = row
    return result


def manifests(base, overlay):
    require(base["schema"] == 1 and base["archive_format"] == "tar.zst" and
            (base["checkpoint"]["height"], base["checkpoint"]["hash"]) == (TIP_HEIGHT, TIP),
            "Base checkpoint identity mismatch")
    require(overlay["schema"] == 1 and overlay["kind"] == "fresh-mainnet-tail-file-overlay" and
            overlay["base_release_tag"] == "en8-mainnet-tail-fixture-v1" and overlay["base_manifest_sha256"] == BASE_SHA and
            (overlay["anchor_height"], overlay["anchor_hash"], overlay["target_tip_height"], overlay["target_tip_hash"],
             overlay["removed_block_rows"], overlay["removed_proof_rows"]) == (ANCHOR_HEIGHT, ANCHOR, TIP_HEIGHT, TIP, 4119, 4119),
            "Fresh overlay identity mismatch")
    before = members(base["file_members"])
    after = members(overlay["file_members"])
    replacements = members(overlay["replacement_members"])
    removed = overlay["remove_members"]
    require(isinstance(removed, list) and all(name_allowed(name) for name in removed) and
            removed == sorted(set(before) - set(after)) and
            replacements == {name: row for name, row in after.items() if before.get(name) != row},
            "Overlay delta does not reconstruct the target manifest")
    require(len(before) == len(after) == 309 and len(replacements) == 7 and len(removed) == 5 and
            sum(row["bytes"] for row in before.values()) == base["unpacked_file_bytes"] and
            sum(row["bytes"] for row in replacements.values()) == 491251, "Unexpected pinned fixture shape")
    required = FLAT_FILES | {"blocks/index/CURRENT", "blocks/index/LOCK", "chainstate/CURRENT", "chainstate/LOCK"}
    require(required <= set(before) and required <= set(after) and
            not (FLAT_FILES | {"blocks/index/LOCK", "chainstate/LOCK"}) & replacements.keys(),
            "Protected raw files or lock members changed")
    return before, after, replacements


def decode_overlay(compressed, replacements):
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        decoded = stream.read(EXPANDED_LIMIT + 1)
    require(0 < len(decoded) <= EXPANDED_LIMIT and len(decoded) % 512 == 0, "Overlay expansion exceeds its hard byte cap")
    replacements_seen = {}
    end = 0
    with tarfile.open(fileobj=io.BytesIO(decoded), mode="r:") as archive:
        for member in archive:
            name = member.name
            require(name in replacements and name not in replacements_seen, "Duplicate, extra or unsafe archive member")
            require(member.offset == end and member.type == tarfile.REGTYPE and not member.linkname and
                    not member.sparse and set(member.pax_headers) <= {"mtime"} and not archive.pax_headers,
                    "Nonregular member, extra tar metadata or sparse data")
            expected = replacements[name]
            require(member.size == expected["bytes"], "Archive member length mismatch")
            with archive.extractfile(member) as stream:
                data = stream.read(expected["bytes"] + 1)
            require(len(data) == expected["bytes"] and sha(data) == expected["sha256"], "Archive member SHA-256 mismatch")
            replacements_seen[name] = data
            end = member.offset_data + (member.size + 511) // 512 * 512
    require(replacements_seen.keys() == replacements.keys() and len(decoded) - end >= 1024 and not any(decoded[end:]),
            "Missing archive members or unexpected data after end of archive")
    return replacements_seen


@contextmanager
def open_source(path, stamp):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    require(signature(path.lstat()) == stamp, f"Fixture changed before opening: {path}")
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        descriptor = signature(info)
        # Portable lstat and fstat do not expose the same optional metadata on every filesystem.
        require(stat.S_ISREG(info.st_mode) and info.st_size == stamp[2] and
                (not info.st_ino or not stamp[1] or descriptor[:2] == stamp[:2]),
                f"Fixture changed before reading: {path}")
        yield stream
        require(signature(os.fstat(stream.fileno())) == descriptor and signature(path.lstat()) == stamp,
                f"Fixture changed while reading: {path}")


def list_tree(root, expected):
    actual, pending = {}, [root]
    seen_dirs = set()
    while pending:
        folder = pending.pop()
        directory(folder)
        for path in folder.iterdir():
            name = path.relative_to(root).as_posix()
            if name in DIRS:
                directory(path)
                seen_dirs.add(name)
                pending.append(path)
                continue
            require(name in expected, f"Unexpected fixture member: {name!r}")
            info = path.lstat()
            regular(info, path)
            require(info.st_size == expected[name]["bytes"], f"Wrong fixture length: {name}")
            actual[name] = signature(info)
    require(seen_dirs == set(DIRS) and actual.keys() == expected.keys(), "Incomplete fixture tree")
    return actual


def verify_tree(root, expected):
    stamps = list_tree(root, expected)
    for name, row in expected.items():
        with open_source(root / name, stamps[name]) as stream:
            require(hashlib.file_digest(stream, "sha256").hexdigest() == row["sha256"], f"Wrong fixture SHA-256: {name}")
            if name.endswith("/CURRENT"):
                require(row["bytes"] <= 64, f"Unexpected database CURRENT size: {name}")
                stream.seek(0)
                manifest = stream.read()
                require(CURRENT.fullmatch(manifest) and
                        name.rsplit("/", 1)[0] + "/" + manifest[:-1].decode("ascii") in expected,
                        f"Invalid database CURRENT reference: {name}")
    require(list_tree(root, expected) == stamps, "Fixture was modified during audit")
    return stamps


def independent_destination(base, output, receipt):
    require(base.is_absolute() and base.resolve(strict=True) == base, "Choose an absolute canonical closed base")
    for path in (output, receipt):
        require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent and
                not os.path.lexists(path), "Output and receipt must be fresh canonical paths")
    require(base != output and base not in output.parents and output not in base.parents and
            base != receipt and base not in receipt.parents and output != receipt and output not in receipt.parents,
            "Source, output and external receipt must be separate")
    directory(base)


def build(base, output, before, after, replacements):
    require(shutil.disk_usage(output.parent).free >= sum(row["bytes"] for row in after.values()) + RESERVE,
            "Insufficient space for a new full fixture plus reserve")
    base_stamps = verify_tree(base, before)
    output.mkdir(mode=0o700)
    for folder in DIRS:
        (output / folder).mkdir(mode=0o700)
    for name, row in after.items():
        with (output / name).open("xb") as destination:
            if name in replacements:
                destination.write(replacements[name])
            else:
                with open_source(base / name, base_stamps[name]) as source:
                    shutil.copyfileobj(source, destination, CHUNK)
            destination.flush()
            os.fsync(destination.fileno())
        require((output / name).stat().st_size == row["bytes"], f"Short destination copy: {name}")
    target_stamps = verify_tree(output, after)
    source_identities = {item[:2] for item in base_stamps.values() if item[1]}
    require(not source_identities.intersection(item[:2] for item in target_stamps.values() if item[1]) and
            list_tree(base, before) == base_stamps, "Source was aliased or altered during the copy")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("base", "base-manifest", "overlay-manifest", "archive", "output", "receipt"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    independent_destination(args.base, args.output, args.receipt)
    base = json_no_duplicates(signed_input(args.base_manifest, BASE_SHA, MANIFEST_LIMIT))
    overlay = json_no_duplicates(signed_input(args.overlay_manifest, MANIFEST_SHA, MANIFEST_LIMIT))
    before, after, replacements = manifests(base, overlay)
    compressed = signed_input(args.archive, ARCHIVE_SHA, ARCHIVE_BYTES, ARCHIVE_BYTES)
    assets = decode_overlay(compressed, replacements)
    build(args.base, args.output, before, after, assets)
    result = {
        "schema": 1, "status": "fresh_overlay_verified", "datadir": str(args.output),
        "base_manifest_sha256": BASE_SHA, "overlay_manifest_sha256": MANIFEST_SHA, "archive_sha256": ARCHIVE_SHA,
        "anchor_height": ANCHOR_HEIGHT, "anchor_hash": ANCHOR, "target_tip_height": TIP_HEIGHT, "target_tip_hash": TIP,
        "full_file_count": len(after), "full_file_bytes": sum(row["bytes"] for row in after.values()),
        "replacement_file_count": len(replacements), "obsolete_file_count": len(overlay["remove_members"]),
    }
    with args.receipt.open("x") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


if __name__ == "__main__":
    main()

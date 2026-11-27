"""Bind a closed native block-index export to the authenticated canonical tail."""

from pathlib import Path
import re
import struct
import subprocess

from mature_common import ANCHOR, load_tail, require
from prepare_fresh_overlay import sha

FORK_LIST_SHA = "b2724a59fd473f006b3fbdb5168e097bed290657047b9f14eb71d33d01753c22"
REQUEST_SHA = "63d2616c77a3acf7289130e77cbff4005189fe267d4fadd580ca193d8f10f6d6"
FIXED_KEYS = (b"\x0e\x00obfuscate_key", b"f" + struct.pack("<I", 169), b"l")
ARCHIVE_LIMIT = 1 << 20
FORMAT = b"SCIDX01\n"


def key_bytes(tail):
    names = Path(__file__).with_name("absent-forks.txt").read_text(encoding="ascii").splitlines()
    require(len(names) == 23 and names == sorted(set(names)) and
            all(re.fullmatch(r"[a-f0-9]{64}", name) for name in names) and
            sha(("\n".join(names) + "\n").encode("ascii")) == FORK_LIST_SHA, "Wrong audited fork list")
    blocks = load_tail(tail)
    canonical = bytes.fromhex(ANCHOR)[::-1] + b"".join(blocks)
    forks = b"".join(bytes.fromhex(name)[::-1] for name in names)
    request = canonical + forks
    require(len(request) == 131840 and sha(request) == REQUEST_SHA, "Wrong replay index evidence request")
    return request


def validate(raw, request):
    require(len(raw) <= ARCHIVE_LIMIT and raw.startswith(FORMAT) and len(raw) >= 12,
            "Invalid native export format or size")
    hashes = [request[index:index + 32] for index in range(0, len(request), 32)]
    keys = (*FIXED_KEYS, *(prefix + item for item in hashes for prefix in (b"b", b"y")))
    count, = struct.unpack_from("<I", raw, 8)
    require(count == len(keys) == 8243, "Incorrect number of native export rows")
    offset, present = 12, 0
    for number, key in enumerate(keys):
        require(offset + 4 <= len(raw), "Truncated native export row prefix")
        found, key_size, value_size = struct.unpack_from("<BBH", raw, offset)
        offset += 4
        require(found in (0, 1) and key_size == len(key) and value_size <= 512 and
                bool(value_size) == bool(found) and offset + key_size + value_size <= len(raw) and
                raw[offset:offset + key_size] == key, "Unexpected native export key or record size")
        if number != 0:
            require(bool(found) == (number < 3 + 2 * 4097), "Unexpected native canonical or fork row presence")
        offset += key_size + value_size
        present += found
    require(offset == len(raw), "Extra native export data")
    return present


def export(binary, scratch, profile, case_dir, tail):
    request = key_bytes(tail)
    keys = case_dir / "index-key-request.bin"
    raw = case_dir / "index-export.bin"
    with keys.open("xb") as output:
        output.write(request)
    subprocess.run([str(binary), str(scratch), str(profile), str(keys), str(raw)], check=True, timeout=90)
    require(raw.stat().st_size <= ARCHIVE_LIMIT, "Native index evidence exceeds its hard size cap")
    contents = raw.read_bytes()
    present = validate(contents, request)
    return {
        "format": "SCIDX01", "export_sha256": sha(contents), "bytes": len(contents), "key_request_sha256": REQUEST_SHA,
        "fork_list_sha256": FORK_LIST_SHA, "record_count": 8243, "present_count": present, "absent_count": 8243 - present,
        "required_tail_pairs": 4096, "required_anchor_pairs": 1, "absent_fork_pairs": 23,
    }

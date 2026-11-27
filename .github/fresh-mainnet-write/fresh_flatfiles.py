"""Audit authentic fresh flat-file frames after the owned node has closed."""

import hashlib
import struct

from mature_common import MAGIC, TAIL_SHA, compact_size, hash256, load_tail, require, shown
from prepare_fresh_overlay import regular

UNDO_SHA = "cde90b366ee9d81983962ffe82b0adf7238c0f6e5ba9a1c0aedfd5d52d05799c"
REPLAY_BYTES = 1_939_122


def unxor_read(stream, length, key):
    offset = stream.tell()
    data = stream.read(length)
    require(len(data) == length, "Short newly written flat-file frame")
    return bytes(item ^ key[(offset + i) % len(key)] for i, item in enumerate(data))


def frame_read(stream, key, budget, checksum):
    require(budget >= 8, "Fresh flat-file audit byte budget exceeded")
    prefix = unxor_read(stream, 8, key)
    magic, size = struct.unpack("<4sI", prefix)
    require(magic == MAGIC and 0 < size <= budget - 8 - checksum, "Invalid new flat-file frame header")
    payload = unxor_read(stream, size + checksum, key)
    return prefix, payload


def verify(datadir, tail, body_start=124263644, undo_start=22536617):
    bodies = load_tail(tail)
    blocks = datadir / "blocks"
    expected_files = {"blk00169.dat", "rev00169.dat", "xor.dat"}
    present = {path.name for path in blocks.iterdir() if path.name.endswith(".dat")}
    require(present == expected_files, "Observed unexpected flat-file rotation for bounded fixture")
    for name in expected_files:
        regular((blocks / name).lstat(), name)
    key = (blocks / "xor.dat").read_bytes()
    require(len(key) == 8, "Unexpected fresh fixture block XOR key size")
    body_digest, undo_digest = hashlib.sha256(), hashlib.sha256()
    by_hash = {}
    positions = []
    budget = REPLAY_BYTES
    with (blocks / "blk00169.dat").open("rb") as body_file, (blocks / "rev00169.dat").open("rb") as undo_file:
        body_file.seek(body_start)
        undo_file.seek(undo_start)
        for _ in bodies:
            body_data_offset = body_file.tell() + 8
            prefix, payload = frame_read(body_file, key, budget, 0)
            require(len(payload) > 80, "Truncated body in fresh flat-file interval")
            identity = hash256(payload[:80])
            require(identity not in by_hash and bodies.get(identity) == payload,
                    "Freshly recorded block body differs from pinned requested block")
            by_hash[identity] = (body_data_offset, prefix + payload)
            budget -= len(prefix) + len(payload)
        for identity, body in bodies.items():
            body_data_offset, body_frame = by_hash[identity]
            body_digest.update(body_frame)
            undo_data_offset = undo_file.tell() + 8
            prefix, framed = frame_read(undo_file, key, budget, 32)
            payload, checksum = framed[:-32], framed[-32:]
            require(checksum == hash256(body[4:36] + payload), "Freshly written undo checksum differs")
            undo_count, _ = compact_size(payload)
            tx_count, _ = compact_size(body, 80)
            require(undo_count + 1 == tx_count, "Freshly written undo count differs")
            positions.append({"hash": shown(identity), "body_data_offset": body_data_offset,
                              "body_payload_bytes": len(body), "undo_data_offset": undo_data_offset,
                              "undo_payload_bytes": len(payload), "transaction_count": tx_count})
            undo_digest.update(prefix[4:] + framed)
            budget -= len(prefix) + len(framed)
        body_end, undo_end = body_file.tell(), undo_file.tell()
    require(budget == 0 and body_digest.hexdigest() == TAIL_SHA and undo_digest.hexdigest() == UNDO_SHA,
            "Fresh body/undo framed lengths or independent digests differ")
    return {"file": 169, "verified_frame_pairs": len(bodies), "decoded_frame_bytes": REPLAY_BYTES,
            "body_start": body_start, "body_end": body_end, "undo_start": undo_start, "undo_end": undo_end,
            "framed_body_sha256": TAIL_SHA, "framed_undo_sha256": UNDO_SHA}, positions

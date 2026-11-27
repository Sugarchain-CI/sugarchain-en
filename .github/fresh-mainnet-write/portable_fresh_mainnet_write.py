#!/usr/bin/env python3
"""Exercise normal Mainnet header admission and durable body writes on a prepared private copy."""

import argparse
import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import socket
import stat
import struct
import subprocess
import time

from mature_common import (
    ANCHOR, ANCHOR_WORK, END_HEIGHT, FIRST, HEIGHT, MANIFEST_SHA, POST_UTXO, TIP, TIP_WORK,
    RECEIVED, REQUEST, UPDATE, RPC, check_header, compact_size, frame, free_port, hash256,
    load_tail, read_frame, requests, require, require_stock_startup_check, shown, timestamp_ns, utxo, version,
)
from prepare_fresh_overlay import (
    ARCHIVE_SHA as OVERLAY_ARCHIVE_SHA, BASE_SHA, MANIFEST_SHA as OVERLAY_MANIFEST_SHA,
    MANIFEST_LIMIT, json_no_duplicates, members, signed_input, verify_tree,
)
from process_resources import Resources

CONVERTER_REFERENCE_SHA = "ed7ad4350ce13e0f20302ab8d05927248213932308112aa17d609328703379c4"
CURSORS_SHA = "f6bbbb520d55e9e948d2c7f6c941939bdd751a84d2d295ab9d552816eb2d5aff"
ANCHOR_HEADER_SHA = "5211ac6e034169b0dea980a78a05c7007c4c76b7d081076345ffcdb87df4904e"
PRE_UTXO = {
    "height": HEIGHT, "bestblock": ANCHOR,
    "hash_serialized_3": "c7523f3471148733dd0bcc2011dd35364d7a3764b3d5c50477db626c182eeacf",
    "txouts": 7268171, "total_amount": "979478533.92969728",
}
HEADER = re.compile(rb"Saw new header hash=([a-f0-9]{64}) height=(\d+) peer=(\d+)\b")
DIRECT = re.compile(rb"Requesting block ([a-f0-9]{64}) from  peer=(\d+)")
SYNCS = {
    "block_and_undo": re.compile(rb"write block and undo data to disk completed \(([0-9.]+)ms\)"),
    "block_index": re.compile(rb"write block index to disk completed \(([0-9.]+)ms\)"),
    "coins": re.compile(rb"Committed (\d+) changed transaction outputs"),
}
COMPILED_WORK_FLOOR = 0x14058fe37bb0b
TABLE_LIMIT_MARKER = b"LevelDB bounded block index table cache enabled on Windows x64 (table_cache_target=32)."
CACHE_LINES = {
    "block_index_mib": re.compile(rb"Using ([0-9.]+) MiB for block index database"),
    "coins_database_mib": re.compile(rb"Using ([0-9.]+) MiB for chain state database"),
    "utxo_cache_mib": re.compile(rb"Using ([0-9.]+) MiB for in-memory UTXO set"),
}
MAX_MESSAGES = 10_000
MAX_ACCEPTED_BYTES = 4 << 20
NATIVE_PINS = {
    "4032c943f6969767d5c2413215063ca5051075a3f6391f443655ab8e0fef5f96":
        ("Linux", "d68b443c027b1f962be73f715643fcafce4f51f1"),
    "6ccb4c7ab8bee0528773cfffa76b68b05d69bfb0fa86a46f6b13a7a278a1deb7":
        ("Windows", "1b3029359223d7cee5da852762c04f2aac700a88"),
    "05821a46cb376d1a8e5c885fb4df55f0ed500fff7238313078b481f6c646dfde":
        ("Windows", "60f067d121651b8267b8d02c46fb221af4fc3529"),
}


def private_json(path):
    require(path.is_absolute() and path.resolve(strict=True) == path, "Expected canonical receipt path")
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size < 64 << 10 and
            not getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT,
            "Invalid private fixture receipt")
    return json_no_duplicates(path.read_bytes())


def fixture(datadir, receipt, manifest_path, cursors_path):
    require(datadir.is_absolute() and datadir.resolve(strict=True) == datadir and
            datadir not in receipt.parents, "Noncanonical datadir or overlay receipt inside fixture")
    require(BASE_SHA == MANIFEST_SHA, "Portable base and Mainnet history pins differ")
    restored = private_json(receipt)
    manifest = json_no_duplicates(signed_input(manifest_path, OVERLAY_MANIFEST_SHA, MANIFEST_LIMIT))
    target = members(manifest["file_members"])
    require((restored["schema"], restored["status"], restored["datadir"], restored["base_manifest_sha256"],
             restored["overlay_manifest_sha256"], restored["archive_sha256"], restored["anchor_height"],
             restored["anchor_hash"], restored["target_tip_height"], restored["target_tip_hash"],
             restored["full_file_count"], restored["full_file_bytes"], restored["replacement_file_count"],
             restored["obsolete_file_count"]) ==
            (1, "fresh_overlay_verified", str(datadir), BASE_SHA, OVERLAY_MANIFEST_SHA, OVERLAY_ARCHIVE_SHA,
             HEIGHT, ANCHOR, END_HEIGHT, TIP, 309, sum(row["bytes"] for row in target.values()), 7, 5) and
            len(target) == 309, "Portable overlay preparation receipt mismatch")
    cursors = json_no_duplicates(signed_input(cursors_path, CURSORS_SHA, 4096))
    require((cursors["schema"], cursors["kind"], cursors["overlay_manifest_sha256"],
             cursors["reference_conversion_sha256"], cursors["anchor_height"], cursors["anchor_hash"],
             cursors["removed_block_rows"], cursors["removed_proof_rows"], cursors["retained_file"],
             cursors["original_body_end"], cursors["original_undo_end"]) ==
            (1, "fresh_overlay_original_file_cursors", OVERLAY_MANIFEST_SHA, CONVERTER_REFERENCE_SHA,
             HEIGHT, ANCHOR, 4119, 4119, 169, 124263644, 22536617), "Original fixture cursor identity mismatch")
    verify_tree(datadir, target)
    return cursors


def headers_after(locator, ordered_identities, headers, predecessor):
    if locator == predecessor:
        start = 0
    else:
        start = ordered_identities.index(locator) + 1
    return ordered_identities[start:start + 2000], headers[start:start + 2000]


class ReplayPeer:
    def __init__(self, bodies, anchor, transcript, peer_port):
        self.bodies = bodies
        self.predecessor = anchor[4:36]
        self.hashes = (hash256(anchor), *bodies)
        self.headers = (anchor, *(body[:80] for body in bodies.values()))
        self.transcript = transcript
        self.peer_port = peer_port
        self.header_replies = []
        self.requested = []
        self.offered = set()
        self.sent = set()
        self.body_bytes = self.max_batch = 0
        self.first = self.first_headers = self.last_send = self.error = None
        self.complete = asyncio.Event()
        self.done = asyncio.Event()
        self.writer = None
        self.closing = False

    def note(self, message, **data):
        self.transcript.write(json.dumps({"event": message, "monotonic_ns": time.monotonic_ns(), **data}) + "\n")

    async def accept(self, reader, writer):
        if self.writer is not None:
            writer.close()
            return
        self.writer = writer
        version_seen = verack_seen = False
        self.inbound_bytes = 0
        try:
            writer.get_extra_info("socket").setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            for _ in range(MAX_MESSAGES):
                command, payload = await read_frame(reader)
                self.inbound_bytes += len(payload) + 24
                require(self.inbound_bytes <= MAX_ACCEPTED_BYTES, "Owned peer input budget exceeded")
                if command == b"version":
                    require(not version_seen and len(payload) >= 20, "Unexpected loopback version")
                    version_seen = True
                    writer.write(frame(b"version", version(self.peer_port)) + frame(b"verack"))
                elif command == b"verack":
                    require(version_seen and not verack_seen and not payload, "Unexpected loopback verack")
                    verack_seen = True
                elif command == b"ping":
                    require(len(payload) == 8, "Unexpected ping length")
                    writer.write(frame(b"pong", payload))
                elif command == b"getheaders":
                    require(verack_seen, "GETHEADERS arrived before negotiation")
                    self.send_headers(payload)
                elif command == b"getdata":
                    require(verack_seen, "GETDATA arrived before negotiation")
                    self.send_blocks(payload)
                elif command in (b"getaddr", b"sendheaders", b"sendcmpct", b"wtxidrelay", b"sendaddrv2",
                                 b"feefilter", b"pong"):
                    pass
                else:
                    raise ValueError(f"Unexpected owned peer command {command!r}")
                await writer.drain()
                if command == b"getdata":
                    self.last_send = time.monotonic_ns()
                    if len(self.sent) == len(self.bodies):
                        self.complete.set()
            raise ValueError("Owned peer message limit exceeded")
        except (ValueError, OSError, asyncio.IncompleteReadError) as error:
            if not self.closing:
                self.error = error
        finally:
            writer.close()
            self.done.set()

    def send_headers(self, payload):
        count, offset = compact_size(payload, 4)
        require(0 < count <= 101 and len(payload) == offset + 32 * (count + 1), "Invalid GETHEADERS locator")
        locator = tuple(payload[i:i+32] for i in range(offset, len(payload) - 32, 32))
        require(payload[-32:] == bytes(32), "GETHEADERS has an unanticipated explicit stop hash")
        common = next((item for item in locator if item in self.hashes or item == self.predecessor), None)
        require(common is not None, "GETHEADERS locator did not connect to the prepared range")
        ids, headers = headers_after(common, self.hashes, self.headers, self.predecessor)
        require(len(self.header_replies) < 8, "Excessive header continuation")
        if not self.header_replies:
            require(common in (self.predecessor, self.hashes[0]), "Initial locator skipped fresh headers")
            self.first_headers = (time.monotonic_ns(), time.time_ns())
        self.offered.update(ids)
        self.writer.write(frame(b"headers", compact_count(len(headers)) + b"".join(h + bytes(1) for h in headers)))
        self.header_replies.append((shown(common), tuple(shown(item) for item in ids if item in self.bodies)))
        self.note("headers", common=shown(common), count=len(ids), last=shown(ids[-1]) if ids else None)

    def send_blocks(self, payload):
        ids = requests(payload)
        require(len(ids) <= 128 and len(ids) == len(set(ids)) and
                all(item in self.offered and item in self.bodies and item not in self.sent for item in ids),
                "Duplicate, foreign or unannounced GETDATA body")
        if self.first is None:
            self.first = (time.monotonic_ns(), time.time_ns())
        self.max_batch = max(self.max_batch, len(ids))
        for identity in ids:
            body = self.bodies[identity]
            self.writer.write(frame(b"block", body))
            self.sent.add(identity)
            self.requested.append(shown(identity))
            self.body_bytes += len(body)
        self.note("getdata", hashes=[shown(item) for item in ids])

    async def close(self):
        self.closing = True
        if self.writer is not None:
            self.writer.close()
            await asyncio.wait_for(self.done.wait(), 5)


def compact_count(value):
    return bytes([value]) if value < 253 else b"\xfd" + struct.pack("<H", value)


def executable(path, digest):
    require(digest in NATIVE_PINS and NATIVE_PINS[digest][0] == platform.system(), "Unsupported package pin")
    require(path.is_absolute() and path.resolve(strict=True) == path and path.is_file(), "Noncanonical daemon")
    with path.open("rb") as source:
        prefix = source.read(64)
        if platform.system() == "Windows":
            require(platform.machine() in ("AMD64", "x86_64") and len(prefix) == 64 and prefix[:2] == b"MZ",
                    "Expected a native Windows executable")
            pe_offset = int.from_bytes(prefix[60:64], "little")
            require(64 <= pe_offset < 1 << 20, "Invalid PE header offset")
            source.seek(pe_offset)
            pe = source.read(26)
            require(pe[:6] == b"PE\x00\x00\x64\x86" and pe[24:26] == b"\x0b\x02", "Expected AMD64 PE32+")
        else:
            require(platform.system() == "Linux" and platform.machine() == "x86_64" and
                    prefix[:6] == b"\x7fELF\x02\x01" and prefix[18:20] == b"\x3e\x00", "Expected native x86-64 ELF")
        source.seek(0)
        require(hashlib.file_digest(source, "sha256").hexdigest() == digest, "Daemon SHA-256 mismatch")


def finish_cleanup(receipt, fields, errors, primary):
    fields["primary_exception"] = type(primary).__name__ if primary is not None else None
    fields["cleanup_errors"] = [{"stage": stage, "exception": type(error).__name__} for stage, error in errors]
    try:
        with receipt.open("x", encoding="utf-8") as output:
            json.dump(fields, output, sort_keys=True, indent=2)
            output.write("\n")
    except BaseException as error:
        errors.append(("write_cleanup_receipt", error))
        if primary is not None:
            primary.add_note(f"Could not write {receipt.name} ({type(error).__name__})")
    if primary is None and errors:
        raise errors[0][1]


async def finish_node(process, rpc, shutdown_timeout, log, receipt, primary):
    errors = []
    forced = clean = acknowledged = False
    try:
        if rpc is not None and process.poll() is None:
            await rpc("stop", timeout=10 if primary is None else 3)
            acknowledged = True
            await asyncio.to_thread(process.wait, shutdown_timeout)
        if acknowledged or primary is None:
            with log.open("rb") as stream:
                require(acknowledged and process.returncode == 0 and any(b"Shutdown done" in line for line in stream),
                        "Owned node lacked a clean shutdown")
            clean = True
    except BaseException as error:
        errors.append(("graceful_shutdown", error))
    finally:
        if process.returncode is None:
            # There are no awaits on the escalation path, so cancellation cannot abandon the child.
            forced = True
            for stage, action in (("terminate", process.terminate), ("kill", process.kill)):
                try:
                    action()
                except BaseException as error:
                    errors.append((stage, error))
                try:
                    process.wait(timeout=10)
                    break
                except BaseException as error:
                    errors.append((f"wait_after_{stage}", error))
    finish_cleanup(receipt, {"pid": process.pid, "returncode": process.returncode,
                             "reaped": process.returncode is not None, "forced": forced,
                             "rpc_acknowledged": acknowledged, "clean_shutdown": clean and not forced}, errors, primary)


async def finish_peer(server, peer, receipt, primary):
    errors = []
    deadline = time.monotonic() + 10
    try:
        server.close()
        # Python 3.14 waits for client transports in Server.wait_closed.
        await asyncio.wait_for(peer.close(), timeout=5)
    except BaseException as error:
        errors.append(("peer_close", error))
    try:
        if errors:
            server.abort_clients()
        await asyncio.wait_for(server.wait_closed(), timeout=max(0, deadline - time.monotonic()))
    except BaseException as error:
        errors.append(("server_wait_closed", error))
        try:
            server.abort_clients()
        except BaseException as abort_error:
            errors.append(("abort_clients", abort_error))
    finish_cleanup(receipt, {"clean_shutdown": not errors}, errors, primary)


@asynccontextmanager
async def node(args, phase, port):
    rpc_port = free_port()
    while rpc_port == port:
        rpc_port = free_port()
    log = args.output / f"{phase}-node.log"
    options = [
        str(args.binary), f"-datadir={args.datadir}", f"-conf={args.output / 'isolated.conf'}", "-nosettings",
        "-chain=main", "-server=1", "-disablewallet", "-prune=1", "-assumevalid=0",
        "-checkblocks=6", "-checklevel=3",
        f"-connect=127.0.0.1:{port}" if port else "-connect=0",
        "-txindex=0", "-coinstatsindex=0", "-txospenderindex=0", "-blockfilterindex=0",
        "-discover=0", "-dns=0", "-dnsseed=0", "-fixedseeds=0", "-listenonion=0", "-natpmp=0",
        "-networkactive=0", "-listen=0", "-v2transport=0", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
        f"-rpcport={rpc_port}", "-logtimestamps=1", "-logtimemicros=1", "-printtoconsole=0",
        "-loglevel=debug", "-debug=net", "-debug=bench", "-debug=validation", "-debug=coindb",
        f"-debuglogfile={log}", "-shrinkdebugfile=0",
    ]
    log.touch(exist_ok=False)
    with (args.output / f"{phase}-console.log").open("xb") as console:
        process = subprocess.Popen(options, stdin=subprocess.DEVNULL, stdout=console, stderr=subprocess.STDOUT)
        rpc = None
        primary = None
        try:
            rpc = RPC(args.datadir, rpc_port)
            start = time.monotonic()
            while time.monotonic() < start + args.startup_timeout:
                require(process.poll() is None, f"Owned node exited during startup: {process.returncode}")
                if rpc.cookie.is_file():
                    try:
                        state = await rpc("getblockchaininfo", timeout=3)
                        break
                    except (OSError, ValueError, RuntimeError):
                        pass
                await asyncio.sleep(0.5)
            else:
                raise TimeoutError("Owned node startup deadline expired")
            require_stock_startup_check(log)
            yield process, rpc, log, state, time.monotonic() - start
        except BaseException as error:
            primary = error
            raise
        finally:
            await finish_node(process, rpc, args.shutdown_timeout, log, args.output / f"{phase}-cleanup.json", primary)


def state_check(state, height, block, work):
    require((state["chain"], state["blocks"], state["headers"], state["bestblockhash"],
             state["chainwork"], state["pruned"]) == ("main", height, height, block, work, True),
            "Unexpected active tip, header tip or work in owned fixture")


async def history(rpc, timeout, result):
    stop = time.monotonic() + timeout
    while time.monotonic() < stop:
        status = (await rpc("getblockchaininfo"))["historicalpow"]
        result["historicalpow_latest"] = status
        require(status["state"] not in ("failed", "interrupted", "disabled"), "Historical proof check unavailable")
        if status["state"] == "complete":
            require(status["historical_trust"] is False and status["remaining"] == 0 and
                    status["total"] == status["checked"] and status["checked"] > HEIGHT,
                    "Historical proof check did not commit the entire prepared range")
            return status
        await asyncio.sleep(0.5)
    raise TimeoutError("Historical proof verification was not complete before the sample")


def network_evidence(lines, peer, peer_id):
    expected = [shown(identity) for identity in peer.bodies]
    offered = [identity for _, identities in peer.header_replies for identity in identities]
    ends = [identities[-1] for _, identities in peer.header_replies if identities]
    headers, req, recv, updates = [], [], [], []
    connect = undo = disconnect = 0
    for line in lines:
        if match := HEADER.search(line):
            require(int(match[3]) == peer_id, "Unexpected accepted header peer")
            headers.append((match[1].decode(), int(match[2])))
        if match := REQUEST.search(line):
            require(int(match[3]) == peer_id, "Unexpected native request peer")
            req.append((match[1].decode(), int(match[2])))
        if match := DIRECT.search(line):
            require(int(match[2]) == peer_id, "Unexpected direct fetch peer")
            req.append((match[1].decode(), None))
        if match := RECEIVED.search(line):
            require(int(match[2]) == peer_id, "Unexpected native block receive peer")
            recv.append(match[1].decode())
        if match := UPDATE.search(line):
            updates.append((match[1].decode(), int(match[2])))
        connect += b"- Connect block: " in line
        undo += b"- Write undo data: " in line
        disconnect += b"DisconnectTip:" in line
    heights = {identity: HEIGHT + n for n, identity in enumerate(expected, 1)}
    require(offered == expected and headers == [(item, heights[item]) for item in ends],
            "Native accepted header batch endpoints differ from the complete offered range")
    require(peer.requested == [item for item, _ in req] == recv and
            set(recv) == set(expected) and len(recv) == len(expected) and
            all(height is None or heights[item] == height for item, height in req),
            "Native requested or received bodies differ from the wire stream")
    require(updates == list(heights.items()) and connect == undo == len(expected) and disconnect == 0,
            "Canonical connects, undo writes or active-tip sequence differs")
    return {"fresh_headers_offered": len(offered), "accepted_header_batch_ends": headers,
            "requested": len(req), "received": len(recv), "connect": connect, "undo": undo, "disconnect": disconnect}


def sync_evidence(lines):
    stages = []
    for line in lines:
        require(b"Failed to flush block file" not in line and b"Failed to force flush state" not in line,
                "Native explicit flush reported a write failure")
        if b"Writing chainstate to disk: flush mode=FORCE_SYNC," in line:
            stages.append(("force_sync", None))
        for name, pattern in SYNCS.items():
            if match := pattern.search(line):
                stages.append((name, match[1]))
    require([name for name, _ in stages] == ["force_sync", "block_and_undo", "block_index", "coins"] and
            int(stages[3][1]) > 0, "Missing or unordered native block/undo, index or changed coin sync")
    return {"mode": "FORCE_SYNC", "block_and_undo_ms": float(stages[1][1]),
            "block_index_ms": float(stages[2][1]), "changed_coin_outputs": int(stages[3][1])}


def read_segment(log, offset, end=None):
    with log.open("rb") as stream:
        stream.seek(offset)
        return (stream.read(end - offset) if end is not None else stream.read()).splitlines()


def cache_allocation(log, bounded):
    allocation = {}
    markers = 0
    with log.open("rb") as stream:
        for line in stream:
            markers += TABLE_LIMIT_MARKER in line
            for name, pattern in CACHE_LINES.items():
                if match := pattern.search(line):
                    require(name not in allocation, "Duplicated native cache allocation log")
                    allocation[name] = float(match[1])
    require(allocation == {"block_index_mib": 64.0, "coins_database_mib": 8.0, "utxo_cache_mib": 952.0},
            "Native cache allocation does not match the compiled Windows defaults")
    require(markers == int(bounded), "Native bounded table-cache activation mismatch")
    return {**allocation, "table_cache_target": 32 if bounded else "default"}


def counter_deltas(before, after):
    diff = {key: after[key] - before[key] for key in before if key.startswith("io_") or key == "cpu_seconds"}
    require(all(value >= 0 for value in diff.values()), "Native process counters regressed")
    return diff


async def observed_tip(stream, peer, process, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        require(process.poll() is None and not peer.error, f"Owned node or peer stopped: {peer.error}")
        while line := stream.readline():
            if not line.endswith(b"\n"):
                stream.seek(-len(line), os.SEEK_CUR)
                break
            match = UPDATE.search(line)
            if match and int(match[2]) == END_HEIGHT:
                require(match[1].decode() == TIP and peer.first is not None,
                        "Final active tip appeared without its genuine GETDATA stream")
                await asyncio.wait_for(peer.complete.wait(), timeout=min(2, max(0, deadline - time.monotonic())))
                require(len(peer.sent) == len(peer.bodies), "Target appeared before the complete wire stream")
                return timestamp_ns(line)
        await asyncio.sleep(0.025)
    raise TimeoutError("Final active tip did not connect before the delivery deadline")


async def run(args):
    resources = Resources()
    host = resources.host()
    require(4 << 30 <= host["physical_bytes"] <= 16 << 30, "Runner is outside native cache-comparison RAM scope")
    executable(args.binary, args.binary_sha256)
    original = fixture(args.datadir, args.overlay_receipt, args.overlay_manifest, args.cursor_receipt)
    bodies = load_tail(args.tail)
    anchor = args.anchor_header.read_bytes()
    require(len(anchor) == 80 and hashlib.sha256(anchor).hexdigest() == ANCHOR_HEADER_SHA and
            shown(hash256(anchor)) == ANCHOR and
            next(iter(bodies.values()))[4:36] == hash256(anchor) and
            int(ANCHOR_WORK, 16) > COMPILED_WORK_FLOOR, "Expected exact connected anchor above stock work floor")
    require(args.output.is_absolute() and args.output.parent.resolve(strict=True) == args.output.parent and
            args.datadir != args.output and args.datadir not in args.output.parents,
            "Use a canonical fresh result directory outside the owned profile")
    args.output.mkdir(mode=0o700)
    (args.output / "isolated.conf").touch(exist_ok=False)
    # A successful or failed trial consumes the prepared copy once.
    with (args.datadir / ".fresh-mainnet-write-claimed").open("x") as claim:
        claim.write(str(args.output) + "\n")
    result = {
        "status": "incomplete", "schema": 1, "receiver_datadir": str(args.datadir),
        "binary_sha256": args.binary_sha256, "source_commit": NATIVE_PINS[args.binary_sha256][1],
        "checkpoint_manifest_sha256": MANIFEST_SHA,
        "overlay_manifest_sha256": OVERLAY_MANIFEST_SHA, "original_cursor_receipt_sha256": CURSORS_SHA,
        "fixture_preparation": "verified_full_portable_overlay",
        "database_cache_option": "compiled_default",
        "script_check_parallelism_option": "compiled_default",
        "anchor_header_sha256": hashlib.sha256(anchor).hexdigest(), "stock_work_floor_hex": f"{COMPILED_WORK_FLOOR:064x}",
        "assumevalid": 0, "host": host,
        "original_body_end": original["original_body_end"], "original_undo_end": original["original_undo_end"],
        "process_resources": {},
    }
    snapshots = result["process_resources"]
    bounded = result["source_commit"] == "60f067d121651b8267b8d02c46fb221af4fc3529"
    try:
        with (args.output / "wire.jsonl").open("x") as transcript:
            port = free_port()
            peer = ReplayPeer(bodies, anchor, transcript, port)
            server = await asyncio.start_server(peer.accept, "127.0.0.1", port)
            primary = None
            try:
                async with node(args, "fresh", port) as (process, rpc, log, state, startup):
                    result["startup_seconds"] = startup
                    snapshots["rpc_ready"] = resources.sample(process)
                    result["cache_allocation"] = cache_allocation(log, bounded)
                    state_check(state, HEIGHT, ANCHOR, ANCHOR_WORK)
                    require(await rpc("getconnectioncount") == 0, "Owned profile is not offline")
                    await check_header(rpc, ANCHOR, HEIGHT, ANCHOR_WORK)
                    for missing in (FIRST, TIP):
                        try:
                            await rpc("getblockheader", missing)
                        except RuntimeError as error:
                            require(str(error) == "Owned getblockheader RPC returned code -5", str(error))
                        else:
                            raise ValueError("Fresh target header already exists before network activation")
                    result["preflight_utxo"] = await utxo(rpc)
                    require(result["preflight_utxo"] == PRE_UTXO, "Wrong rollback chainstate")
                    result["historicalpow_before"] = await history(rpc, args.history_timeout, result)
                    offset = log.stat().st_size
                    snapshots["before_network"] = resources.sample(process)
                    began = time.monotonic()
                    with log.open("rb") as stream:
                        stream.seek(offset)
                        require(await rpc("setnetworkactive", True) is True, "Could not enable the single peer")
                        tip_epoch = await observed_tip(stream, peer, process, args.delivery_timeout)
                    observed = time.monotonic_ns()
                    snapshots["observed_tip"] = resources.sample(process)
                    result["delivery_counters"] = counter_deltas(snapshots["before_network"], snapshots["observed_tip"])
                    result["node_cpu_to_observed_tip_seconds"] = result["delivery_counters"]["cpu_seconds"]
                    require(peer.first_headers and peer.last_send is not None, "Incomplete header/body transcript")
                    body_wall = (tip_epoch - peer.first[1]) / 1e9
                    monotonic_body_wall = (observed - peer.first[0]) / 1e9
                    require(0 < body_wall <= monotonic_body_wall + 0.02 and
                            abs((time.time_ns() - time.monotonic_ns()) - (peer.first[1] - peer.first[0])) < 20_000_000,
                            "Node and monotonic measurement clocks differ")
                    result.update({
                        "activation_to_observed_tip_seconds": observed / 1e9 - began,
                        "first_header_send_to_observed_tip_seconds": (observed - peer.first_headers[0]) / 1e9,
                        "first_getdata_to_tip_log_seconds": body_wall,
                        "wire_blocks": len(peer.sent), "wire_body_bytes": peer.body_bytes, "max_getdata_batch": peer.max_batch,
                    })
                    contacts = await rpc("getpeerinfo")
                    require(len(contacts) == 1 and contacts[0]["addr"] == f"127.0.0.1:{port}" and
                            contacts[0]["inbound"] is False and not contacts[0]["permissions"],
                            "Expected one ordinary outbound Mainnet peer")
                    require(await rpc("setnetworkactive", False) is False, "Could not close sample network")
                    state = await rpc("getblockchaininfo")
                    state_check(state, END_HEIGHT, TIP, TIP_WORK)
                    result["historicalpow_after"] = state["historicalpow"]
                    require(result["historicalpow_after"] == result["historicalpow_before"],
                            "Historical verification overlapped the fresh sample")
                    await check_header(rpc, TIP, END_HEIGHT, TIP_WORK)
                    result["native_log_evidence"] = network_evidence(read_segment(log, offset), peer, contacts[0]["id"])
                    require(result["wire_body_bytes"] == 1602648, "Unexpected genuine wire body bytes")
                    flush_offset = log.stat().st_size
                    snapshots["before_explicit_flush"] = resources.sample(process)
                    flush_start = time.monotonic()
                    result["post_replay_utxo"] = await utxo(rpc)
                    result["flush_and_utxo_rpc_seconds"] = time.monotonic() - flush_start
                    snapshots["after_explicit_flush"] = resources.sample(process)
                    result["flush_and_utxo_counters"] = counter_deltas(snapshots["before_explicit_flush"], snapshots["after_explicit_flush"])
                    result["flush_and_utxo_rpc_cpu_seconds"] = result["flush_and_utxo_counters"]["cpu_seconds"]
                    require(result["post_replay_utxo"] == POST_UTXO, "Wrong final replay UTXO state")
                    result["forced_flush"] = sync_evidence(read_segment(log, flush_offset))
            except BaseException as error:
                primary = error
                raise
            finally:
                await finish_peer(server, peer, args.output / "fresh-peer-cleanup.json", primary)
        async with node(args, "reopen", 0) as (process, rpc, log, state, startup):
            state_check(state, END_HEIGHT, TIP, TIP_WORK)
            require(cache_allocation(log, bounded) == result["cache_allocation"], "Reopen cache allocation differs")
            snapshots["offline_reopen_ready"] = resources.sample(process)
            require(await rpc("getconnectioncount") == 0, "Unexpected offline reopen peer")
            await check_header(rpc, TIP, END_HEIGHT, TIP_WORK)
            result["offline_reopen_seconds"] = startup
            result["offline_reopen_utxo"] = await utxo(rpc)
            require(result["offline_reopen_utxo"] == POST_UTXO, "Wrong reopened UTXO state")
            snapshots["offline_reopen_checked"] = resources.sample(process)
        result["status"] = "fresh_write_verified_pending_disk_audit"
    except asyncio.CancelledError:
        result["error"] = "Shared per-case qualification deadline expired"
        raise
    except BaseException as error:
        result["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        (args.output / "result.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("binary", "datadir", "overlay-receipt", "overlay-manifest", "cursor-receipt", "tail", "anchor-header", "output"):
        parser.add_argument(f"--{option}", type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    for option, default in (("startup", 600), ("history", 240), ("delivery", 240), ("shutdown", 90)):
        parser.add_argument(f"--{option}-timeout", type=int, default=default)
    args = parser.parse_args()
    require(0 < args.startup_timeout <= 600 and 0 < args.history_timeout <= 1800 and
            0 < args.delivery_timeout <= 240 and 0 < args.shutdown_timeout <= 180,
            "Timeouts must be positive and bounded")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()

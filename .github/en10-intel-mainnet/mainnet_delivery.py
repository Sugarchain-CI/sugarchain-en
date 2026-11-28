#!/usr/bin/env python3
"""Compare bounded request ceilings for isolated releases receiving genuine Mainnet blocks."""

import argparse
import asyncio
from contextlib import AsyncExitStack
import ctypes
from datetime import datetime, timezone
from ctypes import wintypes
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import socket
import statistics
import struct
import time
from types import SimpleNamespace

from mainnet_paired import MAGIC, MAX_FRAME, compact_size, first_locator, fixture_headers, hash256, message, version_payload
from mainnet_probe import check_host, node, rpc
from resource_macos import sample as sample_darwin
from mainnet_warm import block_hex_records, make_batch, make_rpc_request, read_rpc_response, verify_batch, wait_empty_node

ARCHIVE_SHA = "eb0a6130b5a561bed197918face18106711715ba8e0c7862f5ad83b541b3082d"
RAW_SHA = "d3ab941f31aa5d1a6c6781d02d7212cdea95db75bafb054743a4adf3a82563d4"
NODE_COUNT = 4
HEIGHT = 4096
UTXO_SHA = "3548801d15bff5f17a3065079b3dd13bf7fb0e3469c4e97223777b8697a37649"
UTXO_COUNT = 5787


class MemoryCounters(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
        (name, ctypes.c_size_t) for name in (
            "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage",
            "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage",
        )
    ]


class Resources:
    def __init__(self):
        self.snapshot = None
        if os.name == "nt":
            self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            self.process_times = self.kernel.GetProcessTimes
            self.process_times.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
            self.process_times.restype = wintypes.BOOL
            self.kernel.GetCurrentProcess.restype = wintypes.HANDLE
            wow = self.kernel.IsWow64Process2
            wow.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.USHORT), ctypes.POINTER(wintypes.USHORT)]
            wow.restype = wintypes.BOOL
            process, host = wintypes.USHORT(), wintypes.USHORT()
            if not wow(self.kernel.GetCurrentProcess(), ctypes.byref(process), ctypes.byref(host)):
                raise ctypes.WinError(ctypes.get_last_error())
            if process.value or host.value != 0x8664 or hasattr(ctypes.WinDLL("ntdll"), "wine_get_version"):
                raise RuntimeError("Native Windows AMD64 execution is required")
            self.memory = ctypes.WinDLL("psapi", use_last_error=True).GetProcessMemoryInfo
            self.memory.argtypes = [wintypes.HANDLE, ctypes.POINTER(MemoryCounters), wintypes.DWORD]
            self.memory.restype = wintypes.BOOL

    @staticmethod
    def seconds(value):
        return ((value.dwHighDateTime << 32) | value.dwLowDateTime) / 10_000_000

    def sample(self, proc):
        if os.name == "nt":
            handle = wintypes.HANDLE(int(proc._handle))
            times = [wintypes.FILETIME() for _ in range(4)]
            if not self.process_times(handle, *(ctypes.byref(t) for t in times)):
                raise ctypes.WinError(ctypes.get_last_error())
            fields = MemoryCounters(cb=ctypes.sizeof(MemoryCounters))
            if not self.memory(handle, ctypes.byref(fields), fields.cb):
                raise ctypes.WinError(ctypes.get_last_error())
            return self.seconds(times[2]) + self.seconds(times[3]), fields.WorkingSetSize
        if platform.system() == "Linux":
            root = Path(f"/proc/{proc.pid}")
            fields = (root / "stat").read_text().rsplit(")", 1)[1].split()
            seconds = (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
            rss = int(fields[21]) * os.sysconf("SC_PAGE_SIZE")
            return seconds, rss
        self.snapshot = sample_darwin(proc.pid)
        return (self.snapshot["cpu_user_seconds"] + self.snapshot["cpu_system_seconds"],
                self.snapshot["resident_bytes"])


async def read_frame(reader):
    header = await reader.readexactly(24)
    size = struct.unpack_from("<I", header, 16)[0]
    if header[:4] != MAGIC or size > MAX_FRAME:
        raise ValueError("Unexpected loopback node frame")
    payload = await reader.readexactly(size)
    if hash256(payload)[:4] != header[20:24]:
        raise ValueError("Loopback node checksum differs")
    return header[4:16].rstrip(b"\0"), payload


def read_inventory(payload):
    if not payload:
        raise ValueError("Empty getdata message")
    count, pos = (struct.unpack_from("<H", payload, 1)[0], 3) if payload[0] == 253 else (payload[0], 1)
    if len(payload) != pos + count * 36:
        raise ValueError("Unexpected getdata size from the owned node")
    rows = []
    for _ in range(count):
        kind = struct.unpack_from("<I", payload, pos)[0] & 0x3FFFFFFF
        if kind == 2:
            rows.append(payload[pos + 4:pos + 36])
        pos += 36
    return rows


class Peer:
    def __init__(self, headers, blocks, start_hash, delay):
        self.headers = headers
        self.block_frames = {hash256(block[:80]): message(b"block", block) for block in blocks}
        self.positions = {hash256(header): index for index, header in enumerate(headers)}
        self.positions[start_hash] = -1
        self.delay = delay
        self.ready = asyncio.Event()
        self.started = False
        self.writer = None
        self.error = None
        self.timers = set()
        self.bytes = 0
        self.pending = 0
        self.peak_pending = 0
        self.requested = set()
        self.requests = 0
        self.responses = 0
        self.max_batch = 0
        self.first_request = None
        self.last_response = None
        self.delay_inaccuracy = 0.0

    async def start(self):
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self):
        self.server.close()
        for timer in self.timers:
            timer.cancel()
        self.timers.clear()
        if self.writer is not None:
            self.writer.close()
            try:
                await asyncio.wait_for(self.writer.wait_closed(), timeout=2)
            except TimeoutError:
                self.writer.transport.abort()
            except (OSError, ConnectionError):
                pass
        await asyncio.wait_for(self.server.wait_closed(), timeout=2)

    def send_headers(self, headers):
        payload = compact_size(len(headers)) + b"".join(header + b"\0" for header in headers)
        self.writer.write(message(b"headers", payload))

    def begin(self):
        self.started = True
        # Announce the cached final header only. All header proof work is untimed.
        self.send_headers(self.headers[-1:])

    def request(self, payload):
        requested = read_inventory(payload)
        self.max_batch = max(self.max_batch, len(requested))
        if requested and not self.started:
            raise RuntimeError("Block requests started before the measured window")
        loop = asyncio.get_running_loop()
        now = loop.time()
        if requested and self.first_request is None:
            self.first_request = now
        for block in requested:
            if block not in self.block_frames:
                raise RuntimeError("Owned node requested a block outside the benchmark fixture")
            self.requested.add(block)
            self.requests += 1
            self.pending += 1
            self.peak_pending = max(self.peak_pending, self.pending)
            due = now + self.delay
            def deliver(block_hash=block, deadline=due):
                if self.writer.is_closing():
                    return
                self.pending -= 1
                frame = self.block_frames[block_hash]
                self.writer.write(frame)
                self.bytes += len(frame) - 24
                self.responses += 1
                self.last_response = loop.time()
                self.delay_inaccuracy += max(0, self.last_response - deadline)
            self.timers.add(loop.call_at(due, deliver))

    async def handle(self, reader, writer):
        if self.writer is not None:
            writer.close()
            await writer.wait_closed()
            return
        self.writer = writer
        writer.get_extra_info("socket").setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            while True:
                command, payload = await read_frame(reader)
                if command == b"version":
                    writer.write(message(b"version", version_payload(self.port)) + message(b"verack", b""))
                elif command == b"verack":
                    self.ready.set()
                elif command == b"ping":
                    writer.write(message(b"pong", payload))
                elif command == b"getheaders":
                    offset = self.positions.get(first_locator(payload), len(self.headers)) + 1
                    self.send_headers(self.headers[offset:offset + 2000] if self.started else [])
                elif command == b"getdata":
                    self.request(payload)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, BrokenPipeError):
            # The final RPC verification detects a disconnect during delivery.
            pass
        except (ValueError, RuntimeError, OSError) as error:
            self.error = error
            self.ready.set()

    def evidence(self, start):
        return {
            "requests": self.requests, "unique_requested_blocks": len(self.requested),
            "responses": self.responses, "body_bytes_sent": self.bytes, "peak_pending": self.peak_pending,
            "largest_request_batch": self.max_batch, "outstanding_at_end": self.pending,
            "first_request_seconds": None if self.first_request is None else self.first_request - start,
            "last_response_seconds": None if self.last_response is None else self.last_response - start,
            "total_delivery_lateness_seconds": self.delay_inaccuracy,
        }


def require_logging_off(directory, port):
    categories = rpc(directory, port, "logging")
    if not isinstance(categories, dict) or not categories or any(categories.values()):
        raise RuntimeError("Expected disabled debug categories on the owned node")
    return {"active_categories": [], "category_count": len(categories)}


def require_clean_stop(directory, restart=False):
    label = "shutdown-restart.json" if restart else "shutdown.json"
    receipt = json.loads((directory / label).read_bytes())
    if not (receipt["rpc_ack"] and receipt["reaped"] and receipt["clean_shutdown"]
            and receipt["returncode"] == 0 and not receipt["forced"]):
        raise RuntimeError(f"Expected normal RPC shutdown of the owned node: {receipt}")
    return receipt


def verify_chain(directory, port, blocks, timeout, restart=False):
    request = json.dumps({"jsonrpc": "2.0", "id": "verify-full-prefix",
                          "method": "verifychain", "params": [4, 0]}).encode("ascii")
    cookie = (directory / ".cookie").read_bytes().strip()
    log = directory / ("debug-restart.log" if restart else "debug.log")
    start_offset = log.stat().st_size
    started = time.monotonic()
    response = json.loads(read_rpc_response(make_rpc_request(port, cookie, request), timeout))
    if response.get("id") != "verify-full-prefix" or response.get("error") or response.get("result") is not True:
        raise RuntimeError("Stock VerifyDB level 4 did not pass")
    with log.open("rb") as stream:
        stream.seek(start_offset)
        tail = stream.read().decode("utf-8", errors="replace")
    transactions = block_geometry(blocks)["transactions"]
    started_marker = f"Verifying last {len(blocks)} blocks at level 4"
    completed_marker = f"Verification: No coin database inconsistencies in last {len(blocks)} blocks ({transactions} transactions)"
    if (tail.count(started_marker) != 1 or tail.count(completed_marker) != 1
            or tail.index(started_marker) >= tail.index(completed_marker)):
        raise RuntimeError("Full level-4 block/transaction coverage did not appear in the stock log")
    return {"rpc": True, "seconds": time.monotonic() - started, "level": 4, "blocks": len(blocks),
            "transactions": transactions, "completion_marker": completed_marker}


def snapshot_delta(before, after):
    if before is None or after is None:
        return None
    identity = ("pid", "process_start_abstime", "source", "io_semantics")
    metrics = ("cpu_user_seconds", "cpu_system_seconds", "read_bytes", "write_bytes", "page_ins")
    if any(before[x] != after[x] for x in identity) or before["sampled_monotonic_ns"] >= after["sampled_monotonic_ns"]:
        raise RuntimeError("Resource sample identities or order differ")
    if any(not math.isfinite(before[x]) or not math.isfinite(after[x]) or not 0 <= before[x] <= after[x] for x in metrics):
        raise RuntimeError("Resource counters decreased or are invalid")
    return {"before": before, "after": after, "delta": {x: after[x] - before[x] for x in metrics}}


def header_chainwork(headers):
    # Stock Sugarchain Mainnet genesis uses compact target 0x1f3fffff.
    bits_values = [0x1f3fffff, *(struct.unpack_from("<I", header, 72)[0] for header in headers)]
    work = 0
    for bits in bits_values:
        value, exponent = bits & 0x7fffff, bits >> 24
        target = value << (8 * (exponent - 3)) if exponent >= 3 else value >> (8 * (3 - exponent))
        if bits & 0x800000 or not 0 < target < 2**256:
            raise ValueError("Malformed fixture compact target")
        work += (2**256) // (target + 1)
    return f"{work:064x}"


async def measure_case(options, directory, fixture, headers, blocks, header_batch, ceiling, resources, *,
                       request_limit, verify_restart=False, require_wire_ceiling=False):
    flags = (
        "-networkactive=0", "-connect=0", "-dnsseed=0", "-fixedseeds=0", "-dns=0", "-v2transport=0",
        "-assumevalid=0", "-minimumchainwork=0", "-debug=0", "-loglevel=info",
    )
    if request_limit is not None:
        flags += (f"-maxibdblocksinflight={request_limit}",)
    count = len(headers)
    work = header_chainwork(headers)
    with node(options, directory, "network-body", extra_flags=flags, shutdown_timeout=20) as (proc, port, _):
        cold = await asyncio.to_thread(wait_empty_node, directory, port, proc, options.timeout)
        if cold["chain"] != "main" or cold["headers"] != 0 or cold["blocks"] != 0 or cold["bestblockhash"] != fixture["genesis"]:
            raise RuntimeError("Expected the isolated mainnet genesis state")
        logging_before = await asyncio.to_thread(require_logging_off, directory, port)
        cookie = (directory / ".cookie").read_bytes().strip()
        prime_start = time.perf_counter()
        response = await asyncio.to_thread(read_rpc_response, make_rpc_request(port, cookie, header_batch), options.timeout)
        prime_seconds = time.perf_counter() - prime_start
        verified = verify_batch(response, count, "submitheader")
        primed = await asyncio.to_thread(rpc, directory, port, "getblockchaininfo")
        tip = await asyncio.to_thread(rpc, directory, port, "getblockheader", fixture["tip"])
        if (not primed or not tip or primed["headers"] != count or primed["blocks"] != 0
                or primed["bestblockhash"] != fixture["genesis"] or tip["height"] != count):
            raise RuntimeError("Verified header priming did not reach the fixed tip with zero active blocks")
        async with AsyncExitStack() as stack:
            peers = []
            for _ in range(NODE_COUNT):
                peer = await Peer(headers, blocks, bytes.fromhex(fixture["genesis"])[::-1], options.latency_ms / 1000).start()
                stack.push_async_callback(peer.stop)
                peers.append(peer)
            network = await asyncio.to_thread(rpc, directory, port, "setnetworkactive", True)
            if network is not True:
                raise RuntimeError("Owned node network activation failed")
            for peer in peers:
                await asyncio.to_thread(rpc, directory, port, "addnode", f"127.0.0.1:{peer.port}", "onetry", False)
            await asyncio.wait_for(asyncio.gather(*(peer.ready.wait() for peer in peers)), timeout=min(20, options.timeout))
            if any(peer.error or peer.started or peer.pending for peer in peers):
                raise RuntimeError(f"Loopback peer preflight failed: {[str(peer.error) for peer in peers]}")
            contacts = await asyncio.to_thread(rpc, directory, port, "getpeerinfo")
            expected = {f"127.0.0.1:{peer.port}" for peer in peers}
            if not contacts or {peer["addr"] for peer in contacts} != expected:
                raise RuntimeError("Owned node is not connected to exactly the four local test peers")
            loop = asyncio.get_running_loop()
            before_cpu, before_rss = await asyncio.to_thread(resources.sample, proc)
            before_snapshot = resources.snapshot
            harness_cpu = time.process_time()
            start = loop.time()
            for peer in peers:
                peer.begin()
            peak_pending_rss = before_rss
            last_resource_poll = start
            peak_inflight = 0
            while loop.time() - start < options.timeout:
                if proc.poll() is not None:
                    raise RuntimeError("Owned node exited during block delivery")
                if any(peer.error for peer in peers):
                    raise RuntimeError(f"Loopback peer failed: {[str(peer.error) for peer in peers]}")
                state = await asyncio.to_thread(rpc, directory, port, "getblockchaininfo")
                elapsed = loop.time() - start
                if state and state["blocks"] == count:
                    break
                now = loop.time()
                if now - last_resource_poll >= 0.20:
                    _, rss = await asyncio.to_thread(resources.sample, proc)
                    peak_pending_rss = max(peak_pending_rss, rss)
                    contacts = await asyncio.to_thread(rpc, directory, port, "getpeerinfo")
                    if not contacts or {peer["addr"] for peer in contacts} != expected:
                        raise RuntimeError("Loopback-only peer contact set changed during the measurement")
                    peak_inflight = max(peak_inflight, *(len(peer["inflight"]) for peer in contacts))
                    if peak_inflight > ceiling:
                        raise RuntimeError("Owned node exceeded the configured IBD request ceiling")
                    last_resource_poll = now
                await asyncio.sleep(0.015)
            else:
                raise TimeoutError("Real Mainnet block delivery did not complete within the limit")
            after_cpu, after_rss = await asyncio.to_thread(resources.sample, proc)
            after_snapshot = resources.snapshot
            harness_cpu = time.process_time() - harness_cpu
            sent = set().union(*(peer.requested for peer in peers))
            rows = [peer.evidence(start) for peer in peers]
            measured_resources = snapshot_delta(before_snapshot, after_snapshot)
            persist(directory / "body-endpoint.json", {
                "seconds": elapsed, "rpc_endpoint": state, "peer_counters": rows,
                "peak_inflight_per_peer_sampled": peak_inflight,
                "node_cpu_seconds": after_cpu - before_cpu, "owned_node_resources": measured_resources,
                "body_bytes": sum(row["body_bytes_sent"] for row in rows),
                "unique_requested_blocks": len(sent),
            })
            if (len(sent) != count or any(row["outstanding_at_end"] or row["peak_pending"] > ceiling or
                                           row["largest_request_batch"] > ceiling for row in rows)):
                raise RuntimeError("Unexpected pending block count, request ceiling, or fixture completion")
            wire_peak = max(row["peak_pending"] for row in rows)
            if require_wire_ceiling and wire_peak != ceiling:
                raise RuntimeError(f"Expected wire request peak {ceiling}, observed {wire_peak}")
            body_bytes = sum(row["body_bytes_sent"] for row in rows)
            if (body_bytes != sum(map(len, blocks)) or sum(row["requests"] for row in rows) != count
                    or sum(row["responses"] for row in rows) != count):
                raise RuntimeError("Unexpected block body byte count during delivery")
            if (state["chain"] != "main" or state["headers"] != count or state["bestblockhash"] != fixture["tip"]
                    or state["chainwork"] != work or state["initialblockdownload"] is not True):
                raise RuntimeError("Mainnet block delivery did not reach the expected active state")
            logging_after = await asyncio.to_thread(require_logging_off, directory, port)
            utxo = await asyncio.to_thread(rpc, directory, port, "gettxoutsetinfo", "hash_serialized_3")
            if (not utxo or utxo["height"] != count or utxo["bestblock"] != fixture["tip"]
                    or utxo.get("hash_serialized_3") != UTXO_SHA or utxo["txouts"] != UTXO_COUNT):
                raise RuntimeError("Mainnet block delivery UTXO state differs")

            verified_delivery = await asyncio.to_thread(verify_chain, directory, port, blocks, options.timeout)
            result = {
                "ceiling": ceiling, "configured_request_limit": request_limit,
                "primed_headers": count, "initial_active_blocks": 0,
                "verified_header_responses": verified, "header_prime_seconds_excluded": prime_seconds,
                "seconds": elapsed, "blocks_per_second": count / elapsed, "node_cpu_seconds": after_cpu - before_cpu,
                "harness_cpu_seconds": harness_cpu, "before_rss_bytes": before_rss, "after_rss_bytes": after_rss,
                "sampled_peak_rss_bytes": max(peak_pending_rss, after_rss),
                "peak_inflight_per_peer_sampled": peak_inflight, "wire_peak_pending_per_peer": wire_peak,
                "peer_counters": rows, "block_body_bytes_received": body_bytes,
                "unique_requested_blocks": len(sent), "blocks": count, "headers": state["headers"],
                "tip": state["bestblockhash"], "chainwork": state["chainwork"],
                "initialblockdownload": state["initialblockdownload"], "verified_chain": verified_delivery,
                "owned_node_resources": measured_resources,
                "logging_at_start": logging_before, "logging_at_end": logging_after,
                "utxo_hash": utxo["hash_serialized_3"], "utxo_count": utxo["txouts"], "proof_and_script_checks": True,
            }
    if verify_restart:
        first_shutdown = require_clean_stop(directory)
        with node(options, directory, "network-body", extra_flags=flags, restart=True,
                  shutdown_timeout=20) as (restarted, restart_port, started):
            reopened = await asyncio.to_thread(wait_empty_node, directory, restart_port, restarted, options.timeout)
            restart_seconds = time.monotonic() - started
            logging_restart = await asyncio.to_thread(require_logging_off, directory, restart_port)
            verified_chain = await asyncio.to_thread(verify_chain, directory, restart_port, blocks, options.timeout, True)
            reopened_utxo = await asyncio.to_thread(rpc, directory, restart_port, "gettxoutsetinfo", "hash_serialized_3")
            network = await asyncio.to_thread(rpc, directory, restart_port, "getnetworkinfo")
            contacts = await asyncio.to_thread(rpc, directory, restart_port, "getpeerinfo")
            if (reopened["chain"] != "main" or reopened["blocks"] != count or reopened["headers"] != count
                    or reopened["bestblockhash"] != fixture["tip"] or reopened["chainwork"] != work
                    or reopened["initialblockdownload"] is not True
                    or not reopened_utxo or reopened_utxo["height"] != count or reopened_utxo["bestblock"] != fixture["tip"]
                    or reopened_utxo.get("hash_serialized_3") != UTXO_SHA or reopened_utxo["txouts"] != UTXO_COUNT
                    or not network or network["networkactive"] is not False or contacts != []):
                raise RuntimeError("Offline restart did not reopen the exact verified Mainnet tip and UTXO state")
        restart_shutdown = require_clean_stop(directory, restart=True)
        result["verified_chain_restart"] = verified_chain
        result["logging_at_restart"] = logging_restart
        result["shutdown"] = first_shutdown
        result["shutdown_restart"] = restart_shutdown
        result["offline_restart"] = {
            "seconds": restart_seconds, "blocks": reopened["blocks"], "headers": reopened["headers"],
            "tip": reopened["bestblockhash"], "chainwork": reopened["chainwork"],
            "utxo_hash": reopened_utxo["hash_serialized_3"],
            "utxo_count": reopened_utxo["txouts"], "networkactive": False,
            "initialblockdownload": reopened["initialblockdownload"],
            "first_stop_exit": proc.returncode, "second_stop_exit": restarted.returncode,
        }
    return result


def persist(path, report):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def get_fixture(archive, metadata):
    data = archive.read_bytes()
    if hashlib.sha256(data).hexdigest() != ARCHIVE_SHA:
        raise ValueError("Mainnet archive checksum differs")
    raw = gzip.decompress(data)
    if hashlib.sha256(raw).hexdigest() != RAW_SHA:
        raise ValueError("Mainnet raw fixture checksum differs")
    fixture = json.loads(metadata.read_text(encoding="utf-8"))
    headers = fixture_headers(raw, fixture)
    blocks = [bytes.fromhex(block) for block in block_hex_records(raw)]
    if len(headers) != HEIGHT or len(blocks) != HEIGHT or any(header != block[:80] for header, block in zip(headers, blocks)):
        raise RuntimeError("Expected the first 4,096 Mainnet headers and block records")
    return fixture, headers, blocks


def block_geometry(blocks):
    lengths = [len(block) for block in blocks]
    stamps = [struct.unpack_from("<I", block, 68)[0] for block in (blocks[0], blocks[-1])]
    # The pinned early fixture contains one or two transactions per block.
    counts = [block[80] for block in blocks]
    if any(count >= 253 for count in counts):
        raise ValueError("Unexpected fixture transaction-count encoding")
    return {
        "raw_payload_bytes": sum(lengths), "minimum_block_bytes": min(lengths),
        "median_block_bytes": statistics.median(lengths), "maximum_block_bytes": max(lengths),
        "transactions": sum(counts), "multi_transaction_blocks": sum(count > 1 for count in counts),
        "first_and_last_header_times_utc": [datetime.fromtimestamp(stamp, timezone.utc).isoformat() for stamp in stamps],
    }


async def run(options):
    check_host()
    resources = Resources()
    options.gui = False
    options.binary = options.binary.resolve(strict=True)
    with options.binary.open("rb") as stream:
        binary_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    if binary_hash != options.binary_sha256:
        raise ValueError("Executable checksum differs")
    fixture, headers, blocks = get_fixture(options.fixture, options.fixture_info)
    header_batch = make_batch("submitheader", [header.hex() for header in headers])
    options.output = options.output.resolve()
    options.output.mkdir(parents=True)
    result = {
        "scope": "Native Mainnet fixture, loopback P2P body transport",
        "test_minimumchainwork_override": "0 for isolated fixture admission only",
        "assumevalid": 0, "peer_count": NODE_COUNT, "injected_delay_ms": options.latency_ms,
        "host": {"platform": platform.platform(), "machine": platform.machine(), "logical_cpus": os.cpu_count(),
                 "cpu": os.environ.get("PROCESSOR_IDENTIFIER") or platform.processor()},
        "binary_sha256": binary_hash, "fixture": fixture, "block_geometry": block_geometry(blocks),
        "order": options.order, "samples": [],
    }
    result_path = options.output / "result.json"
    persist(result_path, result)
    for index, ceiling in enumerate(options.order, 1):
        print(f"Sample {index}, ceiling {ceiling}: priming the fixed Mainnet header fixture", flush=True)
        row = await measure_case(options, options.output / f"{index:02d}-cap-{ceiling}", fixture, headers, blocks,
                                 header_batch, ceiling, resources, request_limit=ceiling)
        result["samples"].append(row)
        persist(result_path, result)
        print(f"Sample {index}, ceiling {ceiling}: {row['seconds']:.3f}s, {row['node_cpu_seconds']:.3f}s CPU, "
              f"{row['block_body_bytes_received']} block bytes received", flush=True)
    result["medians"] = {
        str(ceil): {key: statistics.median(row[key] for row in result["samples"] if row["ceiling"] == ceil)
                    for key in ("seconds", "node_cpu_seconds", "harness_cpu_seconds", "sampled_peak_rss_bytes")}
        for ceil in sorted(set(options.order))
    }
    persist(result_path, result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--fixture-info", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--latency-ms", default=100.0, type=float)
    parser.add_argument("--timeout", default=95.0, type=float)
    parser.add_argument("--ceiling", action="append", choices=(16, 32, 64, 128), type=int)
    parser.add_argument("--smoke", action="store_true", help="Run one sample per ceiling for correctness only")
    options = parser.parse_args()
    first = options.ceiling or [16, 32, 64, 128]
    if len(set(first)) != len(first) or not math.isfinite(options.latency_ms) or not 0 <= options.latency_ms <= 1000:
        parser.error("Use unique ceilings and an injected response delay between 0 and 1,000 milliseconds")
    if not math.isfinite(options.timeout) or options.timeout <= 0:
        parser.error("Use a positive finite startup and phase timeout")
    options.order = first if options.smoke else first + first[::-1]
    asyncio.run(run(options))


if __name__ == "__main__":
    main()

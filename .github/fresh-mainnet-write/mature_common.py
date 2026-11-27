"""Shared fixture, wire, and RPC helpers from the mature Mainnet qualification."""

import asyncio
import base64
import calendar
from datetime import datetime
from decimal import Decimal
import hashlib
import json
import re
import secrets
import socket
import struct
import time
import urllib.error
import urllib.request

MAGIC = bytes.fromhex("9feb4b9d")

MAX_FRAME = 4_000_000

HEIGHT = 44_942_101

END_HEIGHT = 44_946_197

ANCHOR = "78ab162387ae1c1274b1607e2845bfff1e6048a8400083f3b897e2e6a523d55c"

FIRST = "6c66f49502dac5cf84f3136d36c8a99d31156de40686f5baa0914533314c61a6"

TIP = "e67e0b48cb20a99db213f2618001d9c43a8c40dfa33a1ea6bf057c9644cf50cf"

ANCHOR_WORK = f"{0x141b05b7a1fb7:064x}"

TIP_WORK = f"{0x141b070c3ab4d:064x}"

TAIL_SHA = "5a912065d6029c008d9cdafe770d566c7f33fcb56c2f63aa3e5cc08d2e92bbac"

MANIFEST_SHA = "234d86232dc76cc86045b0f6cba2988a140562a112ecbbb454e82fa3f20a30f3"

POST_UTXO = {
    "height": END_HEIGHT, "bestblock": TIP,
    "hash_serialized_3": "bbf9db53b89be011b67f5fdc246292a534e41f292cde07f949f7994c04b2ec1a",
    "txouts": 7268394, "total_amount": "979500524.16225280",
}

REQUEST = re.compile(rb"Requesting block ([0-9a-f]{64}) \((\d+)\) peer=(\d+)")

RECEIVED = re.compile(rb"received block ([0-9a-f]{64}) peer=(\d+)")

UPDATE = re.compile(rb"UpdateTip: new best=([0-9a-f]{64}) height=(\d+)\b")

STAMP = re.compile(rb"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")

def require(condition, message):
    if not condition:
        raise ValueError(message)

def hash256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def shown(value):
    return value[::-1].hex()

def compact_size(data, offset=0):
    require(offset < len(data), "Truncated CompactSize")
    marker = data[offset]
    if marker < 253:
        return marker, offset + 1
    width = {253: 2, 254: 4, 255: 8}[marker]
    end = offset + 1 + width
    require(end <= len(data), "Truncated CompactSize value")
    value = int.from_bytes(data[offset + 1:end], "little")
    require(value >= {2: 253, 4: 1 << 16, 8: 1 << 32}[width], "Noncanonical CompactSize")
    return value, end

def frame(command, payload=b""):
    return MAGIC + command.ljust(12, b"\0") + struct.pack("<I", len(payload)) + hash256(payload)[:4] + payload

async def read_frame(reader):
    prefix = await reader.readexactly(24)
    length = struct.unpack_from("<I", prefix, 16)[0]
    command = prefix[4:16].rstrip(b"\0")
    require(prefix[:4] == MAGIC and length <= MAX_FRAME and command and
            all(32 <= byte <= 126 for byte in command), "Invalid loopback frame header")
    payload = await reader.readexactly(length)
    require(hash256(payload)[:4] == prefix[20:24], "Loopback frame checksum differs")
    return command, payload

def version(port):
    services = 1 | 8  # NODE_NETWORK and NODE_WITNESS.
    host = b"\0" * 10 + b"\xff\xff" + socket.inet_aton("127.0.0.1")
    endpoint = struct.pack("<Q", services) + host + struct.pack(">H", port)
    agent = b"/SugarchainMainnetTail:1/"
    return (struct.pack("<iQq", 70016, services, int(time.time())) + endpoint * 2 +
            struct.pack("<Q", secrets.randbits(64)) + bytes([len(agent)]) + agent +
            struct.pack("<iB", END_HEIGHT, 0))

def requests(payload):
    count, offset = compact_size(payload)
    require(0 < count <= 50_000 and len(payload) == offset + 36 * count, "Invalid GETDATA inventory")
    hashes = []
    for start in range(offset, len(payload), 36):
        kind = struct.unpack_from("<I", payload, start)[0]
        require(kind in (2, 0x40000002), "GETDATA requested an unexpected inventory type")
        hashes.append(payload[start + 4:start + 36])
    return hashes

def load_tail(path):
    require(path.stat().st_size == 1_635_416, "Wrong mature Mainnet fixture size")
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == TAIL_SHA, "Wrong mature Mainnet fixture SHA-256")
    bodies = {}
    parent = bytes.fromhex(ANCHOR)[::-1]
    offset = txs = 0
    while offset < len(data):
        magic, size = struct.unpack_from("<4sI", data, offset)
        end = offset + 8 + size
        require(magic == MAGIC and 80 < size <= MAX_FRAME and end <= len(data), "Invalid mature Mainnet frame")
        body = data[offset + 8:end]
        identity = hash256(body[:80])
        require(body[4:36] == parent and identity not in bodies, "Broken or repeated mature block link")
        count, _ = compact_size(body, 80)
        require(count > 0, "Missing mature block coinbase")
        txs += count
        bodies[identity] = body
        parent = identity
        offset = end
    require(len(bodies) == END_HEIGHT - HEIGHT and shown(next(iter(bodies))) == FIRST and shown(parent) == TIP and
            txs == 4149, "Wrong mature Mainnet block range")
    return bodies

def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

class RPC:
    def __init__(self, datadir, port):
        self.cookie = datadir / ".cookie"
        self.url = f"http://127.0.0.1:{port}/"
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def sync(self, method, params, timeout):
        auth = base64.b64encode(self.cookie.read_bytes().strip()).decode()
        request = urllib.request.Request(
            self.url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
            headers={"Authorization": "Basic " + auth, "Content-Type": "application/json"},
        )
        try:
            response = self.opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            result = json.load(response, parse_float=Decimal)
        if result.get("error") is not None:
            raise RuntimeError(f"Owned {method} RPC returned code {result['error'].get('code')}")
        return result["result"]

    async def __call__(self, method, *params, timeout=10):
        return await asyncio.to_thread(self.sync, method, params, timeout)

def require_stock_startup_check(log):
    begun = completed = False
    with log.open("rb") as stream:
        for line in stream:
            begun |= b"Verifying last 6 blocks at level 3" in line
            completed |= b"Verification: No coin database inconsistencies in last 6 blocks (" in line
            require(b"Block verification stopping" not in line and b"Skipped verification of level >=3" not in line,
                    "Stock level-3 startup verification was incomplete")
    require(begun and completed, "Missing successful stock six-block level-3 startup verification")

async def check_header(rpc, identity, height, chainwork):
    result = await rpc("getblockheader", identity)
    require((result["hash"], result["height"], result["chainwork"]) == (identity, height, chainwork),
            "Stored header differs from the pinned chainwork")

async def utxo(rpc):
    result = await rpc("gettxoutsetinfo", "hash_serialized_3", timeout=180)
    return {
        **{key: result[key] for key in ("height", "bestblock", "hash_serialized_3", "txouts")},
        "total_amount": format(result["total_amount"], ".8f"),
    }

def timestamp_ns(line):
    match = STAMP.match(line)
    require(match, "Missing microsecond node log timestamp")
    stamp = datetime.strptime(match[0].decode("ascii"), "%Y-%m-%dT%H:%M:%S.%fZ")
    return calendar.timegm(stamp.utctimetuple()) * 1_000_000_000 + stamp.microsecond * 1000

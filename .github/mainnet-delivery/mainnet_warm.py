#!/usr/bin/env python3
"""Compare trusted local Mainnet block submission with pre-verified headers."""

import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path
import platform
import statistics
import struct
import time
from types import SimpleNamespace
from urllib.request import Request, urlopen

from mainnet_paired import fixture_headers, sha256_file
from mainnet_probe import check_host, node, rpc


def block_hex_records(raw):
    pos = 0
    blocks = []
    while pos < len(raw):
        size = struct.unpack_from("<I", raw, pos + 4)[0]
        start = pos + 8
        pos = start + size
        blocks.append(raw[start:pos].hex())
    return blocks


def make_batch(method, records):
    return json.dumps(
        [
            {"jsonrpc": "2.0", "id": height, "method": method, "params": [record]}
            for height, record in enumerate(records, 1)
        ],
        separators=(",", ":"),
    ).encode("ascii")


def make_rpc_request(port, cookie, payload):
    return Request(
        f"http://127.0.0.1:{port}/",
        data=payload,
        headers={
            "Authorization": "Basic " + base64.b64encode(cookie).decode("ascii"),
            "Content-Type": "application/json",
        },
    )


def read_rpc_response(request, timeout):
    with urlopen(request, timeout=timeout) as response:
        return response.read()


def verify_batch(response, expected, method):
    rows = json.loads(response)
    if not isinstance(rows, list) or len(rows) != expected:
        raise RuntimeError(f"{method}: expected {expected} RPC responses")
    ids = set()
    for row in rows:
        ident = row.get("id")
        if type(ident) is not int or not 1 <= ident <= expected or ident in ids:
            raise RuntimeError(f"{method}: invalid response ID {ident!r}")
        if "result" not in row or row["result"] is not None or row.get("error") is not None:
            raise RuntimeError(f"{method} height {ident} failed: {str(row)[:200]}")
        ids.add(ident)
    return len(ids)


def wait_empty_node(directory, port, proc, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"Node exited during startup: {proc.returncode}")
        info = rpc(directory, port, "getblockchaininfo")
        if info is not None:
            return info
        time.sleep(0.1)
    raise TimeoutError("Node did not start in the allotted time")


def benchmark(args, directory, fixture, header_batch, block_batch):
    count = fixture["last_height"]
    flags = ("-networkactive=0", "-dnsseed=0", "-fixedseeds=0", "-assumevalid=0")
    with node(args, directory, "warm", extra_flags=flags) as (proc, port, _):
        cold = wait_empty_node(directory, port, proc, args.timeout)
        if (
            cold["chain"] != "main"
            or cold["blocks"] != 0
            or cold["headers"] != 0
            or cold["bestblockhash"] != fixture["genesis"]
        ):
            raise RuntimeError("Expected a fresh Mainnet node at the known genesis block")

        cookie = (directory / ".cookie").read_bytes().strip()
        submit_headers = make_rpc_request(port, cookie, header_batch)
        submit_blocks = make_rpc_request(port, cookie, block_batch)

        t0 = time.perf_counter()
        reply = read_rpc_response(submit_headers, args.timeout)
        prime_seconds = time.perf_counter() - t0
        received_headers = verify_batch(reply, count, "submitheader")
        primed = rpc(directory, port, "getblockchaininfo")
        best_header = rpc(directory, port, "getblockheader", fixture["tip"])
        if (
            not primed or primed["headers"] != count or primed["blocks"] != 0
            or primed["bestblockhash"] != fixture["genesis"]
            or not best_header or best_header["height"] != count
            or best_header["hash"] != fixture["tip"]
        ):
            raise RuntimeError("Header priming did not reach the fixed header tip while leaving blocks at genesis")

        # The payload and request are ready. Include loopback transfer, RPC
        # dispatch, validation and chain activation, up to the final response.
        t0 = time.perf_counter()
        reply = read_rpc_response(submit_blocks, args.timeout)
        elapsed = time.perf_counter() - t0
        received_blocks = verify_batch(reply, count, "submitblock")

        final = rpc(directory, port, "getblockchaininfo")
        utxo = rpc(directory, port, "gettxoutsetinfo", "hash_serialized_3")
        if (
            not final or final["blocks"] != count or final["headers"] != count
            or final["bestblockhash"] != fixture["tip"]
            or not utxo or utxo["height"] != count or utxo["bestblock"] != fixture["tip"]
            or len(utxo.get("hash_serialized_3", "")) != 64
        ):
            raise RuntimeError("Body submission did not reach the required active chain and UTXO tip")
        return {
            "status": "verified",
            "header_prime_seconds": prime_seconds,
            "warm_body_seconds": elapsed,
            "warm_blocks_per_second": count / elapsed,
            "verified_header_responses": received_headers,
            "verified_block_responses": received_blocks,
            "rpc_errors": 0,
            "primed_headers": primed["headers"],
            "initial_blocks": primed["blocks"],
            "final_headers": final["headers"],
            "final_blocks": final["blocks"],
            "final_block_hash": final["bestblockhash"],
            "genesis": cold["bestblockhash"],
            "utxo_hash_serialized_3": utxo["hash_serialized_3"],
            "utxo_count": utxo["txouts"],
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--fixture-info", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--repeats", default=3, type=int)
    parser.add_argument("--timeout", default=65, type=int)
    options = parser.parse_args()
    if not 1 <= options.repeats <= 5 or not 15 <= options.timeout <= 120:
        parser.error("--repeats must be 1–5 and --timeout must be 15–120 seconds")
    check_host()

    fixture = json.loads(options.fixture_info.read_text())
    if sha256_file(options.fixture) != fixture["archive_sha256"]:
        parser.error("Fixture archive checksum mismatch")
    raw = gzip.decompress(options.fixture.read_bytes())
    if hashlib.sha256(raw).hexdigest() != fixture["blocks_sha256"]:
        parser.error("Fixture block checksum mismatch")
    headers = fixture_headers(raw, fixture)
    header_batch = make_batch("submitheader", [header.hex() for header in headers])
    block_batch = make_batch("submitblock", block_hex_records(raw))

    root = options.output.resolve()
    root.mkdir(parents=True)
    binaries = {"baseline": options.baseline.resolve(strict=True), "candidate": options.candidate.resolve(strict=True)}
    measurements = {"baseline": [], "candidate": []}
    report = {
        "method": "verified_mainnet_headers_then_submitblock_batch",
        "host": {"name": platform.platform(), "machine": platform.machine(), "mode": "gui" if options.gui else "daemon"},
        "binary_sha256": {label: sha256_file(path) for label, path in binaries.items()},
        "fixture": fixture,
        "measurements": measurements,
    }
    first_utxo = None
    first_utxo_count = None
    for index in range(1, options.repeats + 1):
        labels = ("baseline", "candidate") if index % 2 else ("candidate", "baseline")
        for label in labels:
            args = SimpleNamespace(binary=binaries[label], gui=options.gui, timeout=options.timeout)
            result = benchmark(args, root / f"{index:02d}-{label}", fixture, header_batch, block_batch)
            if first_utxo is None:
                first_utxo = result["utxo_hash_serialized_3"]
                first_utxo_count = result["utxo_count"]
            if result["utxo_hash_serialized_3"] != first_utxo or result["utxo_count"] != first_utxo_count:
                raise RuntimeError("UTXO state differs across the compared runs")
            measurements[label].append({"repeat": index, **result})
            (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")
            print(
                f"{label} #{index}: warm body validation {result['warm_body_seconds']:.3f} s, "
                f"excluded header priming {result['header_prime_seconds']:.3f} s",
                flush=True,
            )

    old, new = ([sample["warm_body_seconds"] for sample in measurements[label]] for label in ("baseline", "candidate"))
    baseline_median, candidate_median = map(statistics.median, (old, new))
    report["comparison"] = {
        "baseline_median": baseline_median,
        "candidate_median": candidate_median,
        "wall_time_reduction_percent": 100 * (1 - candidate_median / baseline_median),
        "throughput_increase_percent": 100 * (baseline_median / candidate_median - 1),
        "paired_wall_time_reductions_percent": [100 * (1 - n / o) for o, n in zip(old, new)],
        "utxo_hash_parity": True,
    }
    (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()

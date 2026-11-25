#!/usr/bin/env python3
"""Validate paired benchmark evidence; this diagnostic does not authorize release."""
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys

import importlib.util
spec = importlib.util.spec_from_file_location("inputs", Path(__file__).with_name("check-package-native-inputs.py"))
inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inputs)
work = Path(sys.argv[1])
native_hash = inputs.digest(work / "native/bin/sugarchaind")
native_archive = inputs.digest(work / "native.tar.gz")
summary = {"source_sha": inputs.SOURCE, "source_tree": inputs.TREE,
           "artifact_run": 45677529513,
           "baseline": "exact signed En.6 packaged daemon",
           "candidate": "exact-source native AppleClang daemon",
           "publication_authorized": False, "results": {}}
fixture = {
    "blocks": 10000,
    "genesis": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
    "fixture_sha256": "e9a32c1f46099faa4a901e1479aef2aab0bc13f1143d048d3d661564fc0ad2d9",
    "fixture_tip": "634c6ae57600a991a51009c92cba732d9ed96504d0e636df534bc45cdd3a8e28",
    "fixture_utxo_sha256": "63208d710cf03c30de2660b77a5434181b20fd1c5e70460b256ea4f4e798cb84",
    "sender_time": 1795584000, "receiver_time": 1795756800,
    "max_tip_age": 86400, "dbcache_mib": 256, "checkblockindex": 0,
}
for sender in ("baseline", "candidate"):
    data = json.loads((work / ("paired-" + sender) / "result.json").read_text())
    assert data["system"] == "Darwin" and data["machine"] == "x86_64"
    assert all(data[k] == v for k, v in fixture.items())
    assert data["sender"] == sender
    assert data["sample_order"] == ["baseline", "candidate", "candidate", "baseline", "baseline", "candidate"]
    assert set(data["variants"]) == {"baseline", "candidate"}
    hashes = {"baseline": (inputs.ARCHIVE_HASH, inputs.DAEMON_HASH),
              "candidate": (native_archive, native_hash)}
    assert data["sender_binary_sha256"] == hashes[sender][1]
    for label, (archive_hash, binary_hash) in hashes.items():
        variant = data["variants"][label]
        assert variant["archive_sha256"] == archive_hash and variant["binary_sha256"] == binary_hash
        assert len(variant["samples"]) == 3 and all(row["reload_verified"] is True for row in variant["samples"])
        times = [row["sync_seconds"] for row in variant["samples"]]
        assert all(type(t) in (int, float) and math.isfinite(t) and t > 0 for t in times)
        assert math.isclose(statistics.median(times), variant["median_sync_seconds"], abs_tol=1e-9)
    summary["results"][sender] = data
    print("Sender", sender, "packaged", data["variants"]["baseline"]["median_sync_seconds"],
          "native", data["variants"]["candidate"]["median_sync_seconds"])
(work / "comparison-summary.json").write_text(json.dumps(summary, indent=2) + "\n")

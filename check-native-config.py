#!/usr/bin/env python3
"""Compare daemon compiler inputs with BUILD_TESTS disabled and enabled."""
import json
from pathlib import Path
import re
import shlex
import sys

NAMES = {
    "validation.cpp", "scheduler.cpp", "sync.cpp", "net.cpp", "net_processing.cpp",
    "txmempool.cpp", "disconnected_transactions.cpp", "streams.cpp", "fees.cpp",
    "yespower-opt.c",
}


def commands(path):
    output = {}
    for row in json.loads(path.read_text()):
        name = Path(row["file"]).name
        if name not in NAMES:
            continue
        args = row.get("arguments") or shlex.split(row["command"])
        # A second target can compile the same TU; preserve the output identity.
        output[(row["file"], args[args.index("-o") + 1])] = args
        levels = [arg for arg in args if re.fullmatch(r"-O([0-9]|s|z|g|fast)?", arg)]
        assert levels[-1] == "-O3", (name, levels)
        assert any(arg in ("-flto", "-flto=thin", "-flto=full") for arg in args), name
        assert not any(arg.startswith(("-march=", "-mcpu=", "-fsanitize=")) for arg in args), name
        assert not any(arg in ("-DDEBUG", "-DDEBUG_LOCKORDER", "-DDEBUG_LOCKCONTENTION", "-DNDEBUG") for arg in args), name
    assert {Path(k[0]).name for k in output} == NAMES
    return output


folder = Path(sys.argv[1])
before = commands(folder / "commands-tests-off.json")
after = commands(folder / "commands-tests-on.json")
# Test builds may add TU entries for test-only targets. All daemon entries must
# remain byte-for-byte equivalent; never infer this merely from Release mode.
changes = [key for key, args in before.items() if after.get(key) != args]
assert not changes, changes
assert (folder / "config-tests-off.h").read_bytes() == (folder / "config-tests-on.h").read_bytes()
(folder / "config-comparison.json").write_text(json.dumps({
    "production_commands_compared": len(before),
    "build_tests_changes_production_commands": False,
    "build_tests_changes_generated_config": False,
    "optimization": "-O3 with IPO", "cpu": "generic x86_64",
}, indent=2) + "\n")
print("BUILD_TESTS OFF/ON preserves all sampled daemon compiler inputs and generated configuration")

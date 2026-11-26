#!/usr/bin/env python3
"""Bind cross-built binaries to their source and record the ad-hoc-signed copies."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess

from pins import CONTROL_DIFF, SOURCES, STOCK_PARENT, file_sha


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def stage(role, incoming, output):
    receipt = json.loads((incoming / "build.json").read_bytes())
    parent = SOURCES["candidate"][0] if role == "control" else STOCK_PARENT
    require(receipt["schema"] == 1 and receipt["role"] == role and receipt["parent"] == parent and
            (receipt["source"], receipt["tree"]) == SOURCES[role], "Wrong transfer source identity")
    require(receipt["control_selector_diff_sha256"] == (CONTROL_DIFF if role == "control" else None), "Wrong selector diff receipt")
    expected = {"sugarchaind", "test_bitcoin"} if role == "candidate" else {"sugarchaind"}
    require(set(receipt["files"]) == expected, f"Unexpected transfer files: {role}")
    destination = output / role
    destination.mkdir()
    runtime = {}
    for name, sha in receipt["files"].items():
        original = incoming / name
        require(original.is_file() and not original.is_symlink() and file_sha(original) == sha, f"Invalid transfer binary {role}/{name}")
        path = destination / name
        shutil.copyfile(original, path)
        path.chmod(0o755)
        require(subprocess.check_output(["lipo", "-archs", str(path)], text=True, timeout=15).strip() == "arm64",
                f"Non-ARM64 transfer binary {role}/{name}")
        imports = subprocess.check_output(["otool", "-L", str(path)], text=True, timeout=15).splitlines()[1:]
        require(imports and all(line.split()[0].startswith(("/usr/lib/", "/System/Library/")) for line in imports),
                f"Non-system dylib in {role}/{name}")
        subprocess.run(["codesign", "--force", "--sign", "-", "--timestamp=none", path], check=True, timeout=30)
        subprocess.run(["codesign", "--verify", "--strict", path], check=True, timeout=30)
        runtime[name] = {"transfer_sha256": sha, "native_sha256": file_sha(path)}
    return {"build": receipt, "runtime": runtime}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("candidate", "control", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    options = parser.parse_args()
    options.output.mkdir()
    roles = {role: stage(role, getattr(options, role), options.output) for role in SOURCES}
    candidate, control = (roles[role]["build"] for role in ("candidate", "control"))
    require(candidate["depends_hash"] and candidate["depends_hash"] == control["depends_hash"], "Build dependency identities differ")
    require(candidate["commands"] == control["commands"], "Matched build flags or compiler paths differ")
    require(roles["candidate"]["runtime"]["sugarchaind"]["native_sha256"] != roles["control"]["runtime"]["sugarchaind"]["native_sha256"],
            "Expected different native candidate and control binaries")
    with (options.output / "native-builds.json").open("x", encoding="utf-8") as stream:
        json.dump({"schema": 1, "roles": roles}, stream, sort_keys=True, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Collect and stage exact Apple ARM64 test binaries."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess


SOURCES = {
    "control": ("2a0f1a9679f6b25c8bfefddd571b9572a3372233", "585f08d47bc953b7863d2fc3ba51f3ea762bc36f"),
    "candidate": ("61e2687ccd25c21466e381adaeeb2285e9ec5c06", "f470eab39b3f7bf6960d44c6ced2b5b5ed2560b8"),
}
ARM64_MAGIC = bytes.fromhex("cffaedfe0c000001")


def require(ok, detail):
    if not ok:
        raise ValueError(detail)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def collect(role, source, build, depends, output):
    want = SOURCES[role]
    actual = subprocess.check_output(["git", "-C", source, "rev-parse", "HEAD", "HEAD^{tree}"], text=True).split()
    require(tuple(actual) == want, "Unexpected release source")
    subprocess.run(["git", "-C", source, "diff", "--exit-code", "HEAD", "--", "src"], check=True)
    if role == "candidate":
        parent = subprocess.check_output(["git", "-C", source, "rev-parse", "HEAD^"], text=True).strip()
        require(parent == SOURCES["control"][0], "Candidate is not directly based on the baseline")
    commands = {}
    units = {"net_processing.cpp", "pow.cpp", "yespower-opt.c"}
    for entry in json.loads((build / "compile_commands.json").read_bytes()):
        name = Path(entry["file"]).name
        if name in units:
            args = entry.get("arguments") or shlex.split(entry["command"])
            opt = [arg for arg in args if re.fullmatch(r"-O([0-9]|s|z|g|fast)?", arg)]
            require(opt and opt[-1] == "-O3" and any(arg == "-flto" or arg.startswith("-flto=") for arg in args),
                    f"Unmatched Release optimization for {name}")
            commands.setdefault(name, []).append(args)
    require(set(commands) == units, "Missing matched compile units")
    output.mkdir()
    binaries = {"sugarchaind": build / "installed/bin/sugarchaind"}
    if role == "candidate":
        binaries |= {"sugarchain-cli": build / "installed/bin/sugarchain-cli", "test_bitcoin": build / "bin/test_bitcoin"}
    files = {}
    for name, path in binaries.items():
        with path.open("rb") as stream:
            require(stream.read(8) == ARM64_MAGIC, f"Not a thin Apple ARM64 executable: {name}")
        shutil.copyfile(path, output / name)
        files[name] = digest(output / name)
    (output / "build.json").write_text(json.dumps({
        "role": role, "source": want[0], "tree": want[1], "depends_hash": depends,
        "commands": commands, "files": files,
    }, indent=2) + "\n", encoding="utf-8")


def stage(incoming, output):
    output.mkdir()
    roles = {}
    for role, identifiers in SOURCES.items():
        origin = incoming / f"apple-ordinary-cross-{role}"
        receipt = json.loads((origin / "build.json").read_bytes())
        require((receipt["source"], receipt["tree"]) == identifiers and receipt["role"] == role, "Wrong cross artifact source")
        required = {"sugarchaind", "sugarchain-cli", "test_bitcoin"} if role == "candidate" else {"sugarchaind"}
        require(receipt["files"].keys() == required, "Unexpected cross artifact contents")
        folder = output / role
        folder.mkdir()
        signed = {}
        for name, sha in receipt["files"].items():
            binary = origin / name
            require(digest(binary) == sha, f"Cross transfer digest differs for {role}/{name}")
            target = folder / name
            shutil.copyfile(binary, target)
            target.chmod(0o755)
            require(subprocess.check_output(["lipo", "-archs", target], text=True, timeout=10).strip() == "arm64",
                    "Native executable has unexpected architecture")
            dependencies = subprocess.check_output(["otool", "-L", target], text=True, timeout=10).splitlines()[1:]
            require(dependencies and all(line.split()[0].startswith(("/usr/lib/", "/System/Library/")) for line in dependencies),
                    "An executable uses non-system libraries")
            subprocess.run(["codesign", "--force", "--sign", "-", "--timestamp=none", target], check=True, timeout=30)
            subprocess.run(["codesign", "--verify", "--strict", target], check=True, timeout=30)
            signed[name] = digest(target)
        roles[role] = {"build": receipt, "signed": signed}
    candidate, control = (roles[role]["build"] for role in ("candidate", "control"))
    require(candidate["depends_hash"] and candidate["depends_hash"] == control["depends_hash"] and
            candidate["commands"] == control["commands"], "Matched build configuration differs")
    require(roles["candidate"]["signed"]["sugarchaind"] != roles["control"]["signed"]["sugarchaind"], "Expected distinct code")
    (output / "runtime.json").write_text(json.dumps({"roles": roles}, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    cross = commands.add_parser("collect")
    cross.add_argument("--role", choices=SOURCES, required=True)
    cross.add_argument("--depends", required=True)
    for field in ("source", "build", "output"):
        cross.add_argument(f"--{field}", type=Path, required=True)
    native = commands.add_parser("stage")
    for field in ("incoming", "output"):
        native.add_argument(f"--{field}", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "collect":
        collect(args.role, args.source, args.build, args.depends, args.output)
    else:
        stage(args.incoming, args.output)

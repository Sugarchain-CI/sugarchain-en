#!/usr/bin/env python3
"""Verify optimized source inputs and collect matched ARM64 executables."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess

from pins import CONTROL_DIFF, SOURCES, STOCK_PARENT, file_sha


UNITS = {"pow.cpp", "block.cpp", "yespower-opt.c", "yespower-presync.c", "yespower-1.0.1/sha256.c"}


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def git(source, *arguments):
    return subprocess.check_output(["git", "-C", str(source), *arguments], timeout=10)


def verify_compile_commands(build):
    selected = {}
    for row in json.loads((build / "compile_commands.json").read_bytes()):
        source = Path(row["file"])
        name = "yespower-1.0.1/sha256.c" if source.name == "sha256.c" and source.parent.name == "yespower-1.0.1" else source.name
        if name not in UNITS:
            continue
        command = row.get("arguments") or shlex.split(row["command"])
        opt = [arg for arg in command if re.fullmatch(r"-O([0-9]|s|z|g|fast)?", arg)]
        require(opt and opt[-1] == "-O3" and any(arg == "-flto" or arg.startswith("-flto=") for arg in command),
                f"Expected Release O3 and IPO in {source}")
        if name == "yespower-1.0.1/sha256.c":
            obj = Path(row["directory"]) / command[command.index("-o") + 1]
            bitcode = obj.read_bytes()
            require(all(b"llvm.aarch64.crypto." + insn in bitcode for insn in (b"sha256h", b"sha256h2", b"sha256su0", b"sha256su1")),
                    "Missing native SHA-256 intrinsics")
        selected.setdefault(name, []).append(command)
    require(set(selected) == UNITS, f"Missing build commands: {sorted(UNITS - set(selected))}")
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=SOURCES, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--depends-hash", required=True)
    options = parser.parse_args()
    source = options.source.resolve(strict=True)
    build = options.build.resolve(strict=True)
    sha, tree = SOURCES[options.role]
    parent = SOURCES["candidate"][0] if options.role == "control" else STOCK_PARENT
    require(git(source, "rev-parse", "HEAD", "HEAD^{tree}", "HEAD^").decode().split() == [sha, tree, parent],
            "Checkout differs from the pinned role source")
    require(git(source, "diff", "--exit-code", "HEAD", "--", "src") == b"", "The product source became dirty")
    if options.role == "control":
        require(git(source, "diff", "--name-only", "HEAD^", "HEAD").splitlines() == [b"src/pow.cpp"], "Unexpected control diff scope")
        diff = git(source, "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--full-index",
                   "--no-relative", "--no-renames", "--src-prefix=a/", "--dst-prefix=b/",
                   "--unified=3", "--inter-hunk-context=0", "--diff-algorithm=myers", "--no-indent-heuristic",
                   "HEAD^", "HEAD", "--", "src/pow.cpp")
        require(hashlib.sha256(diff).hexdigest() == CONTROL_DIFF, "Unexpected control selector diff")
    commands = verify_compile_commands(build)

    options.output.mkdir()
    required = {"sugarchaind": build / "installed/bin/sugarchaind"}
    if options.role == "candidate":
        required["test_bitcoin"] = build / "bin/test_bitcoin"
    files = {}
    for name, path in required.items():
        with path.open("rb") as program:
            require(program.read(8) == bytes.fromhex("cffaedfe0c000001"), f"Expected an Apple ARM64 Mach-O: {name}")
        shutil.copyfile(path, options.output / name)
        files[name] = file_sha(options.output / name)
    result = {"schema": 1, "role": options.role, "source": sha, "tree": tree, "parent": parent,
              "depends_hash": options.depends_hash, "commands": commands, "files": files,
              "control_selector_diff_sha256": CONTROL_DIFF if options.role == "control" else None}
    with (options.output / "build.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(f"Matched source {options.role} {sha} {tree}")


if __name__ == "__main__":
    main()

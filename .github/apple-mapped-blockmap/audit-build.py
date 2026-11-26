#!/usr/bin/env python3
"""Audit global diagnostic C++ ABI and package the private build transfer."""

import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

import apple_mapped


def run(source, build, output):
    identity = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD", "HEAD^{tree}"],
                                       text=True).splitlines()
    if identity != [apple_mapped.SOURCE, apple_mapped.TREE]:
        raise ValueError("Unexpected private source identity")
    commands = json.loads((build / "compile_commands.json").read_text())
    cxx = {".cc", ".cpp", ".cxx", ".mm"}
    selected = {"blockstorage.cpp", "pool_tests.cpp", "header_pow_tests.cpp", "validation.cpp"}
    verified = set()
    count = 0
    for row in commands:
        path = Path(row["file"])
        args = row.get("arguments") or shlex.split(row["command"])
        if path.suffix in cxx:
            if args.count(apple_mapped.FLAG) != 1:
                raise ValueError(f"C++ diagnostic flag missing or duplicate in {path.name}")
            if f"-U{apple_mapped.FLAG[2:]}" in args:
                raise ValueError(f"C++ diagnostic flag undefined in {path.name}")
            if "-fno-cxx-modules" not in args or not any(arg.startswith("-mmacos-version-min=") for arg in args):
                raise ValueError(f"Stock Darwin initialization flags missing in {path.name}")
            count += 1
        elif apple_mapped.FLAG in args:
            raise ValueError(f"Unexpected diagnostic flag on {path.name}")
        if path.name in selected:
            optimization = [flag for flag in args if flag in {"-O0", "-O1", "-O2", "-O3", "-Os", "-Oz", "-Ofast"}]
            if not optimization or optimization[-1] != "-O3" or not any(flag.startswith("-flto") for flag in args):
                raise ValueError(f"Expected optimized IPO in {path.name}")
            verified.add(path.name)
    if count <= 100 or verified != selected:
        raise ValueError("Incomplete private C++ build coverage")
    output.mkdir()
    for binary in ("sugarchaind", "test_bitcoin"):
        shutil.copy2(build / "bin" / binary, output / binary)
    (output / "source-commit.txt").write_text(identity[0] + "\n")
    (output / "source-tree.txt").write_text(identity[1] + "\n")
    audit = {"flag": apple_mapped.FLAG, "source": identity[0], "tree": identity[1],
             "cxx_translation_unit_count": count, "optimized_checked_files": sorted(verified)}
    (output / "compile-audit.json").write_text(json.dumps(audit, indent=2) + "\n")
    (output / apple_mapped.MANIFEST).write_text("".join(
        f"{apple_mapped.digest(output / name)}  {name}\n" for name in sorted(apple_mapped.MEMBERS)))


if __name__ == "__main__":
    run(*map(Path, sys.argv[1:]))

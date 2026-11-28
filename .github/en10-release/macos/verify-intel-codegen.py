#!/usr/bin/env python3
"""Check the Intel release codegen in the read-only CMake-generated commands."""

import argparse
import hashlib
import json
import re
import shlex
from pathlib import Path

TARGET = "x86_64-apple-darwin"
VALIDATION_OBJECT = ("CMakeFiles", "bitcoin_node.dir", "validation.cpp.o")
LINKS = {
    "daemon_link": ("src/CMakeFiles/bitcoind.dir/link.txt", "sugarchaind"),
    "gui_link": ("src/qt/CMakeFiles/bitcoin-qt.dir/link.txt", "sugarchain-qt"),
}
MAX_DATABASE_BYTES = 32 << 20
MAX_COMMAND_BYTES = 2 << 20
OPTIMIZATION = re.compile(r"-O(?:[0-9]+|[gsz]|fast)?")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bounded_text(path, size):
    require(path.is_file() and 0 < path.stat().st_size <= size, f"Missing or oversized generated file: {path.name}")
    return path.read_text(encoding="utf-8")


def output_path(argv, directory):
    require(argv.count("-o") == 1 and argv.index("-o") + 1 < len(argv), "Missing unique driver output")
    return (directory / argv[argv.index("-o") + 1]).resolve()


def response_args(argv, directory, build, depth=0):
    expanded = []
    for token in argv:
        if token.startswith("@"):
            require(depth < 2, "Generated response files are nested too deeply")
            response = (directory / token[1:]).resolve()
            require(response.is_relative_to(build), "Generated response file is outside the build directory")
            words = shlex.split(bounded_text(response, MAX_COMMAND_BYTES))
            expanded.extend(response_args(words, directory, build, depth + 1))
        else:
            expanded.append(token)
        require(len(expanded) < 20000, "Generated command has too many arguments")
    return expanded


def validation_command(build):
    entries = json.loads(bounded_text(build / "compile_commands.json", MAX_DATABASE_BYTES))
    require(isinstance(entries, list), "Invalid CMake compilation database")
    matches = []
    for entry in entries:
        directory = Path(entry["directory"]).resolve()
        source = (directory / entry["file"]).resolve()
        if source.parts[-2:] != ("src", "validation.cpp"):
            continue
        require(directory.is_relative_to(build), "Validation compile directory is outside the build directory")
        argv = response_args(shlex.split(entry["command"]), directory, build)
        target = output_path(argv, directory)
        if target.parts[-3:] != VALIDATION_OBJECT:
            continue
        require(target.is_relative_to(build) and target.is_file(), "Validation object was not built")
        require(argv.count("-c") == 1 and argv.index("-c") + 1 < len(argv), "Missing validation compile operand")
        require((directory / argv[argv.index("-c") + 1]).resolve() == source, "Wrong validation compile operand")
        matches.append(argv)
    require(len(matches) == 1, "Expected exactly one compiled product validation object")
    return matches[0]


def link_command(build, link_file, program):
    path = build / link_file
    directory = path.parents[2]
    lines = bounded_text(path, MAX_COMMAND_BYTES).splitlines()
    require(len(lines) == 1, f"Expected one generated driver command for {program}")
    argv = response_args(shlex.split(lines[0]), directory, build)
    target = output_path(argv, directory)
    require("-c" not in argv and target == build / "bin" / program and target.is_file(),
            f"Generated link command does not identify built {program}")
    return argv


def driver_switches(argv):
    # Arguments forwarded explicitly to the linker, assembler or cc1 are not
    # compiler-driver optimization options.
    forwards_next = {"-Xlinker", "-Xassembler", "-Xclang", "-Xpreprocessor"}
    return [arg for i, arg in enumerate(argv) if i == 0 or argv[i - 1] not in forwards_next]


def verify_command(label, argv, *, link):
    require(any(Path(arg).name.startswith("clang++") for arg in argv[:3]), f"{label}: expected the Clang C++ driver")
    switches = driver_switches(argv)
    levels = [arg for arg in switches if OPTIMIZATION.fullmatch(arg)]
    lto = [arg for arg in switches if arg in ("-flto", "-fno-lto") or arg.startswith("-flto=")]
    targets = [arg for arg in switches if arg.startswith("--target=")]
    deployment = [arg for arg in switches if arg.startswith("-mmacos-version-min=")]
    require(levels and levels[-1] == "-O3", f"{label}: effective optimization must be -O3")
    require(lto and lto[-1] == "-flto=thin", f"{label}: effective IPO must be ThinLTO")
    require(set(targets) == {f"--target={TARGET}"}, f"{label}: wrong Darwin target")
    require(set(deployment) == {"-mmacos-version-min=14.0"}, f"{label}: wrong Darwin deployment minimum")
    require(not any(arg.startswith(("-march=", "-mcpu=")) for arg in switches), f"{label}: unexpected CPU targeting")
    require(not any("--lto-O" in arg or "--lto-CGO" in arg for arg in argv), f"{label}: forced LLD LTO level")
    if link:
        require("-fuse-ld=lld" in switches and "-Wl,-platform_version,macos,14.0,14.0" in switches,
                f"{label}: wrong Darwin linker or platform version")
    command_sha = hashlib.sha256(b"\0".join(arg.encode("utf-8") for arg in argv)).hexdigest()
    return {"target": label, "effective_optimization": levels[-1], "effective_ipo": lto[-1],
            "darwin_target": TARGET, "minimum_macos": "14.0", "command_argv_sha256": command_sha}


def verify(build):
    build = build.resolve(strict=True)
    receipts = [verify_command("validation_compile", validation_command(build), link=False)]
    for label, (path, program) in LINKS.items():
        receipts.append(verify_command(label, link_command(build, path, program), link=True))
    return receipts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    args = parser.parse_args()
    try:
        receipts = verify(args.build)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"Intel release codegen verification failed: {exc}\n")
    for row in receipts:
        print(json.dumps(row, sort_keys=True))


if __name__ == "__main__":
    main()

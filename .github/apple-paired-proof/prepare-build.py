#!/usr/bin/env python3
"""Build the standalone experiment from an unmodified pinned production source checkout."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

SOURCE = "9c502574b652804905d2533d51742ca91f694532"
TREE = "f44aa1b47f9701996046bbb396106f1d5c365e66"
VENDOR = "src/crypto/yespower-1.0.1"
INPUTS = (
    *(f"{VENDOR}/{name}" for name in (
        "yespower-opt.c", "yespower-platform.c", "yespower.h", "sha256.c", "sha256.h", "sha256-dispatch.h",
        "sysendian.h", "insecure_memzero.h",
    )),
    "src/primitives/block.h", "src/primitives/block.cpp",
)
HERE = Path(__file__).resolve().parent


def head(source, rev):
    return subprocess.check_output(["git", "-C", str(source), "rev-parse", rev], text=True, timeout=10).strip()


def exact(source, name):
    committed = subprocess.check_output(["git", "-C", str(source), "show", f"{SOURCE}:{name}"], timeout=10)
    disk = (source / name).read_bytes()
    if disk != committed:
        raise ValueError(f"Production input differs from the pinned commit: {name}")
    return disk


def render_params(header, implementation):
    number = lambda name: re.search(rf"inline constexpr uint32_t YESPOWER_SUGAR_{name}\{{(\d+)\}};", header).group(1)
    if number("VERSION") != "10" or "static_assert(YESPOWER_SUGAR_VERSION == YESPOWER_1_0)" not in implementation:
        raise ValueError("Expected the pinned version-one Sugar proof implementation")
    personalization = re.search(r'YESPOWER_SUGAR_PERSONALIZATION\[\]\s*=\s*("[^"\\]+")\s*;', header).group(1)
    return f'''#ifndef SUGAR_PARAMS_H
#define SUGAR_PARAMS_H
#define PROBE_VERSION YESPOWER_1_0
#define PROBE_N UINT32_C({number("N")})
#define PROBE_R UINT32_C({number("R")})
static const uint8_t probe_personalization[] = {personalization};
static const yespower_params_t probe_params = {{PROBE_VERSION, PROBE_N, PROBE_R,
    probe_personalization, sizeof(probe_personalization) - 1}};
#endif
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--sysroot", type=Path)
    parser.add_argument("--cflag", action="append", default=[])
    args = parser.parse_args()
    source, output = args.source.resolve(strict=True), args.output.resolve()
    if head(source, "HEAD") != SOURCE or head(source, "HEAD^{tree}") != TREE:
        parser.error("Expected the exact pinned product source worktree")
    if source == output or source in output.parents:
        parser.error("Build output must be outside the product checkout")
    sdk_flags = []
    if args.sysroot is not None:
        if not args.sysroot.is_absolute() or not args.sysroot.is_dir():
            parser.error("The compiler sysroot must be an existing absolute directory")
        sdk_flags = ["-isysroot", str(args.sysroot)]
    pinned = {name: exact(source, name) for name in INPUTS}
    compiler = shutil.which(args.cc)
    if compiler is None:
        parser.error("Requested compiler is unavailable")
    output.mkdir(mode=0o700)
    for name, content in pinned.items():
        if name.startswith(f"{VENDOR}/"):
            (output / Path(name).name).write_bytes(content)
    vendor = output / "yespower-opt.c"
    original = pinned[f"{VENDOR}/yespower-opt.c"]
    body, final = original.rsplit(b"\n#endif", maxsplit=1)
    if final.strip():
        raise ValueError("Unexpected end of the original Yespower translation unit")
    vendor.write_bytes(body + b'\n\n#include "paired-probe.inc"\n#endif' + final)
    for name in ("paired-probe.h", "paired-probe.inc", "paired-yespower-probe.c"):
        shutil.copyfile(HERE / name, output / name)
    (output / "sugar-params.h").write_text(render_params(pinned["src/primitives/block.h"].decode(), pinned["src/primitives/block.cpp"].decode()), encoding="utf-8")
    command = [compiler, "-O3", "-std=gnu11", "-Wall", "-Wextra", *args.cflag, *sdk_flags, "-pthread",
               "yespower-opt.c", "sha256.c", "paired-yespower-probe.c", "-o", "paired_yespower_probe"]
    subprocess.run(command, cwd=output, check=True, timeout=120)
    receipt = {
        "source": SOURCE, "tree": TREE, "compiler": subprocess.check_output([compiler, "--version"], text=True, timeout=10).splitlines()[0],
        "compiler_arguments": command, "production_input_sha256": {name: hashlib.sha256(content).hexdigest() for name, content in pinned.items()},
        "probe_sha256": hashlib.sha256((output / "paired_yespower_probe").read_bytes()).hexdigest(),
    }
    (output / "build.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("Built exact-source standalone scalar and paired probe")


if __name__ == "__main__":
    main()

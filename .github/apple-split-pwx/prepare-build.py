#!/usr/bin/env python3
"""Build one exact-source executable with generic and split PWX entries."""

import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess


HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "apple-fixed-proof"
PATCH_SHA = "da7a65f215dbf942916f0b8f916a95edb497578a1267ef1c378395548995f7f8"
RENAME = (
    "yespower", "yespower_tls", "yespower_init_local", "yespower_free_local",
    "blockmix_1_0", "blockmix_xor_1_0", "blockmix_xor_save_1_0", "blockmix_salsa_1_0", "blockmix_salsa_xor_1_0",
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cc", required=True)
    parser.add_argument("--cflag", action="append", default=[])
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("proof_sources", COMMON / "prepare-build.py")
    fixed = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixed)
    source, output = args.source.resolve(strict=True), args.output.resolve()
    if fixed.head(source, "HEAD") != fixed.SOURCE or fixed.head(source, "HEAD^{tree}") != fixed.TREE:
        parser.error("Unexpected source identity")
    if source == output or source in output.parents:
        parser.error("Build output must be outside the source checkout")
    compiler = shutil.which(args.cc)
    if compiler is None:
        parser.error("The requested compiler is unavailable")
    pinned = {name: fixed.exact(source, name) for name in fixed.INPUTS}
    with gzip.open(HERE / "split-pwx-product.patch.gz", "rb") as data:
        patch_contents = data.read(8193)
    if len(patch_contents) > 8192 or digest(patch_contents) != PATCH_SHA:
        raise ValueError("Unexpected split PWX patch")
    output.mkdir()
    patch = output / "split-pwx-product.patch"
    patch.write_bytes(patch_contents)
    original = output / "base"
    variant = output / "split" / fixed.VENDOR
    original.mkdir()
    variant.mkdir(parents=True)
    for name, contents in pinned.items():
        if name.startswith(fixed.VENDOR + "/"):
            for directory in (original, variant):
                (directory / Path(name).name).write_bytes(contents)
    for option in (["--check"], []):
        subprocess.run(["git", "apply", *option, str(patch)], cwd=output / "split", check=True, timeout=10)
    changed = [path.name for path in original.iterdir() if path.read_bytes() != (variant / path.name).read_bytes()]
    if changed != ["yespower-opt.c"]:
        raise ValueError("Only the candidate vendor PWX source may differ")
    (output / "sugar-params.h").write_text(fixed.render_params(pinned["src/primitives/block.h"].decode(),
        pinned["src/primitives/block.cpp"].decode()), encoding="utf-8")
    shutil.copyfile(COMMON / "probe-clock.h", output / "probe-clock.h")
    for name in ("fixed-probe.h", "fixed-yespower-probe.c"):
        text = (COMMON / name).read_text(encoding="utf-8")
        (output / name).write_text(text.replace("fixed_sugar_probe", "split_yespower").replace('"fixed"', '"split"').replace("generic|fixed", "generic|split"), encoding="utf-8")
    flags = [compiler, "-std=gnu11", "-Wall", "-Wextra", *args.cflag]
    candidate = str((variant / "yespower-opt.c").relative_to(output))
    commands = (
        [*flags, "-c", "base/yespower-opt.c", "-o", "base.o"],
        [*flags, *(f"-D{name}=split_{name}" for name in RENAME), "-c", candidate, "-o", "split.o"],
        [*flags, "-pthread", "-I", "base", "fixed-yespower-probe.c", "base/sha256.c", "base.o", "split.o", "-o", "split_yespower_probe"],
    )
    for command in commands:
        subprocess.run(command, cwd=output, check=True, timeout=120)
    receipt = {"source": fixed.SOURCE, "tree": fixed.TREE, "patch_sha256": PATCH_SHA, "commands": commands,
               "inputs": {name: digest(data) for name, data in pinned.items()},
               "candidate_source_sha256": digest((variant / "yespower-opt.c").read_bytes()),
               "binary_sha256": digest((output / "split_yespower_probe").read_bytes())}
    (output / "build.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Stage the known pool prototype outside the pinned product checkout."""

import argparse
import gzip
import hashlib
from pathlib import Path
import shutil
import subprocess

SOURCE = "9c502574b652804905d2533d51742ca91f694532"
TREE = "f44aa1b47f9701996046bbb396106f1d5c365e66"
HEADER = "src/support/allocators/pool.h"
PINS = {
    "POOL-CHUNK-BACKING.patch": "6e17b84e16f6b7eda3ee8fa8f691bce4a572f2ab6bc434bd5d45857cc2f40e38",
    "mapped_pool_arena.h": "0ac87d0fff2ef8961287fb8e7c98b24ab3eb7926d5641be3fc84b31d6eb58394",
    "pool_probe.cpp": "b70bf0b2d2b9f33c649a2ef5846c0ff221510647ce827bed01ad44f51067df74",
}
BASELINE_SHA = "6081b7de3a270b9c7d30db86c178b74025fe8c42a1f076ed36f4f7725770160b"
TOOLS = Path(__file__).resolve().parent


def require(ok, detail):
    if not ok:
        raise ValueError(detail)


def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args], timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(strict=True), args.output.resolve()
    require(source != output and source not in output.parents, "Stage outside product checkout")
    require(git(source, "rev-parse", "HEAD").decode().strip() == SOURCE and
            git(source, "rev-parse", "HEAD^{tree}").decode().strip() == TREE, "Unexpected product source identity")
    original = git(source, "show", f"{SOURCE}:{HEADER}")
    require((source / HEADER).read_bytes() == original and hashlib.sha256(original).hexdigest() == BASELINE_SHA,
            "Unexpected original pool header")
    require(git(source, "diff", "--exit-code", "HEAD", "--", "src") == b"", "Product source is modified")
    files = {name: (TOOLS / name).read_bytes() for name in ("mapped_pool_arena.h", "pool_probe.cpp")}
    with gzip.open(TOOLS / "POOL-CHUNK-BACKING.patch.gz", "rb") as payload:
        files["POOL-CHUNK-BACKING.patch"] = payload.read(8193)
    require(len(files["POOL-CHUNK-BACKING.patch"]) <= 8192, "Patch payload exceeds its size cap")
    require(all(hashlib.sha256(body).hexdigest() == PINS[name] for name, body in files.items()),
            "Prototype source digests differ")
    output.mkdir(mode=0o700)
    header = output / HEADER
    header.parent.mkdir(parents=True)
    header.write_bytes(original)
    (output / "pool-baseline.h").write_bytes(original)
    patch = output / "POOL-CHUNK-BACKING.patch"
    patch.write_bytes(files[patch.name])
    for option in (["--check"], []):
        subprocess.run(["git", "apply", *option, str(patch)], cwd=output, check=True, timeout=10)
    for name in ("pool_probe.cpp", "mapped_pool_arena.h"):
        (output / name).write_bytes(files[name])
    arena = output / "mapped_pool_arena.h"
    body = arena.read_bytes()
    needle = b"class AppleFileArena\n{\n"
    require(body.count(needle) == 1, "Unexpected arena class definition")
    arena.write_bytes(body.replace(needle, needle + b"    friend struct AppleFileArenaLifecycle;\n", 1))
    shutil.copyfile(TOOLS / "pool-lifecycle.cpp", output / "pool-lifecycle.cpp")
    require((source / HEADER).read_bytes() == original, "Product header changed during staging")
    print("Verified 9c inputs and staged one private pool hook; native arena only adds a read-only inspection friend.")


if __name__ == "__main__":
    main()

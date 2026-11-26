#!/usr/bin/env python3
"""Validate exact production headers and add two diagnostic calls in a private overlay."""

import hashlib
from pathlib import Path
import subprocess
import sys

SOURCE_COMMIT = "9c502574b652804905d2533d51742ca91f694532"
SOURCE_TREE = "f44aa1b47f9701996046bbb396106f1d5c365e66"
DIGESTS = {
    "node/blockmap.h": "196782d5eb1ec185ad78f55f3aa686e231130b902cae131fe77a5bc9141c8aa4",
    "chain.h": "58105b0ec03b5a69b52ea5aee191e35ec73f14c872394649c7e8f1735baad414",
    "support/allocators/pool.h": "6081b7de3a270b9c7d30db86c178b74025fe8c42a1f076ed36f4f7725770160b",
}
ALLOCATE = b"    void* Allocate(std::size_t bytes, std::size_t alignment)\n    {\n"
CHUNK = b"        m_allocated_chunks.emplace_back(m_available_memory_it);\n"


def insert(data, anchor, addition):
    if data.count(anchor) != 1:
        raise ValueError("Unexpected allocator layout")
    return data.replace(anchor, anchor + addition)


def main(source, output):
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD", "HEAD^{tree}"],
                                       text=True).splitlines()
    if revision != [SOURCE_COMMIT, SOURCE_TREE]:
        raise ValueError("Unexpected audited source commit or tree")
    subprocess.run(["git", "-C", str(source), "diff", "--quiet", "HEAD", "--", "src"], check=True)
    for name, expected in DIGESTS.items():
        data = (source / "src" / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"Unexpected input bytes for {name}")
    pool = (source / "src/support/allocators/pool.h").read_bytes()
    pool = insert(pool, ALLOCATE, b"        ::report::Allocate(bytes, alignment, IsFreeListUsable(bytes, alignment));\n")
    pool = insert(pool, CHUNK, b"        ::report::Chunk(m_chunk_size_bytes);\n")
    header = output / "support/allocators/pool.h"
    header.parent.mkdir(parents=True)
    header.write_bytes(pool)
    print(f"source_commit {SOURCE_COMMIT}\nsource_tree {SOURCE_TREE}")
    for name, digest in DIGESTS.items():
        print(f"{digest} {name}")
    print(f"{hashlib.sha256(pool).hexdigest()} overlay/support/allocators/pool.h")


if __name__ == "__main__":
    main(*(Path(arg).resolve() for arg in sys.argv[1:]))

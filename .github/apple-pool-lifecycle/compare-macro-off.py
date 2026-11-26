#!/usr/bin/env python3
"""Compare the entire preprocessed output, allowing one known assertion location to move."""

import argparse
import hashlib
from itertools import zip_longest
from pathlib import Path
import re


POOL_START = b"template <std::size_t MAX_BLOCK_SIZE_BYTES, std::size_t ALIGN_BYTES>"
CONDITION = b"m_chunk_size_bytes >= MAX_BLOCK_SIZE_BYTES"


def normalize(data, source, line):
    path = b"|".join(re.escape(bytes(name)) for name in (Path(source.name), source))
    pattern = re.compile(
        rb"(__assert_rtn\(\s*__func__\s*,\s*)\"(?:" + path + rb")\"(\s*,\s*)" + str(line).encode() +
        rb"(?=\s*,\s*\"" + re.escape(CONDITION) + rb"\"\s*\))"
    )
    compared, count = pattern.subn(rb'\g<1>"pool.h"\g<2>185', data)
    if count != 1:
        raise ValueError(f"Expected exactly one enabled pool assertion at {source.name}:{line}, found {count}")
    return compared


def first_difference(label, baseline, candidate):
    for number, (a, b) in enumerate(zip_longest(baseline.splitlines(), candidate.splitlines(), fillvalue=b""), 1):
        if a == b:
            continue
        column = next(i for i, (x, y) in enumerate(zip_longest(a, b)) if x != y)
        begin = max(0, column - 56)
        end = column + 96
        print(f"{label} first difference at line {number}, column {column + 1}")
        print(f"baseline {a[begin:end]!r}")
        print(f"macro-off {b[begin:end]!r}")
        return


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    inputs = (("baseline", args.stage / "pool-baseline.h", 185),
              ("macro-off", args.stage / "src/support/allocators/pool.h", 227))
    original = []
    for label, _, _ in inputs:
        data = (args.stage / f"{label}.ii").read_bytes()
        print(f"Raw {label} SHA-256 {hashlib.sha256(data).hexdigest()}", flush=True)
        original.append(data)
        begin = data.find(POOL_START)
        if begin != -1:
            # Record the project header portion without publishing all included SDK headers.
            with (args.output / f"{label}.pool.ii").open("xb") as evidence:
                evidence.write(data[begin:])
    first_difference("Raw", *original)
    normalized = [normalize(data, source, line) for data, (_, source, line) in zip(original, inputs, strict=True)]
    if normalized[0] != normalized[1]:
        first_difference("Normalized", *normalized)
        raise ValueError("Macro-off output differs beyond the pinned assertion source location")
    print(f"Normalized SHA-256 {hashlib.sha256(normalized[0]).hexdigest()}")
    print("Assertions enabled. Macro-off output matches after normalizing the one source location.")


if __name__ == "__main__":
    main()

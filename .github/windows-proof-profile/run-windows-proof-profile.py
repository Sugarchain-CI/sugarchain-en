#!/usr/bin/env python3
"""Prepare pinned En.7 and mainnet fixture inputs, then run one Windows profile."""

import argparse
import gzip
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
from urllib.request import urlopen
import zipfile

HERE = Path(__file__).resolve().parent
BASE_URL = "https://github.com/decryp2kanon/sugarchain-en/releases/download/v31.1.2-en.7/"
PORTABLE_HASH = {
    "ucrt": "acc8926e6ff11d6a5c230c86b27c7c953ea612afa236b259dfb70b47f29193b6",
    "msvcrt": "03fd8d51520b5548bb079b2ef763177dea44b873292955971b76ada393b4f7ba",
}
RAW_HASH = "f64a65677abdfa525b67d9a09291868fbfd1f9fb0d4089cdfafc3b2718dd07dd"
GZIP_HASH = "1d6b46da12f732190804a276b0c457d3c0ff923733ba29294f826eea971664ce"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def prepare_headers(fixture, count):
    compressed = fixture.read_bytes()
    if hashlib.sha256(compressed).hexdigest() != GZIP_HASH:
        raise ValueError("Wrong Mainnet 100,000-header fixture archive")
    raw = gzip.decompress(compressed)
    if len(raw) != 8_000_000 or hashlib.sha256(raw).hexdigest() != RAW_HASH:
        raise ValueError("Wrong Mainnet 100,000-header fixture payload")
    return raw[:count * 80]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crt", required=True, choices=PORTABLE_HASH)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--count", type=int, default=40000)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not 40000 <= args.count <= 100000 or args.count % 2000:
        parser.error("Use 40,000–100,000 headers divisible by 2,000")
    temp = args.output.resolve()
    temp.mkdir(parents=True)
    name = f"sugarchain-en-31.1.2-windows-x86_64-{args.crt}-portable"
    archive = temp / f"{name}.zip"
    with urlopen(BASE_URL + archive.name, timeout=90) as response, archive.open("wb") as stream:
        shutil.copyfileobj(response, stream)
    if digest(archive) != PORTABLE_HASH[args.crt]:
        raise ValueError("Published Windows archive hash differs")
    member = f"{name}/daemon/sugarchaind.exe"
    binary = temp / "sugarchaind.exe"
    with zipfile.ZipFile(archive) as package, package.open(member) as stream, binary.open("wb") as output:
        shutil.copyfileobj(stream, output)
    headers = prepare_headers(args.fixture, args.count)
    headers_path = temp / "headers.bin"
    headers_path.write_bytes(headers)
    subprocess.run([
        sys.executable, "-B", str(HERE / "windows-cold-proof.py"), "--crt", args.crt,
        "--binary", str(binary), "--headers", str(headers_path), "--headers-sha256",
        hashlib.sha256(headers).hexdigest(), "--count", str(args.count), "--output", str(temp / "profile"),
    ], check=True)


if __name__ == "__main__":
    main()

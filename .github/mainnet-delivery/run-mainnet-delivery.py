#!/usr/bin/env python3
"""Run the Mainnet delivery proxy with a pinned native En.7 CLI release."""
import argparse
import hashlib
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
from urllib.request import urlopen
import zipfile

HERE = Path(__file__).resolve().parent
URL = "https://github.com/decryp2kanon/sugarchain-en/releases/download/v31.1.2-en.7/"
PREFIX = "sugarchain-en-31.1.2-"
TARGETS = {
    "ucrt": {
        "archive": f"{PREFIX}windows-x86_64-ucrt-portable.zip",
        "archive_sha": "acc8926e6ff11d6a5c230c86b27c7c953ea612afa236b259dfb70b47f29193b6",
        "daemon_sha": "dd42ac39df4f52605751c610383432c81c497b44103912f90527bcd29c03da2a",
    },
    "msvcrt": {
        "archive": f"{PREFIX}windows-x86_64-msvcrt-portable.zip",
        "archive_sha": "03fd8d51520b5548bb079b2ef763177dea44b873292955971b76ada393b4f7ba",
        "daemon_sha": "e5ad7945b13e38d93a512287d6cfeca125da6546f0404b655e95c3b7d55c37a4",
    },
    "macos-arm64": {
        "archive": f"{PREFIX}macos-arm64-cli.tar.gz",
        "archive_sha": "00433459749009dc5bc8f537c025797e690d3caf6cfcec4e1a7b5dbc54abed02",
        "daemon_sha": "9509fc91b5c1f79b723257fd01056b3ed46fd10a19e85df99115f6fd9991cf26",
    },
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=TARGETS)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--fixture-info", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    mac = args.target == "macos-arm64"
    if mac and (platform.system(), platform.machine()) != ("Darwin", "arm64"):
        raise ValueError("Expected Apple Silicon macOS")
    if not mac and (platform.system() != "Windows" or platform.machine().lower() not in ("amd64", "x86_64")):
        raise ValueError("Expected Windows AMD64")
    job = TARGETS[args.target]
    output = args.output.resolve()
    output.mkdir(parents=True)
    bundle = output / job["archive"]
    with urlopen(URL + bundle.name, timeout=90) as response, bundle.open("wb") as stream:
        shutil.copyfileobj(response, stream)
    with bundle.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != job["archive_sha"]:
            raise ValueError("Pinned En.7 release checksum mismatch")
    binary = output / ("sugarchaind" if mac else "sugarchaind.exe")
    if mac:
        member_name = f"{bundle.name.removesuffix('.tar.gz')}/bin/sugarchaind"
        with tarfile.open(bundle, "r:gz") as archive, binary.open("wb") as destination:
            member = archive.getmember(member_name)
            if not member.isfile():
                raise ValueError("Invalid pinned daemon archive member")
            with archive.extractfile(member) as source:
                shutil.copyfileobj(source, destination)
        binary.chmod(0o700)
        subprocess.run(["codesign", "--verify", "--strict", str(binary)], check=True)
        require_arch = subprocess.check_output(["lipo", "-archs", str(binary)], text=True).strip()
        if require_arch != "arm64":
            raise ValueError("Expected released ARM64 executable")
    else:
        with zipfile.ZipFile(bundle) as archive, archive.open(f"{bundle.stem}/daemon/sugarchaind.exe") as source:
            with binary.open("wb") as destination:
                shutil.copyfileobj(source, destination)
    subprocess.run([
        sys.executable, "-B", str(HERE / "mainnet-delivery.py"), "--binary", str(binary), "--binary-sha256",
        job["daemon_sha"], "--fixture", str(args.fixture.resolve(strict=True)), "--fixture-info",
        str(args.fixture_info.resolve(strict=True)), "--output", str(output / "delivery"),
    ], check=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Download public Sugarchain release files and verify their signed SHA-256 list."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


TAG = "v31.1.1-en.1"
RELEASE = f"https://github.com/decryp2kanon/sugarchain-en/releases/download/{TAG}/"
KEY_URL = "https://github.com/decryp2kanon.gpg"
SIGNER = "CF8F465D97437DA3BB25534D92F37F683E41E891"
ASSET_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]*")
CHECKSUM_LINE = re.compile(r"([0-9a-f]{64}) [ *]([a-zA-Z0-9][a-zA-Z0-9._-]*)")
DOWNLOAD_HOSTS = {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}


def download(url, dest):
    request = Request(url, headers={"User-Agent": "Sugarchain-En-public-release-verify"})
    with urlopen(request, timeout=60) as response:
        endpoint = urlsplit(response.url)
        if endpoint.scheme != "https" or endpoint.hostname not in DOWNLOAD_HOSTS:
            raise RuntimeError(f"Unexpected download endpoint for {dest.name}")
        with dest.open("xb") as stream:
            shutil.copyfileobj(response, stream, length=1024 * 1024)


def gpg_path():
    found = shutil.which("gpg")
    if found:
        return found
    if os.name == "nt":
        git_gpg = Path(os.environ["ProgramFiles"]) / "Git/usr/bin/gpg.exe"
        if git_gpg.is_file():
            return str(git_gpg)
    raise RuntimeError("GnuPG is required to verify the release manifest")


def checksums(directory):
    unsigned = directory / "SHA256SUMS"
    signature = directory / "SHA256SUMS.asc"
    gpg = gpg_path()
    subprocess_env = os.environ.copy()
    subprocess_env["LC_ALL"] = "C"
    with tempfile.TemporaryDirectory(prefix=".pgp-", dir=directory, ignore_cleanup_errors=True) as temp:
        temporary = Path(temp)
        key = temporary / "signing-key.gpg"
        verified = temporary / "verified-sha256sums"
        download(KEY_URL, key)
        command = [gpg, "--no-options", "--homedir", temp, "--batch", "--no-tty"]
        try:
            subprocess.run(
                [*command, "--import", str(key)], check=True, timeout=60, env=subprocess_env,
            )
            result = subprocess.run(
                [*command, "--status-fd", "1", "--output", str(verified), "--decrypt", str(signature)],
                check=True, capture_output=True, encoding="ascii", errors="replace",
                timeout=60, env=subprocess_env,
            )
            signatures = [
                line.split()[2:]
                for line in result.stdout.splitlines()
                if line.startswith("[GNUPG:] VALIDSIG ")
            ]
            if len(signatures) != 1 or SIGNER not in {signatures[0][0], signatures[0][-1]}:
                raise RuntimeError("The manifest signer did not match the pinned release fingerprint")
            records = verified.read_bytes().splitlines()
            if records != unsigned.read_bytes().splitlines():
                raise RuntimeError("The verified and public checksum lists have different records")
        finally:
            executable = "gpgconf.exe" if os.name == "nt" else "gpgconf"
            gpgconf = Path(gpg).with_name(executable)
            if gpgconf.is_file():
                subprocess.run(
                    [str(gpgconf), "--homedir", temp, "--kill", "all"],
                    check=False, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
    entries = {}
    for record in records:
        match = CHECKSUM_LINE.fullmatch(record.decode("ascii"))
        if not match:
            raise RuntimeError("Unexpected SHA-256 manifest record")
        digest, name = match.groups()
        if name in entries:
            raise RuntimeError(f"Duplicate checksum for {name}")
        entries[name] = digest
    return entries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("assets", nargs="+", metavar="ASSET")
    args = parser.parse_args()
    if len(set(args.assets)) != len(args.assets):
        parser.error("Asset names must be unique")
    if any(not ASSET_NAME.fullmatch(name) for name in args.assets):
        parser.error("Each asset must be a plain filename")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    for manifest in ("SHA256SUMS", "SHA256SUMS.asc"):
        download(RELEASE + manifest, output / manifest)
    entries = checksums(output)
    report = {"tag": TAG, "signer_fingerprint": SIGNER, "assets": {}}
    for name in args.assets:
        if name not in entries:
            raise RuntimeError(f"No signed checksum for {name}")
        asset = output / name
        download(RELEASE + name, asset)
        with asset.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != entries[name]:
            raise RuntimeError(f"SHA-256 mismatch for {name}")
        report["assets"][name] = {"sha256": actual, "bytes": asset.stat().st_size}
        print(f"Verified signed SHA-256 for {name}", flush=True)
    (output / "integrity.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

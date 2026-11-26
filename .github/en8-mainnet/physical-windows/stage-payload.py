#!/usr/bin/env python3
"""Stage checksum-pinned public runtime inputs without starting a node."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import urllib.request
import zipfile


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def download(url, path, expected):
    if not url.startswith("https://"):
        raise ValueError("Only HTTPS artifact inputs are accepted")
    request = urllib.request.Request(url, headers={"User-Agent": "en8-native-comparison"})
    with urllib.request.urlopen(request, timeout=90) as response, path.open("xb") as target:
        shutil.copyfileobj(response, target, 1024 * 1024)
    if digest(path) != expected:
        raise ValueError(f"Input checksum mismatch: {path.name}")


def main():
    config_path = Path(sys.argv[1]).resolve()
    config = json.loads(config_path.read_text(encoding="utf-8-sig"))
    root = config_path.parent
    payload = root / "payload"
    payload.mkdir(exist_ok=False)
    manifest_bytes = config["manifest"].encode("utf-8")
    if hashlib.sha256(manifest_bytes).hexdigest() != config["manifest_sha256"]:
        raise ValueError("Manifest checksum mismatch")
    manifest = json.loads(manifest_bytes)["files"]
    members = ("SHA256SUMS.release-inputs", "release-source-sha.txt",
               "release-source-tree.txt", "bin/sugarchaind.exe")
    for entry in config["artifacts"]:
        role, crt = entry["role"], entry["crt"]
        if role not in ("baseline", "candidate") or crt not in ("ucrt", "msvcrt"):
            raise ValueError("Unexpected package identity")
        archive = root / f"{role}-{crt}.zip"
        download(entry["url"], archive, entry["digest"].removeprefix("sha256:"))
        with zipfile.ZipFile(archive) as package:
            for member in members:
                name = f"{role}/{crt}/{member}"
                destination = payload / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                if package.namelist().count(member) != 1:
                    raise ValueError(f"Expected one archive member: {name}")
                with package.open(member) as source, destination.open("xb") as target:
                    shutil.copyfileobj(source, target, 1024 * 1024)
                if digest(destination) != manifest[name]:
                    raise ValueError(f"Extracted checksum mismatch: {name}")
        print(f"Verified {role} {crt}", flush=True)
    for name, url in config["raw_inputs"].items():
        if name not in manifest or name.startswith("/") or ".." in Path(name).parts:
            raise ValueError("Unexpected helper name")
        destination = payload / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        download(url, destination, manifest[name])
    actual = {str(p.relative_to(payload)).replace("\\", "/"): digest(p)
              for p in payload.rglob("*") if p.is_file()}
    if actual != manifest:
        raise ValueError("Staged file set differs from the pinned manifest")
    (payload / "manifest.json").write_bytes(manifest_bytes)
    download(config["runner_url"], root / "run-sumi-mainnet-pairs.ps1", config["runner_sha256"])
    print(json.dumps({"payload": str(payload), "files": len(actual),
                      "manifest_sha256": config["manifest_sha256"]}), flush=True)


if __name__ == "__main__":
    main()

"""Authenticate the retained Apple ARM64 control without compiling it."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess


RUN = 45929559984
ARTIFACT = "apple-ordinary-cross-control"
SOURCE = "2a0f1a9679f6b25c8bfefddd571b9572a3372233"
TREE = "585f08d47bc953b7863d2fc3ba51f3ea762bc36f"
BUILD = "55f75504d5060ef71c4fcf74ba0ded20afceaf824903226151e2458219498aa3"
TRANSFER = "c57a95bc04c63e9af807671a6e33a9d93c8feb849bb375050360306d1baaf846"
SIGNED = "a3a93b41f26fc243605c539c60b0420e46efcaa3c7d3b43388be9838460c746f"


def require(ok, error):
    if not ok:
        raise ValueError(error)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_transfer(artifact: Path):
    require({p.name for p in artifact.iterdir()} == {"build.json", "sugarchaind"}, "Unexpected retained files")
    build, binary = (artifact / name for name in ("build.json", "sugarchaind"))
    require(digest(build) == BUILD and digest(binary) == TRANSFER, "Retained artifact digest mismatch")
    manifest = json.loads(build.read_bytes())
    require((manifest["role"], manifest["source"], manifest["tree"], manifest["files"]) ==
            ("control", SOURCE, TREE, {"sugarchaind": TRANSFER}), "Retained source or build identity differs")
    with binary.open("rb") as stream:
        require(stream.read(8) == bytes.fromhex("cffaedfe0c000001"), "Retained daemon is not a thin ARM64 Mach-O")
    return binary


def stage(artifact, output):
    source = verify_transfer(artifact)
    output.mkdir()
    binary = output / source.name
    shutil.copyfile(source, binary)
    binary.chmod(0o755)
    arch = subprocess.check_output(["/usr/bin/lipo", "-archs", binary], text=True, timeout=10).strip()
    require(arch == "arm64", "Retained daemon architecture differs")
    libs = subprocess.check_output(["/usr/bin/otool", "-L", binary], text=True, timeout=10).splitlines()[1:]
    require(libs and all(l.split()[0].startswith(("/usr/lib/", "/System/Library/")) for l in libs),
            "Retained daemon has a non-system library")
    signature = ["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", binary]
    subprocess.run(signature, check=True, timeout=30)
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", binary], check=True, timeout=30)
    require(digest(binary) == SIGNED, "Signed daemon bytes differ from the previous successful native control")
    payload = {"run": RUN, "artifact": ARTIFACT, "source": SOURCE, "tree": TREE, "build_receipt_sha256": BUILD,
               "transfer_sha256": TRANSFER, "native_sha256": SIGNED, "architecture": arch}
    return binary, payload

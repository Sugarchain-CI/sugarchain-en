"""Immutable source and workload identity for the Apple batch-only experiment."""

from pathlib import Path
import hashlib


STOCK_PARENT = "9c502574b652804905d2533d51742ca91f694532"
SOURCES = {
    "candidate": ("50e84a59e2b0b4aef0986adce83e124e76eff524", "8cc7dd2f2fb842a17f2aeec9a6adfe157443e47b"),
    "control": ("ae5e984447c25e03472b43b8e6341130ccc76b68", "a4c67b35ba18eb98b97da5493bf187aad2588a29"),
}
CONTROL_DIFF = "5ac4e14bd4e334aec64f3679ad393f1950cf1bbbfd02d83b170dcaa1481296ce"
ARCHIVE_SHA = "1d6b46da12f732190804a276b0c457d3c0ff923733ba29294f826eea971664ce"
HEADER_SHA = "f64a65677abdfa525b67d9a09291868fbfd1f9fb0d4089cdfafc3b2718dd07dd"
HEADER_TIP = "b62290c6914adee9b29326b8a4567114fff1f9013acb9c3b6ff68612a2947f99"
ORDER = ("control", "candidate", "candidate", "control")
SETTINGS = ((1, 4000), (3, 4000), (8, 40000))
PEER_DELAY = 0.200


def file_sha(path: Path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

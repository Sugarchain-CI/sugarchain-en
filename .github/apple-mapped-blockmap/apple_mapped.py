"""Private Apple mapped block-map capacity checks for the existing qualifier."""

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

SOURCE = "e4499228a8d3a293ddd3be66549b98bcc7641519"
TREE = "5c766f5e57ce1746fd4a249822f6c19c591ff67e"
FLAG = "-DSUGARCHAIN_FILE_BACKED_POOL_DIAGNOSTIC"
ROWS = 44_946_269
FILE_CHUNKS = 34_310
ARENA_BYTES = FILE_CHUNKS * 262_144
MEMORY_BYTES = 7 << 30
MANIFEST = "private-runtime.sha256"
MEMBERS = {"sugarchaind", "test_bitcoin", "source-commit.txt", "source-tree.txt", "compile-audit.json"}
RESERVING = f"Mapped block map reserving {ARENA_BYTES} bytes for {ROWS} rows"
RESERVED = "Mapped block map reservation complete"
LOADED = f"Mapped block map loaded {ROWS} rows using {FILE_CHUNKS} mapped chunks and one initial heap chunk"
PHASE_PREFIXES = (
    "Counting block index entries", "Counted ", RESERVING, RESERVED, "Loading block index",
    LOADED, "Linking block index", "Selecting best block header", "Block index and chainstate loaded",
    "Shutdown: In progress", "Shutdown done",
)
STAMP = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)\s+(.+)$")


def digest(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def require(condition, error):
    if not condition:
        raise ValueError(error)


def manifest(folder, *, signed=False):
    name = "native-runtime.sha256" if signed else MANIFEST
    files = {}
    for line in (folder / name).read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
        require(match is not None, "Malformed private runtime checksum line")
        sha, member = match.groups()
        require(member in MEMBERS and member not in files, "Unexpected private runtime member")
        files[member] = sha
    require(files.keys() == MEMBERS, "Incomplete private runtime manifest")
    for member, expected in files.items():
        path = folder / member
        require(path.is_file() and not path.is_symlink() and digest(path) == expected,
                f"Unexpected private runtime digest for {member}")
    require((folder / "source-commit.txt").read_text().strip() == SOURCE and
            (folder / "source-tree.txt").read_text().strip() == TREE,
            "Unexpected private runtime source identity")
    audit = json.loads((folder / "compile-audit.json").read_text())
    require(audit["flag"] == FLAG and audit["source"] == SOURCE and audit["tree"] == TREE and
            audit["cxx_translation_unit_count"] > 100, "Unexpected private compile audit")
    return files


def native_shape(binary):
    architecture = subprocess.check_output(["lipo", "-archs", str(binary)], timeout=10, text=True).strip()
    require(architecture == "arm64", "Expected a thin Apple Silicon Mach-O runtime")
    with binary.open("rb") as handle:
        require(handle.read(8) == bytes.fromhex("cffaedfe0c000001"), "Wrong Mach-O header")
    lines = subprocess.check_output(["otool", "-L", str(binary)], timeout=15, text=True).splitlines()[1:]
    paths = [line.split()[0] for line in lines if line.split()]
    require(paths and all(path.startswith(("/usr/lib/", "/System/Library/")) for path in paths),
            "Private runtime has unexpected dynamic dependencies")


def stage(incoming, output):
    manifest(incoming)
    output.mkdir()
    for name in sorted(MEMBERS):
        shutil.copy2(incoming / name, output / name)
    for name in ("sugarchaind", "test_bitcoin"):
        binary = output / name
        native_shape(binary)
        binary.chmod(0o755)
        subprocess.run(["codesign", "--force", "--sign", "-", "--timestamp=none", str(binary)], timeout=20, check=True)
        subprocess.run(["codesign", "--verify", "--strict", str(binary)], timeout=20, check=True)
    (output / "native-runtime.sha256").write_text("".join(f"{digest(output / name)}  {name}\n" for name in sorted(MEMBERS)))


def runtime(folder):
    members = manifest(folder, signed=True)
    binary = folder.resolve() / "sugarchaind"
    native_shape(binary)
    subprocess.run(["codesign", "--verify", "--strict", str(binary)], timeout=20, check=True)
    return {"source": SOURCE, "tree": TREE, "binary": str(binary), "binary_sha256": members["sugarchaind"],
            "runtime_manifest_sha256": digest(folder / "native-runtime.sha256"), "package_members": members}


def log_receipt(text):
    markers = []
    for line in text.splitlines():
        match = STAMP.match(line)
        if match and match[2].startswith(PHASE_PREFIXES):
            message = match[2]
            markers.append({"utc": match[1], "message": message})
    messages = [row["message"] for row in markers]
    expected = (RESERVING, RESERVED, LOADED)
    positions = [messages.index(mark) for mark in expected if messages.count(mark) == 1]
    return {"exercised": len(positions) == len(expected) and positions == sorted(positions), "markers": markers}


if __name__ == "__main__":
    import sys
    stage(*map(Path, sys.argv[1:]))

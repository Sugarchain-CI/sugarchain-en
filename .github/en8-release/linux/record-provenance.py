"""Bind the package, release source and verification logs."""

import hashlib
import json
import os
from pathlib import Path
import sys


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


package = Path(sys.argv[1])
target = os.environ["RELEASE_HOST"]
mode = os.environ["RELEASE_MODE"]
out = package.parent
source = (out / "release-source-sha.txt").read_text(encoding="ascii").strip()
tree = (out / "release-source-tree.txt").read_text(encoding="ascii").strip()
assert source == os.environ["SOURCE_REVISION"] and tree == os.environ["SOURCE_TREE"]
assert package.name == f"sugarchain-en-31.1.2-{target}.tar.gz"
sha = sha256(package)
assert (out / "package.sha256").read_text(encoding="ascii") == f"{sha}  {package.name}\n"

verification = ["ELF class, machine, endianness and library dependencies", "Qt font backend linkage and package contents"]
if mode == "native":
    verification.append("Native program versions, GUI X11/XWayland, Mainnet genesis, wallet prefix and clean stop")
    assert (out / "checks" / "native-smoke.txt").is_file()
if target == "x86_64-linux-gnu":
    verification.append("Testnet7 Qt, focused unit and crypto vectors, and native Mainnet header proof protocol")
    for filename in ("focused-unit.xml", "focused-crypto.xml", "focused-p2p-framework.log",
                     "qt-wayland-testnet7.log", "qt-x11-testnet7.log"):
        assert (out / "checks" / filename).is_file(), filename

evidence = {str(path.relative_to(out)): sha256(path) for path in sorted((out / "checks").iterdir()) if path.is_file()}
provenance = {
    "status": "verified_linux_package",
    "release_tag": os.environ["RELEASE_TAG"],
    "repository": "decryp2kanon/sugarchain-en",
    "source": source,
    "tree": tree,
    "workflow": os.environ["GITHUB_WORKFLOW_REF"],
    "workflow_sha": os.environ["GITHUB_SHA"],
    "run_id": os.environ["GITHUB_RUN_ID"],
    "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
    "target": target,
    "mode": mode,
    "artifact": f"en8-release-linux-{target}",
    "package": package.name,
    "package_sha256": sha,
    "package_bytes": package.stat().st_size,
    "verification": verification,
    "check_sha256": evidence,
}
with (out / "provenance.json").open("x", encoding="utf-8") as output:
    json.dump(provenance, output, indent=2, sort_keys=True)
    output.write("\n")

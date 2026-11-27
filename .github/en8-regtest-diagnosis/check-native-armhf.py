#!/usr/bin/env python3
"""Test the ARM64 Linux kernel's ability to execute native AArch32 user code."""

import json
import platform
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


# Only rely on bytes constrained by the ELF32 little-endian ARM executable
# format. OS ABI, flags, entry point and offsets differ across the probe,
# daemon and Qt binary. ET_EXEC and ET_DYN are both permitted.
ELF32_ARM_BYTES = {
    **{offset: (value,) for offset, value in enumerate(b"\x7fELF\x01\x01\x01")},
    16: (2, 3),
    17: (0,),
    18: (40,),
    19: (0,),
    20: (1,),
    21: (0,),
    22: (0,),
    23: (0,),
}


def disjoint_handler(entry: str) -> str | None:
    """Return an exclusion reason when an enabled handler cannot match."""
    lines = entry.splitlines()
    if not lines:
        return None
    if lines[0] == "disabled":
        return "disabled"
    if lines[0] != "enabled":
        return None

    fields = dict(line.split(" ", 1) for line in lines[1:] if " " in line)
    extension = fields.get("extension")
    if extension and "magic" not in fields:
        # All three executable basenames are extensionless.
        return "extension"
    try:
        magic = bytes.fromhex(fields["magic"])
        mask = bytes.fromhex(fields["mask"]) if "mask" in fields else b"\xff" * len(magic)
        offset = int(fields["offset"])
    except (KeyError, ValueError):
        return None
    if not magic or len(magic) != len(mask) or offset < 0:
        return None
    for index, (value, bits) in enumerate(zip(magic, mask)):
        possible = ELF32_ARM_BYTES.get(offset + index)
        if possible and all(candidate & bits != value & bits for candidate in possible):
            return "disjoint ELF magic"
    return None


def run_aarch32_probe(output: Path) -> dict:
    host = platform.machine()
    if platform.system() != "Linux" or host != "aarch64":
        return {"supported": False, "reason": "Expected a Linux AArch64 host", "host": host}

    binfmt = Path("/proc/sys/fs/binfmt_misc")
    try:
        status = (binfmt / "status").read_text().strip()
        entries = {
            path.name: disjoint_handler(path.read_text())
            for path in binfmt.iterdir()
            if path.name not in {"status", "register"}
        } if status == "enabled" else {}
    except OSError as exc:
        return {"supported": False, "reason": f"Cannot inspect foreign ELF handlers ({exc.strerror})", "host": host}
    if status not in {"enabled", "disabled"} or any(reason is None for reason in entries.values()):
        return {"supported": False, "reason": "A foreign executable handler could match ARM ELF", "host": host, "handlers": entries}

    # A standalone ELF32 ARM executable calls exit(0) directly. It needs no
    # dynamic loader or libraries, so failure here cannot be a missing libc.
    entry = 0x10000 + 52 + 32
    ident = b"\x7fELF\x01\x01\x01" + bytes(9)
    header = struct.pack("<16sHHIIIIIHHHHHH", ident, 2, 40, 1, entry, 52, 0,
                         0x05000400, 52, 32, 1, 0, 0, 0)
    code = struct.pack("<III", 0xE3A00000, 0xE3A07001, 0xEF000000)
    size = len(header) + 32 + len(code)
    segment = struct.pack("<IIIIIIII", 1, 0, 0x10000, 0x10000, size, size, 5, 4096)

    with tempfile.TemporaryDirectory(dir=output.parent, prefix="aarch32-") as directory:
        executable = Path(directory) / "probe"
        executable.write_bytes(header + segment + code)
        executable.chmod(0o700)
        try:
            completed = subprocess.run([str(executable.resolve())], timeout=3, check=False)
        except OSError as exc:
            return {"supported": False, "reason": f"Kernel rejected the native AArch32 probe ({exc.strerror})", "host": host, "handlers": entries}
        except subprocess.TimeoutExpired:
            return {"supported": False, "reason": "Native AArch32 probe did not exit within three seconds", "host": host, "handlers": entries}

    return {
        "supported": completed.returncode == 0,
        "reason": "Native ELF32 ARM executed through the Linux kernel" if completed.returncode == 0 else "Native ELF32 ARM probe exited unsuccessfully",
        "host": host,
        "probe_exit_status": completed.returncode,
        "handlers": entries,
    }


def main() -> int:
    output = Path(sys.argv[1])
    output.parent.mkdir(parents=True, exist_ok=True)
    result = run_aarch32_probe(output)
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(result["reason"])
    return 0 if result["supported"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

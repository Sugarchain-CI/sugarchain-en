#!/usr/bin/env python3
"""Test the ARM64 Linux kernel's ability to execute native AArch32 user code."""

import json
import platform
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


def run_aarch32_probe(output: Path) -> dict:
    host = platform.machine()
    if platform.system() != "Linux" or host != "aarch64":
        return {"supported": False, "reason": "Expected a Linux AArch64 host", "host": host}

    binfmt = Path("/proc/sys/fs/binfmt_misc")
    try:
        status = (binfmt / "status").read_text().strip()
        enabled = [
            path.name
            for path in binfmt.iterdir()
            if path.name not in {"status", "register"} and path.read_text().startswith("enabled\n")
        ] if status == "enabled" else []
    except OSError as exc:
        return {"supported": False, "reason": f"Cannot verify that foreign ELF handlers are disabled ({exc.strerror})", "host": host}
    if status not in {"enabled", "disabled"} or enabled:
        return {"supported": False, "reason": "Cannot rule out foreign ELF execution handlers", "host": host, "handlers": enabled}

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
            return {"supported": False, "reason": f"Kernel rejected the native AArch32 probe ({exc.strerror})", "host": host}
        except subprocess.TimeoutExpired:
            return {"supported": False, "reason": "Native AArch32 probe did not exit within three seconds", "host": host}

    return {
        "supported": completed.returncode == 0,
        "reason": "Native ELF32 ARM exited directly through the Linux kernel",
        "host": host,
        "probe_exit_status": completed.returncode,
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

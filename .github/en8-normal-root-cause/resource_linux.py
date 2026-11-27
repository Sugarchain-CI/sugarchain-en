"""Cumulative Linux CPU and I/O counters for an owned live child."""

import os
from pathlib import Path
import time


def sample(pid: int) -> dict:
    if type(pid) is not int or pid <= 0:
        raise ValueError("Expected a positive owned process ID")
    proc = Path("/proc") / str(pid)
    prefix, separator, fields = (proc / "stat").read_text(encoding="ascii", errors="replace").rpartition(") ")
    if not separator or prefix.split(" ", 1)[0] != str(pid):
        raise RuntimeError("Malformed Linux process statistics")
    # The fields after the task name begin at stat field 3.
    fields = fields.split()
    tick_hz = os.sysconf("SC_CLK_TCK")
    page_size = os.sysconf("SC_PAGE_SIZE")
    io = {}
    for line in (proc / "io").read_text(encoding="ascii").splitlines():
        key, value = line.split(":", 1)
        io[key] = int(value)
    return {
        "pid": pid,
        "process_start_identity": f"proc_stat_starttime:{int(fields[19])}",
        "sampled_monotonic_ns": time.monotonic_ns(),
        "cpu_user_seconds": int(fields[11]) / tick_hz,
        "cpu_system_seconds": int(fields[12]) / tick_hz,
        "read_bytes": io["read_bytes"],
        "write_bytes": io["write_bytes"],
        "io_byte_semantics": "Linux /proc/pid/io storage-layer read_bytes and write_bytes",
        "rchar": io["rchar"],
        "wchar": io["wchar"],
        "syscr": io["syscr"],
        "syscw": io["syscw"],
        "cancelled_write_bytes": io["cancelled_write_bytes"],
        "resident_bytes": int(fields[21]) * page_size,
        "source": "Linux /proc/pid/stat and /proc/pid/io",
    }

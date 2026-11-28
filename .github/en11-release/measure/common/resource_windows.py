"""Read cumulative CPU and logical I/O counters for a caller-owned Windows PID."""

import ctypes
from functools import lru_cache
import sys
import time

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
DWORD = ctypes.c_uint32
BOOL = ctypes.c_int32
HANDLE = ctypes.c_void_p


class FileTime(ctypes.Structure):
    _fields_ = [("low", DWORD), ("high", DWORD)]

    def ticks(self):
        return (self.high << 32) | self.low


class IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "read_operations", "write_operations", "other_operations",
        "read_bytes", "write_bytes", "other_bytes",
    )]


@lru_cache(maxsize=1)
def _kernel():
    if sys.platform != "win32":
        raise NotImplementedError("Windows process accounting requires native Windows")
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.OpenProcess.argtypes = [DWORD, BOOL, DWORD]
    api.OpenProcess.restype = HANDLE
    api.GetProcessTimes.argtypes = [HANDLE, *[ctypes.POINTER(FileTime)] * 4]
    api.GetProcessTimes.restype = BOOL
    api.GetProcessIoCounters.argtypes = [HANDLE, ctypes.POINTER(IoCounters)]
    api.GetProcessIoCounters.restype = BOOL
    api.CloseHandle.argtypes = [HANDLE]
    api.CloseHandle.restype = BOOL
    return api


def _error(operation, pid):
    error = ctypes.WinError(ctypes.get_last_error())
    error.add_note(f"{operation} failed for owned Windows PID {pid}")
    return error


def snapshot(pid: int) -> dict[str, int | float | str]:
    """Sample a child PID explicitly supplied by its owner. Pair snapshots by creation time."""
    if type(pid) is not int or not 0 < pid <= 0xFFFFFFFF:
        raise ValueError("Expected a positive Windows process ID")
    api = _kernel()
    handle = api.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        raise _error("OpenProcess", pid)
    try:
        creation, exited, kernel, user = (FileTime() for _ in range(4))
        counters = IoCounters()
        before = time.monotonic()
        if not api.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user)):
            raise _error("GetProcessTimes", pid)
        if not api.GetProcessIoCounters(handle, ctypes.byref(counters)):
            raise _error("GetProcessIoCounters", pid)
        after = time.monotonic()
        return {
            "pid": pid,
            "process_creation_time_100ns": creation.ticks(),
            "monotonic_sample_seconds": (before + after) / 2,
            "sample_window_seconds": after - before,
            "cpu_user_seconds": user.ticks() / 10_000_000,
            "cpu_system_seconds": kernel.ticks() / 10_000_000,
            "read_bytes": counters.read_bytes,
            "write_bytes": counters.write_bytes,
            "io_read_operations": counters.read_operations,
            "io_write_operations": counters.write_operations,
            "io_other_operations": counters.other_operations,
            "io_read_bytes": counters.read_bytes,
            "io_write_bytes": counters.write_bytes,
            "io_other_bytes": counters.other_bytes,
            "io_semantics": "Windows logical transfer counters; not physical disk",
        }
    finally:
        if not api.CloseHandle(handle) and sys.exception() is None:
            raise _error("CloseHandle", pid)


sample = snapshot

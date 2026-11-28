"""Read cumulative resource counters from one live-owned Darwin process."""
import ctypes
import errno
from functools import lru_cache
import os
import sys
import time


class _RUsageInfoV2(ctypes.Structure):
    # XNU bsd/sys/resource.h, struct rusage_info_v2.
    _fields_ = [("ri_uuid", ctypes.c_uint8 * 16)] + [
        (field, ctypes.c_uint64)
        for field in (
            "ri_user_time",
            "ri_system_time",
            "ri_pkg_idle_wkups",
            "ri_interrupt_wkups",
            "ri_pageins",
            "ri_wired_size",
            "ri_resident_size",
            "ri_phys_footprint",
            "ri_proc_start_abstime",
            "ri_proc_exit_abstime",
            "ri_child_user_time",
            "ri_child_system_time",
            "ri_child_pkg_idle_wkups",
            "ri_child_interrupt_wkups",
            "ri_child_pageins",
            "ri_child_elapsed_abstime",
            "ri_diskio_bytesread",
            "ri_diskio_byteswritten",
        )
    ]


class _MachTimebase(ctypes.Structure):
    _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]


_RUSAGE_INFO_V2 = 2


@lru_cache(maxsize=1)
def _native():
    if sys.platform != "darwin" or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise RuntimeError("Darwin PID resource counters require 64-bit macOS")
    if (
        ctypes.sizeof(_RUsageInfoV2) != 160
        or _RUsageInfoV2.ri_proc_start_abstime.offset != 80
        or _RUsageInfoV2.ri_diskio_bytesread.offset != 144
        or _RUsageInfoV2.ri_diskio_byteswritten.offset != 152
    ):
        raise RuntimeError("unexpected Darwin rusage_info_v2 ctypes layout")

    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    read_usage = libproc.proc_pid_rusage
    read_usage.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
    read_usage.restype = ctypes.c_int

    libsystem = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    read_timebase = libsystem.mach_timebase_info
    read_timebase.argtypes = (ctypes.POINTER(_MachTimebase),)
    read_timebase.restype = ctypes.c_int
    timebase = _MachTimebase()
    status = read_timebase(ctypes.byref(timebase))
    if status != 0 or timebase.numer == 0 or timebase.denom == 0:
        raise RuntimeError(f"mach_timebase_info returned invalid timebase (status {status})")
    return read_usage, timebase.numer, timebase.denom


def sample(pid: int) -> dict:
    """Sample an owned child PID while its handle remains alive and unreaped.

    Compare consecutive counters only when PID and process_start_abstime match.
    I/O values are task-attributed Darwin disk bytes. Page-ins are a narrower
    count than all VM faults. The calling harness owns process lifecycle checks.
    """
    if type(pid) is not int or not 0 < pid <= 2**31 - 1:
        raise ValueError("pid must be a positive Darwin pid_t")

    read_usage, numer, denom = _native()
    usage = _RUsageInfoV2()
    ctypes.set_errno(0)
    sampled_start = time.monotonic_ns()
    status = read_usage(pid, _RUSAGE_INFO_V2, ctypes.byref(usage))
    sampled_end = time.monotonic_ns()
    if status != 0:
        error = ctypes.get_errno() or errno.EIO
        raise OSError(error, f"proc_pid_rusage({pid}, RUSAGE_INFO_V2): {os.strerror(error)}")
    if usage.ri_proc_start_abstime == 0 or usage.ri_proc_exit_abstime != 0:
        raise ProcessLookupError(errno.ESRCH, f"no live process identity for PID {pid}")

    def seconds(ticks):
        return ticks * numer / (denom * 1_000_000_000)

    return {
        "pid": pid,
        "process_start_abstime": usage.ri_proc_start_abstime,
        "sampled_monotonic_ns": sampled_end,
        "sample_duration_ns": sampled_end - sampled_start,
        "cpu_user_seconds": seconds(usage.ri_user_time),
        "cpu_system_seconds": seconds(usage.ri_system_time),
        "read_bytes": usage.ri_diskio_bytesread,
        "write_bytes": usage.ri_diskio_byteswritten,
        "page_ins": usage.ri_pageins,
        "resident_bytes": usage.ri_resident_size,
        "physical_footprint_bytes": usage.ri_phys_footprint,
        "source": "Darwin proc_pid_rusage RUSAGE_INFO_V2",
        "io_semantics": "task-attributed disk I/O bytes",
    }


snapshot = sample

"""Record bounded owned-process measurements on a native Windows AMD64 runner."""

import ctypes
from ctypes import wintypes
import os
import platform


class MemoryStatus(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("load", wintypes.DWORD)] + [
        (name, ctypes.c_ulonglong) for name in (
            "total_physical", "available_physical", "total_commit", "available_commit",
            "total_virtual", "available_virtual", "extended_virtual",
        )
    ]


class MemoryCounters(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
        (name, ctypes.c_size_t) for name in (
            "peak_working_set", "working_set", "quota_peak_paged_pool", "quota_paged_pool",
            "quota_peak_nonpaged_pool", "quota_nonpaged_pool", "pagefile_usage", "peak_pagefile_usage",
            "private_usage",
        )
    ]


class IOCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "read_operations", "write_operations", "other_operations", "read_bytes", "write_bytes", "other_bytes",
    )]


def function(library, name, arguments, result=wintypes.BOOL):
    query = getattr(library, name)
    query.argtypes = arguments
    query.restype = result
    return query


def checked(success):
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())


class Resources:
    def __init__(self):
        if platform.system() != "Windows" or platform.machine() not in ("AMD64", "x86_64"):
            raise RuntimeError("This comparison requires native Windows AMD64")
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        current = function(kernel, "GetCurrentProcess", [], wintypes.HANDLE)
        wow64 = function(kernel, "IsWow64Process2", [wintypes.HANDLE, ctypes.POINTER(wintypes.USHORT),
                                                   ctypes.POINTER(wintypes.USHORT)])
        proc, host = wintypes.USHORT(), wintypes.USHORT()
        checked(wow64(current(), ctypes.byref(proc), ctypes.byref(host)))
        if proc.value or host.value != 0x8664 or hasattr(ctypes.WinDLL("ntdll"), "wine_get_version"):
            raise RuntimeError("WOW64 or Wine cannot qualify this native comparison")
        self.host_memory = function(kernel, "GlobalMemoryStatusEx", [ctypes.POINTER(MemoryStatus)])
        self.times = function(kernel, "GetProcessTimes", [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4)
        self.io = function(kernel, "GetProcessIoCounters", [wintypes.HANDLE, ctypes.POINTER(IOCounters)])
        self.memory = function(ctypes.WinDLL("psapi", use_last_error=True), "GetProcessMemoryInfo",
                               [wintypes.HANDLE, ctypes.POINTER(MemoryCounters), wintypes.DWORD])

    def host(self):
        memory = MemoryStatus(size=ctypes.sizeof(MemoryStatus))
        checked(self.host_memory(ctypes.byref(memory)))
        return {
            "os": platform.platform(), "logical_cpus": os.cpu_count(),
            "cpu": os.environ.get("PROCESSOR_IDENTIFIER") or platform.processor(),
            "image": os.environ.get("ImageOS"), "image_version": os.environ.get("ImageVersion"),
            "physical_bytes": memory.total_physical, "available_physical_bytes": memory.available_physical,
            "total_commit_bytes": memory.total_commit, "available_commit_bytes": memory.available_commit,
        }

    def sample(self, process):
        handle = wintypes.HANDLE(int(process._handle))
        times = [wintypes.FILETIME() for _ in range(4)]
        memory = MemoryCounters(cb=ctypes.sizeof(MemoryCounters))
        io = IOCounters()
        checked(self.times(handle, *(ctypes.byref(value) for value in times)))
        checked(self.memory(handle, ctypes.byref(memory), memory.cb))
        checked(self.io(handle, ctypes.byref(io)))
        cpu = sum((value.dwHighDateTime << 32) | value.dwLowDateTime for value in times[2:])
        return {
            "cpu_seconds": cpu / 10_000_000, "working_set_bytes": memory.working_set,
            "peak_working_set_bytes": memory.peak_working_set, "private_usage_bytes": memory.private_usage,
            "io_read_bytes": io.read_bytes, "io_write_bytes": io.write_bytes, "io_other_bytes": io.other_bytes,
            "io_read_operations": io.read_operations, "io_write_operations": io.write_operations,
            "io_other_operations": io.other_operations,
        }

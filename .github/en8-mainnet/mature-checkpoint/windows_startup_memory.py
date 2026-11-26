"""Bounded Windows metadata sampling for a single owned checkpoint child."""

from bisect import bisect_right
from collections import defaultdict
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import threading
import time

# Keep the fixed comparison checkpoints and add one observation when the
# count starts, so a faster candidate can finish counting before 15 seconds.
SAMPLE_SECONDS = (0, 15, 30, 90)
PHASE_POLL_SECONDS = 0.25
COUNT_PHASE = "counting_index_rows"
BEFORE_COUNT_PHASES = {"process_initialization", "before_index_phase"}
SAMPLE_BUDGET_SECONDS = 3
MAX_REGIONS = 32768
MAX_GROUP_PAGES = 1024
QUERY_BATCH = 256
NAME_CAPACITY = 1024
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000
ERROR_INVALID_PARAMETER = 87
DWORD = ctypes.c_uint32
WORD = ctypes.c_uint16
SIZE = ctypes.c_size_t
POINTER = ctypes.c_void_p
BOOL = ctypes.c_int32


class MemoryBasic(ctypes.Structure):
    _fields_ = [
        ("base", POINTER), ("allocation_base", POINTER), ("allocation_protect", DWORD), ("partition", WORD),
        ("size", SIZE), ("state", DWORD), ("protect", DWORD), ("kind", DWORD),
    ]


class MemoryCountersEx(ctypes.Structure):
    _fields_ = [
        ("size", DWORD), ("faults", DWORD),
        *((key, SIZE) for key in (
            "peak_working_set", "working_set", "peak_paged_pool", "paged_pool", "peak_nonpaged_pool",
            "nonpaged_pool", "commit", "peak_commit", "private_usage",
        )),
    ]


class WorkingSetEntry(ctypes.Structure):
    _fields_ = [("address", POINTER), ("attributes", SIZE)]


class SystemInfo(ctypes.Structure):
    _fields_ = [
        ("architecture", DWORD), ("page_size", DWORD), ("min_address", POINTER), ("max_address", POINTER),
        ("active_processors", SIZE), ("processor_count", DWORD), ("processor_type", DWORD),
        ("allocation_granularity", DWORD), ("processor_level", WORD), ("processor_revision", WORD),
    ]


class BoundedSampleError(RuntimeError):
    pass


def stage_from_log(path):
    try:
        with path.open("rb") as handle:
            handle.seek(0, 2)
            handle.seek(max(0, handle.tell() - (64 << 10)))
            lines = handle.read().splitlines()
    except FileNotFoundError:
        return "process_initialization"
    stage = "before_index_phase"
    for line in lines:
        if b"Counting block index entries..." in line:
            stage = COUNT_PHASE
        elif b"Counted " in line and b" block index entries" in line:
            stage = "index_count_complete"
        elif b"Loading block index:" in line:
            stage = "loading_index_rows"
        elif b"Opening LevelDB in " in line and line.rstrip().endswith(b"\\chainstate"):
            stage = "opening_coins"
        elif b"Loaded best chain:" in line:
            stage = "loaded_best_chain"
    return stage


def mapping_category(name, index_prefix):
    if not name:
        return "unresolved_mapped"
    lower = name.replace("/", "\\").casefold()
    if not lower.startswith(index_prefix):
        return "other_mapped"
    relative = lower.removeprefix(index_prefix)
    if relative and "\\" not in relative and relative.endswith((".sst", ".ldb")):
        return "index_sst_or_ldb"
    return "other_index_mapped"


def sample_pages(regions, page_size):
    """Represent each category uniformly across its virtual pages, without storing every page."""
    cumulative = []
    total = 0
    for base, size in regions:
        total += size // page_size
        cumulative.append(total)
    n = min(total, MAX_GROUP_PAGES)
    if not n:
        return total, []
    addresses = []
    for index in range(n):
        rank = (2 * index + 1) * total // (2 * n)
        region = bisect_right(cumulative, rank)
        begin = cumulative[region - 1] if region else 0
        addresses.append(regions[region][0] + (rank - begin) * page_size)
    return total, addresses


class WindowsMemory:
    def __init__(self, proc, directory):
        if ctypes.sizeof(POINTER) != 8 or ctypes.sizeof(MemoryBasic) != 48 or ctypes.sizeof(MemoryCountersEx) != 80:
            raise BoundedSampleError("unsupported_native_structure_layout")
        # Borrow the CreateProcess handle. No command accepts a caller-selected PID.
        self.proc = proc
        self.handle = wintypes.HANDLE(int(proc._handle))
        kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        psapi = ctypes.WinDLL("psapi.dll", use_last_error=True)
        self.virtual_query = kernel.VirtualQueryEx
        self.virtual_query.argtypes = [wintypes.HANDLE, POINTER, ctypes.POINTER(MemoryBasic), SIZE]
        self.virtual_query.restype = SIZE
        self.mapped_file = psapi.GetMappedFileNameW
        self.mapped_file.argtypes = [wintypes.HANDLE, POINTER, wintypes.LPWSTR, DWORD]
        self.mapped_file.restype = DWORD
        self.working_set = psapi.QueryWorkingSetEx
        self.working_set.argtypes = [wintypes.HANDLE, ctypes.POINTER(WorkingSetEntry), DWORD]
        self.working_set.restype = BOOL
        self.counters = psapi.GetProcessMemoryInfo
        self.counters.argtypes = [wintypes.HANDLE, ctypes.POINTER(MemoryCountersEx), DWORD]
        self.counters.restype = BOOL
        sysinfo = kernel.GetNativeSystemInfo
        sysinfo.argtypes = [ctypes.POINTER(SystemInfo)]
        sysinfo.restype = None
        info = SystemInfo()
        sysinfo(ctypes.byref(info))
        self.page_size = info.page_size
        self.end_address = int(info.max_address or 0)
        if self.page_size <= 0 or self.end_address <= 0:
            raise BoundedSampleError("native_system_info_unavailable")

        query_device = kernel.QueryDosDeviceW
        query_device.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, DWORD]
        query_device.restype = DWORD
        root = Path(directory).resolve()
        device = ctypes.create_unicode_buffer(NAME_CAPACITY)
        if not root.drive or not query_device(root.drive, device, len(device)) or not device.value.startswith("\\Device\\"):
            raise BoundedSampleError("owned_index_drive_mapping_unavailable")
        relative = str(root)[len(root.drive):].rstrip("\\/")
        self.index_prefix = (device.value + relative + "\\blocks\\index\\").replace("/", "\\").casefold()

    def memory(self):
        info = MemoryCountersEx(size=ctypes.sizeof(MemoryCountersEx))
        if not self.counters(self.handle, ctypes.byref(info), info.size):
            raise ctypes.WinError(ctypes.get_last_error())
        return {
            "working_set_bytes": info.working_set, "peak_working_set_bytes": info.peak_working_set,
            "private_commit_bytes": info.private_usage, "page_faults": info.faults,
        }

    def category(self, address):
        buffer = ctypes.create_unicode_buffer(NAME_CAPACITY)
        count = self.mapped_file(self.handle, address, buffer, len(buffer))
        return mapping_category(buffer.value if 0 < count < len(buffer) else "", self.index_prefix)

    def check_budget(self, done, deadline):
        if done.is_set():
            raise BoundedSampleError("stopped_at_startup_end")
        if self.proc.poll() is not None:
            raise BoundedSampleError("owned_child_exited")
        if time.monotonic() >= deadline:
            raise BoundedSampleError("sample_time_cap")

    def collect(self, done, deadline):
        regions = defaultdict(list)
        names = {}
        address = 0
        scanned = 0
        while address <= self.end_address:
            self.check_budget(done, deadline)
            if scanned >= MAX_REGIONS:
                raise BoundedSampleError("address_region_cap")
            info = MemoryBasic()
            size = self.virtual_query(self.handle, address, ctypes.byref(info), ctypes.sizeof(info))
            if size != ctypes.sizeof(info):
                if not size and ctypes.get_last_error() == ERROR_INVALID_PARAMETER and address > 0:
                    # The current native information reports the supported upper
                    # bound. Any earlier invalid range makes the scan incomplete.
                    raise BoundedSampleError("early_end_of_virtual_address_scan")
                raise ctypes.WinError(ctypes.get_last_error())
            scanned += 1
            base = int(info.base or 0)
            next_address = base + info.size
            if next_address <= address or base > address or not info.size:
                raise BoundedSampleError("invalid_virtual_region")
            # Another thread can extend a region behind the cursor while this
            # sample runs. Count only addresses not already visited.
            current_size = next_address - address
            if info.state == MEM_COMMIT:
                if info.kind == MEM_MAPPED:
                    allocation = int(info.allocation_base or address)
                    if allocation not in names:
                        names[allocation] = self.category(address)
                    kind = names[allocation]
                elif info.kind == MEM_PRIVATE:
                    kind = "private"
                elif info.kind == MEM_IMAGE:
                    kind = "image"
                else:
                    kind = "other_committed"
                regions[kind].append((address, current_size))
            address = next_address
        return scanned, regions

    def residence(self, addresses, done, deadline):
        resident = 0
        for start in range(0, len(addresses), QUERY_BATCH):
            self.check_budget(done, deadline)
            batch = addresses[start:start + QUERY_BATCH]
            entries = (WorkingSetEntry * len(batch))(*(WorkingSetEntry(address=address) for address in batch))
            if not self.working_set(self.handle, entries, ctypes.sizeof(entries)):
                raise ctypes.WinError(ctypes.get_last_error())
            resident += sum(entry.attributes & 1 for entry in entries)
        return resident

    def snapshot(self, debug, stage_started, target_second, done):
        now = time.monotonic()
        deadline = now + SAMPLE_BUDGET_SECONDS
        row = {"trigger": "count_start" if target_second is None else "scheduled",
               "scheduled_seconds": target_second, "actual_seconds_since_spawn": round(now - stage_started, 4),
               "phase_before": stage_from_log(debug), "status": "in_progress"}
        try:
            row["process_before"] = self.memory()
            scanned, groups = self.collect(done, deadline)
            row["virtual_query_regions"] = scanned
            row["page_size_bytes"] = self.page_size
            row["categories"] = {}
            for category in ("index_sst_or_ldb", "other_index_mapped", "other_mapped", "unresolved_mapped",
                             "private", "image", "other_committed"):
                regions = groups.get(category, [])
                total, addresses = sample_pages(regions, self.page_size)
                resident = self.residence(addresses, done, deadline)
                row["categories"][category] = {
                    "regions": len(regions),
                    "virtual_committed_bytes": sum(length for _, length in regions),
                    "sampled_pages": len(addresses),
                    "valid_working_set_pages": resident,
                    "estimated_resident_bytes": (total * resident * self.page_size // len(addresses)) if addresses else 0,
                }
            row["process_after"] = self.memory()
            row["status"] = "complete"
        except BoundedSampleError as error:
            row.update(status="inconclusive", reason=str(error))
        except OSError as error:
            row.update(status="inconclusive", reason="windows_metadata_query_failed", winerror=getattr(error, "winerror", None))
        row["phase_after"] = stage_from_log(debug)
        row["observation_seconds"] = round(time.monotonic() - now, 4)
        return row


def qualification(samples, observer_stopped, error=None):
    valid = [
        row for row in samples if row["status"] == "complete"
        and row["phase_before"] == row["phase_after"] == COUNT_PHASE
        and row["process_before"]["private_commit_bytes"] >= 0
        and row["process_after"]["private_commit_bytes"] >= 0
    ]
    mapping_counts = {"resolved": 0, "zero": 0, "unresolved": 0}
    for row in valid:
        categories = row["categories"]
        if categories["index_sst_or_ldb"]["regions"]:
            mapping_counts["resolved"] += 1
        elif categories["unresolved_mapped"]["regions"]:
            mapping_counts["unresolved"] += 1
        else:
            mapping_counts["zero"] += 1
    return {
        "status": "verified_metadata" if observer_stopped and valid else "diagnostic_inconclusive",
        "reason": error or (None if valid and observer_stopped else "complete_count_only_native_memory_sample_unavailable"),
        "observer_stopped_before_core_timing": observer_stopped,
        "schedule_seconds_since_spawn": list(SAMPLE_SECONDS),
        "count_start_watch_seconds": SAMPLE_SECONDS[-1],
        "count_start_poll_seconds": PHASE_POLL_SECONDS,
        "sample_time_cap_seconds": SAMPLE_BUDGET_SECONDS,
        "region_cap_per_sample": MAX_REGIONS,
        "page_sample_cap_per_category": MAX_GROUP_PAGES,
        "count_only_complete_samples": len(valid),
        "count_only_samples_with_index_mapping": mapping_counts["resolved"],
        "count_only_samples_without_index_or_unresolved_mapping": mapping_counts["zero"],
        "count_only_samples_without_resolved_index_mapping_but_unresolved_mapping": mapping_counts["unresolved"],
        "samples": samples,
    }


class StartupObserver:
    def __init__(self, proc, directory, started):
        self.proc = proc
        self.directory = directory
        self.started = started
        self.samples = []
        self.error = None
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.record, daemon=True)

    def record(self):
        try:
            native = WindowsMemory(self.proc, self.directory)
            debug = self.directory / "debug-restart.log"
            watch_count_start = True
            for target in SAMPLE_SECONDS:
                while not self.done.is_set() and self.proc.poll() is None:
                    delay = self.started + target - time.monotonic()
                    if delay <= 0:
                        break
                    if watch_count_start:
                        stage = stage_from_log(debug)
                        watch_count_start = stage in BEFORE_COUNT_PHASES
                        if stage == COUNT_PHASE:
                            self.samples.append(native.snapshot(debug, self.started, None, self.done))
                            continue
                    self.done.wait(min(delay, PHASE_POLL_SECONDS) if watch_count_start else delay)
                if self.done.is_set() or self.proc.poll() is not None:
                    return
                row = native.snapshot(debug, self.started, target, self.done)
                self.samples.append(row)
                if row["phase_before"] not in BEFORE_COUNT_PHASES or row["phase_after"] not in BEFORE_COUNT_PHASES:
                    watch_count_start = False
        except BoundedSampleError as error:
            self.error = str(error)
        except (AttributeError, OSError, ValueError) as error:
            self.error = f"windows_metadata_observer_{type(error).__name__}"

    def start(self):
        try:
            self.thread.start()
        except RuntimeError:
            self.error = "windows_metadata_observer_thread_unavailable"

    def stop(self):
        self.done.set()
        if self.thread.ident is not None:
            self.thread.join(timeout=4)
        return not self.thread.is_alive()

    def persist(self, result_path, stopped):
        reason = self.error if stopped else "observer_join_deadline"
        evidence = qualification(list(self.samples), stopped, reason)
        temporary = result_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        temporary.replace(result_path)

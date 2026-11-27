"""Collect wall-stack profiles of the two live-owned benchmark daemons."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

_SAMPLE = "/usr/bin/sample"
_SECONDS = 3
_INTERVAL_MS = 1
_ROLE_NAMES = ("receiver", "sender")
_TASK_COUNTS = ("pti_csw", "pti_syscalls_unix", "pti_syscalls_mach", "pti_faults", "pti_pageins")
_RUSAGE_COUNTS = (
    "ri_user_time", "ri_system_time", "ri_pkg_idle_wkups", "ri_interrupt_wkups",
    "ri_diskio_bytesread", "ri_diskio_byteswritten", "ri_logical_writes", "ri_pageins",
    "ri_runnable_time", "ri_instructions", "ri_cycles",
)


class _TaskProbe:
    def __init__(self):
        library = Path(os.environ["EN9_TASKINFO_PROBE"]).resolve(strict=True)
        with library.open("rb") as stream:
            self.sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
        self._library = ctypes.CDLL(str(library))
        self._sample = self._library.en9_proc_task_snapshot
        self._sample.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t)
        self._sample.restype = ctypes.c_int

    def snapshot(self, daemon):
        if not isinstance(daemon, subprocess.Popen) or daemon.poll() is not None:
            raise ValueError("Task counters require a live owned Popen child")
        started = time.monotonic_ns()
        buffer = ctypes.create_string_buffer(8192)
        parent = os.getpid()
        error = self._sample(daemon.pid, parent, buffer, ctypes.sizeof(buffer))
        if error:
            raise OSError(error, "Owned native task counter acquisition failed")
        row = json.loads(buffer.value)
        if row["pid"] != daemon.pid or row["parent_pid"] != parent or daemon.poll() is not None:
            raise ValueError("Owned process identity changed during task sampling")
        row["capture_started_monotonic_ns"] = started
        row["capture_finished_monotonic_ns"] = time.monotonic_ns()
        row["capture_finished_utc_ns"] = time.time_ns()
        return row


def _window_deltas(before, after):
    identity = ("pid", "parent_pid", "start_seconds", "start_microseconds")
    if any(before[key] != after[key] for key in identity) or (
        before["rusage_info_v4"]["ri_proc_start_abstime"] != after["rusage_info_v4"]["ri_proc_start_abstime"]
    ):
        raise ValueError("Owned process identity changed between counter captures")
    elapsed = after["capture_finished_monotonic_ns"] - before["capture_finished_monotonic_ns"]
    if elapsed <= 0:
        raise ValueError("Task counter captures are out of order")
    result = {"elapsed_monotonic_ns": elapsed}
    for group, fields in (("task", _TASK_COUNTS), ("rusage_info_v4", _RUSAGE_COUNTS)):
        result[group] = {}
        for field in fields:
            first, last = before[group][field], after[group][field]
            if type(first) is not int or type(last) is not int or not 0 <= first <= last:
                raise ValueError(f"Native cumulative counter reset or overflowed: {field}")
            result[group][field] = last - first
    if result["task"]["pti_csw"] == 0:
        raise ValueError("No context switches observed in the active replay interval")
    return result


class _Session:
    """Keep the caller's daemon handles and own the sampler children."""

    def __init__(self, directory: Path, sender_proc: subprocess.Popen):
        if sys.platform != "darwin":
            raise RuntimeError("The macOS sampler requires a native Darwin host")
        if not isinstance(sender_proc, subprocess.Popen):
            raise TypeError("The owned sender Popen handle is required")
        directory = directory.resolve()
        directory.mkdir(mode=0o700)
        self._samplers = {}
        self._directory = directory
        self._result = None
        self._roles = {}
        self._sender = sender_proc
        self._receiver = None
        self._prepared_ns = time.monotonic_ns()
        self._attached_ns = None
        self._body_ns = None
        self._task_probe = _TaskProbe()
        self._task_counters = {}
        self._task_errors = {}

    def attach(self, receiver_proc: subprocess.Popen) -> None:
        if self._receiver is not None or self._result is not None:
            raise RuntimeError("The sampler session already has its receiver or has been finalized")
        if not isinstance(receiver_proc, subprocess.Popen):
            raise TypeError("The owned receiver Popen handle is required")
        if self._sender.pid == receiver_proc.pid:
            raise ValueError("Sender and receiver must be separate children")
        self._receiver = receiver_proc
        self._attached_ns = time.monotonic_ns()

    def _capture_counters(self, endpoint):
        window = self._task_counters[endpoint] = {}
        for role, daemon in zip(_ROLE_NAMES, (self._receiver, self._sender), strict=True):
            try:
                window[role] = self._task_probe.snapshot(daemon)
            except (OSError, ValueError, KeyError) as exc:
                self._task_errors[f"{endpoint}/{role}"] = f"{type(exc).__name__}: {exc}"

    def _counter_receipt(self):
        intervals = {}
        for role in _ROLE_NAMES:
            try:
                intervals[role] = _window_deltas(self._task_counters["first_full_headers"][role],
                                                  self._task_counters["ibd_clear_observed"][role])
            except (ValueError, KeyError) as exc:
                self._task_errors[f"interval/{role}"] = f"{type(exc).__name__}: {exc}"
        return {
            "status": "measured" if not self._task_errors else "unavailable",
            "scope": "first observed full headers before sampling to observed IBD-clear before post-verification",
            "probe_sha256": self._task_probe.sha256,
            "captures": self._task_counters,
            "deltas": intervals,
            "errors": self._task_errors,
        }

    def body_started(self) -> None:
        if self._receiver is None or self._body_ns is not None or self._result is not None:
            raise RuntimeError("Sampling requires two attached daemon handles and a fresh body signal")
        self._body_ns = time.monotonic_ns()
        self._capture_counters("first_full_headers")
        for role, daemon in zip(_ROLE_NAMES, (self._receiver, self._sender), strict=True):
            report = self._directory / f"{role}.sample.txt"
            console = self._directory / f"{role}.sample.log"
            receipt = {
                "daemon_pid": daemon.pid,
                "report": report.name,
                "console": console.name,
                "status": "failed",
                "launch_start_monotonic_ns": time.monotonic_ns(),
            }
            self._roles[role] = receipt
            if daemon.poll() is not None:
                receipt["error"] = "owned daemon exited before sampler attachment"
                continue
            try:
                with console.open("xb") as stream:
                    self._samplers[role] = subprocess.Popen(
                        [_SAMPLE, str(daemon.pid), str(_SECONDS), str(_INTERVAL_MS), "-file", str(report)],
                        stdout=stream,
                        stderr=subprocess.STDOUT,
                        stdin=subprocess.DEVNULL,
                    )
                receipt["sampler_pid"] = self._samplers[role].pid
                receipt["launch_return_monotonic_ns"] = time.monotonic_ns()
            except OSError as exc:
                receipt["error"] = f"{type(exc).__name__}: {exc}"

    def _check_report(self, receipt):
        report = self._directory / receipt["report"]
        if not report.is_file() or report.stat().st_size == 0:
            return "sampler did not produce a report"
        receipt["report_bytes"] = report.stat().st_size
        owner = re.compile(rb"^Process:.*\[" + str(receipt["daemon_pid"]).encode() + rb"\]\s*$")
        report_owner = graph = images = False
        with report.open("rb") as stream:
            for line in stream:
                report_owner |= owner.match(line) is not None
                graph |= line.strip() == b"Call graph:"
                images |= line.strip() == b"Binary Images:"
        if not (report_owner and graph and images):
            return "sampler report lacks the expected daemon identity or call-graph structure"
        return None

    def finish(self, timeout=30) -> dict:
        if self._result is not None:
            return self._result
        if not 0 < timeout <= 30:
            raise ValueError("sampler finish timeout must be within 0–30 seconds")
        invoked = time.monotonic_ns()
        if self._body_ns is not None:
            self._capture_counters("ibd_clear_observed")
        budget = min(timeout, 8)
        deadline = time.monotonic() + budget
        natural_deadline = deadline - min(budget / 4, 1)
        for role, sampler in self._samplers.items():
            receipt = self._roles[role]
            try:
                sampler.wait(timeout=max(0, natural_deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                receipt["error"] = "sampler exceeded its completion deadline"

        for role, sampler in self._samplers.items():
            if sampler.poll() is None:
                try:
                    # Only these retained sampler handles are signaled.
                    sampler.kill()
                except OSError as exc:
                    self._roles[role]["cleanup_error"] = f"{type(exc).__name__}: {exc}"

        for role, sampler in self._samplers.items():
            receipt = self._roles[role]
            try:
                receipt["returncode"] = sampler.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                receipt["cleanup_error"] = "sampler could not be reaped after SIGKILL"
            receipt["completion_observed_monotonic_ns"] = time.monotonic_ns()
            try:
                report_error = self._check_report(receipt)
            except OSError as exc:
                report_error = f"{type(exc).__name__}: {exc}"
            if report_error:
                receipt["report_error"] = report_error
            if receipt.get("returncode") == 0 and not any(
                k in receipt for k in ("error", "cleanup_error", "report_error")
            ):
                receipt["status"] = "passed"
            elif "error" not in receipt:
                receipt["error"] = "sampler exited unsuccessfully or produced incomplete evidence"

        self._result = {
            "status": "passed" if all(self._roles.get(role, {}).get("status") == "passed" for role in _ROLE_NAMES) else "failed",
            "sampler": _SAMPLE,
            "requested_seconds": _SECONDS,
            "sample_interval_ms": _INTERVAL_MS,
            "prepared_monotonic_ns": self._prepared_ns,
            "receiver_attached_monotonic_ns": self._attached_ns,
            "body_signal_monotonic_ns": self._body_ns,
            "finish_called_monotonic_ns": invoked,
            "roles": self._roles,
            "owned_task_counters": self._counter_receipt(),
        }
        if self._body_ns is None:
            self._result["error"] = "no full-headers body signal arrived before finalization"
        return self._result


def prepare(directory: Path, sender_proc: subprocess.Popen) -> _Session:
    """Create a new evidence directory before the receiver process starts."""
    return _Session(directory, sender_proc)

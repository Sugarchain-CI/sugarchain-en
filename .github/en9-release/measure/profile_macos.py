"""Collect wall-stack profiles of the two live-owned benchmark daemons."""
from pathlib import Path
import re
import subprocess
import sys
import time

_SAMPLE = "/usr/bin/sample"
_SECONDS = 3
_INTERVAL_MS = 1
_ROLE_NAMES = ("receiver", "sender")


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

    def attach(self, receiver_proc: subprocess.Popen) -> None:
        if self._receiver is not None or self._result is not None:
            raise RuntimeError("The sampler session already has its receiver or has been finalized")
        if not isinstance(receiver_proc, subprocess.Popen):
            raise TypeError("The owned receiver Popen handle is required")
        if self._sender.pid == receiver_proc.pid:
            raise ValueError("Sender and receiver must be separate children")
        self._receiver = receiver_proc
        self._attached_ns = time.monotonic_ns()

    def body_started(self) -> None:
        if self._receiver is None or self._body_ns is not None or self._result is not None:
            raise RuntimeError("Sampling requires two attached daemon handles and a fresh body signal")
        self._body_ns = time.monotonic_ns()
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
        }
        if self._body_ns is None:
            self._result["error"] = "no full-headers body signal arrived before finalization"
        return self._result


def prepare(directory: Path, sender_proc: subprocess.Popen) -> _Session:
    """Create a new evidence directory before the receiver process starts."""
    return _Session(directory, sender_proc)

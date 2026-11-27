"""Capture one unscored owned-process Windows Regtest diagnostic with WPR."""

import atexit
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid

MAX_TRACE_BYTES = 512 << 20
MAX_RECORD_SECONDS = 35


class Profile:
    def __init__(self, directory, sender_proc):
        if sys.platform != "win32" or os.environ.get("GITHUB_ACTIONS") != "true":
            raise RuntimeError("ETW profile requires the isolated native Windows CI job")
        if sender_proc.pid <= 0 or sender_proc.poll() is not None:
            raise ValueError("Expected a live owned sender PID")
        self.directory = directory
        self.directory.mkdir()
        self.sender_pid = sender_proc.pid
        self.receiver_pid = None
        self.body_utc_ns = None
        self.instance = f"SugarchainRegtest{uuid.uuid4().hex[:12]}"
        self.guard = threading.Lock()
        self.active = False
        self.expired = False
        self.timer = None
        wpr = shutil.which("wpr.exe") or str(Path(os.environ["SystemRoot"]) / "System32" / "wpr.exe")
        self.wpr = Path(wpr)
        self.dotnet = shutil.which("dotnet.exe") or shutil.which("dotnet")
        self.parser = Path(os.environ.get("SUGARCHAIN_ETW_READER", ""))
        if not self.wpr.is_file() or not self.dotnet or not self.parser.is_file():
            raise RuntimeError("WPR and the prepared .NET TraceEvent reader are required on this Windows runner")
        scratch = Path(os.environ["RUNNER_TEMP"])
        if shutil.disk_usage(scratch).free < 2 << 30:
            raise RuntimeError("Insufficient scratch capacity for bounded WPR profile")
        self.scratch = tempfile.TemporaryDirectory(prefix="sugarchain-etw-", dir=scratch)
        self.raw = Path(self.scratch.name)
        atexit.register(self.cancel)
        try:
            status = self._command("global-status", "-status", named=False)
            status_text = (status.stdout + status.stderr).lower().replace(b"\x00", b"")
            if b"recording is in progress" in status_text:
                raise RuntimeError("The runner already has a WPR recording")
            self._command("help", "-help", named=False)
            self._command("profiles", "-profiles", named=False).check_returncode()
            self._command("profile-interval", "-profint", named=False)
            self.active = True  # A failed start can still allocate its uniquely named session.
            started = self._command("start", "-start", "CPU.Light", "-start", "FileIO.Light", "-filemode",
                                    "-recordtempto", str(self.raw), timeout=20)
            started.check_returncode()
            self.timer = threading.Timer(MAX_RECORD_SECONDS, self._expire)
            self.timer.daemon = True
            self.timer.start()
        except BaseException:
            self.cancel()
            raise

    def _command(self, name, *args, timeout=15, named=True):
        command = [str(self.wpr), *args]
        if named:
            command.extend(("-instancename", self.instance))
        try:
            done = subprocess.run(command, capture_output=True, timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW)
        except subprocess.TimeoutExpired as error:
            (self.directory / f"wpr-{name}-stdout.log").write_bytes(error.stdout or b"")
            (self.directory / f"wpr-{name}-stderr.log").write_bytes(error.stderr or b"")
            raise
        (self.directory / f"wpr-{name}-stdout.log").write_bytes(done.stdout)
        (self.directory / f"wpr-{name}-stderr.log").write_bytes(done.stderr)
        return done

    def _expire(self):
        with self.guard:
            if self.active:
                self.expired = True
                self._cancel_owned("deadline-cancel")

    def _cancel_owned(self, name):
        try:
            self._command(name, "-cancel", timeout=10)
        finally:
            self.active = False

    def cancel(self):
        if self.timer:
            self.timer.cancel()
        try:
            with self.guard:
                # This named instance was generated here. It never targets a default session.
                if self.active:
                    self._cancel_owned("cancel")
        finally:
            self.scratch.cleanup()
            atexit.unregister(self.cancel)

    def attach(self, receiver_proc):
        if self.receiver_pid is not None or receiver_proc.pid <= 0 or receiver_proc.pid == self.sender_pid or receiver_proc.poll() is not None:
            raise ValueError("Expected a new live owned receiver PID")
        self.receiver_pid = receiver_proc.pid

    def body_started(self):
        if self.receiver_pid is None or self.body_utc_ns is not None:
            raise RuntimeError("ETW block window requires the attached receiver and exactly one start")
        self.body_utc_ns = time.time_ns()

    def finish(self, timeout=30):
        finish_utc_ns = time.time_ns()
        deadline = time.monotonic() + min(timeout, 30)
        if self.timer:
            self.timer.cancel()
        try:
            if self.body_utc_ns is None or self.receiver_pid is None:
                raise RuntimeError("ETW window was not marked")
            with self.guard:
                if self.expired or not self.active:
                    raise RuntimeError("ETW recording reached its hard capture bound")
                etl = self.raw / "profile.etl"
                stopped = self._command("stop", "-stop", str(etl), "-skipPdbGen", timeout=max(0.1, deadline - time.monotonic()))
                stopped.check_returncode()
                self.active = False
            if not etl.is_file() or not 0 < etl.stat().st_size <= MAX_TRACE_BYTES:
                raise RuntimeError("The ETW trace was missing or exceeded the bounded analysis size")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("ETW stop exhausted the analysis deadline")
            process = subprocess.run(
                [self.dotnet, str(self.parser), str(etl), str(self.sender_pid), str(self.receiver_pid),
                 str(self.body_utc_ns), str(finish_utc_ns)],
                timeout=remaining, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW,
            )
            (self.directory / "traceevent-stderr.log").write_bytes(process.stderr)
            process.check_returncode()
            result = json.loads(process.stdout)
            if result.get("sender", {}).get("pid") != self.sender_pid or result.get("receiver", {}).get("pid") != self.receiver_pid:
                raise RuntimeError("ETW reader returned a different PID scope")
            result["trace_size_bytes"] = etl.stat().st_size
            result["wpr"] = {"tool": self.wpr.name, "tool_help_log": "wpr-help-stdout.log",
                             "sample_interval_log": "wpr-profile-interval-stdout.log",
                             "profiles": ["CPU.Light", "FileIO.Light"],
                             "elapsed_recording_limit_seconds": MAX_RECORD_SECONDS}
            result["raw_trace_retained"] = False
            (self.directory / "owned-profile.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            return result
        finally:
            self.cancel()


prepare = Profile

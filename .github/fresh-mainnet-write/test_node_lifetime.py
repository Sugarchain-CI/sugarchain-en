"""Exercise the native replay cleanup without launching a daemon or opening a socket."""

import asyncio
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import portable_fresh_mainnet_write as replay


class FakeProcess:
    def __init__(self, log):
        self.pid = 700
        self.returncode = None
        self.log = log
        self.actions = []
        self.signal = None
        self.graceful = False
        self.grace_expires = False
        self.terminate_expires = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.actions.append("terminate")
        self.signal = "terminate"

    def kill(self):
        self.actions.append("kill")
        self.signal = "kill"

    def wait(self, timeout):
        self.actions.append(("wait", timeout))
        if self.signal == "kill":
            self.returncode = -9
        elif self.signal == "terminate" and not self.terminate_expires:
            self.returncode = -15
        elif self.signal is None and self.graceful and not self.grace_expires:
            self.returncode = 0
            self.log.write_text("Shutdown done\n", encoding="ascii")
        else:
            raise subprocess.TimeoutExpired("fake-owned-daemon", timeout)
        return self.returncode


class FakeRPC:
    def __init__(self, process):
        self.process = process
        self.cookie = SimpleNamespace(is_file=lambda: True)
        self.startup_error = None
        self.stop_error = None
        self.block_stop = False
        self.stop_started = asyncio.Event()
        self.requests = []

    async def __call__(self, method, *, timeout):
        self.requests.append((method, timeout))
        if method == "getblockchaininfo":
            if self.startup_error is not None:
                raise self.startup_error
            return {"chain": "main"}
        if method != "stop":
            raise AssertionError(method)
        self.stop_started.set()
        if self.block_stop:
            await asyncio.Future()
        if self.stop_error is not None:
            raise self.stop_error
        self.process.graceful = True
        return "stopping"


class NodeLifetimeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.output = Path(directory)
        self.args = SimpleNamespace(output=self.output, binary=self.output / "fake-daemon", datadir=self.output,
                                    startup_timeout=5, shutdown_timeout=7)
        self.process = FakeProcess(self.output / "fresh-node.log")
        self.rpc = FakeRPC(self.process)
        self.enterContext(patch.object(replay.subprocess, "Popen", return_value=self.process))
        self.rpc_factory = self.enterContext(patch.object(replay, "RPC", return_value=self.rpc))
        self.enterContext(patch.object(replay, "free_port", return_value=19444))
        self.enterContext(patch.object(replay, "require_stock_startup_check"))

    def receipt(self):
        return json.loads((self.output / "fresh-cleanup.json").read_text(encoding="utf-8"))

    async def run_context(self):
        async with replay.node(self.args, "fresh", None) as (_, _, _, state, _):
            self.assertEqual(state["chain"], "main")

    async def test_clean_shutdown_has_no_forced_action(self):
        await self.run_context()
        record = self.receipt()
        self.assertEqual(self.rpc.requests, [("getblockchaininfo", 3), ("stop", 10)])
        self.assertEqual(self.process.actions, [("wait", 7)])
        self.assertTrue(record["clean_shutdown"] and record["reaped"] and record["rpc_acknowledged"])
        self.assertFalse(record["forced"])
        self.assertEqual(record["returncode"], 0)
        self.assertEqual(record["cleanup_errors"], [])

    async def test_rpc_construction_failure_reaps_the_child(self):
        self.rpc_factory.side_effect = LookupError("failed to construct RPC")
        with self.assertRaisesRegex(LookupError, "failed to construct RPC"):
            await self.run_context()
        self.assertEqual(self.process.actions, ["terminate", ("wait", 10)])
        self.assertEqual(self.receipt()["primary_exception"], "LookupError")
        self.assertFalse(self.receipt()["rpc_acknowledged"])

    async def test_startup_rpc_failure_survives_failed_cleanup_rpc(self):
        self.rpc.startup_error = NameError("original startup error")
        self.rpc.stop_error = LookupError("private cleanup detail")
        with self.assertRaises(NameError) as raised:
            await self.run_context()
        self.assertIs(raised.exception, self.rpc.startup_error)
        self.assertEqual(self.rpc.requests, [("getblockchaininfo", 3), ("stop", 3)])
        self.assertEqual(self.process.actions, ["terminate", ("wait", 10)])
        record = self.receipt()
        self.assertEqual(record["primary_exception"], "NameError")
        self.assertEqual(record["cleanup_errors"], [{"stage": "graceful_shutdown", "exception": "LookupError"}])
        self.assertNotIn("private cleanup detail", json.dumps(record))
        self.assertTrue(record["reaped"] and record["forced"])
        self.assertFalse(record["clean_shutdown"])

    async def test_stop_exception_without_primary_fails_after_reaping(self):
        self.rpc.stop_error = LookupError("stop failed")
        with self.assertRaises(LookupError) as raised:
            await self.run_context()
        self.assertIs(raised.exception, self.rpc.stop_error)
        self.assertEqual(self.process.actions, ["terminate", ("wait", 10)])
        self.assertIsNone(self.receipt()["primary_exception"])
        self.assertFalse(self.receipt()["clean_shutdown"])

    async def test_cancelled_stop_reaps_the_child_before_propagating(self):
        self.rpc.block_stop = True
        task = asyncio.create_task(self.run_context())
        await asyncio.wait_for(self.rpc.stop_started.wait(), timeout=1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.process.actions, ["terminate", ("wait", 10)])
        self.assertTrue(self.receipt()["reaped"])
        self.assertEqual(self.receipt()["cleanup_errors"][0]["exception"], "CancelledError")

    async def test_expired_wait_escalates_to_kill_then_reaps(self):
        self.process.grace_expires = self.process.terminate_expires = True
        with self.assertRaises(subprocess.TimeoutExpired):
            await self.run_context()
        self.assertEqual(self.process.actions, [("wait", 7), "terminate", ("wait", 10), "kill", ("wait", 10)])
        record = self.receipt()
        self.assertEqual(record["returncode"], -9)
        self.assertEqual([row["stage"] for row in record["cleanup_errors"]], ["graceful_shutdown", "wait_after_terminate"])
        self.assertTrue(record["reaped"] and record["forced"])
        self.assertFalse(record["clean_shutdown"])


class PeerLifetimeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.output = Path(directory) / "peer-cleanup.json"
        self.events = []

    def controls(self, *, hung=False):
        async def close_peer():
            self.events.append("close peer")

        async def wait_server():
            self.events.append("wait server")
            if hung:
                await asyncio.Future()

        server = SimpleNamespace(close=lambda: self.events.append("close server"), wait_closed=wait_server,
                                 abort_clients=lambda: self.events.append("abort clients"))
        return server, SimpleNamespace(close=close_peer)

    async def test_wait_closed_follows_peer_close(self):
        server, peer = self.controls()
        await replay.finish_peer(server, peer, self.output, None)
        self.assertEqual(self.events, ["close server", "close peer", "wait server"])
        self.assertTrue(json.loads(self.output.read_text())["clean_shutdown"])

    async def test_bounded_server_failure_does_not_mask_primary(self):
        server, peer = self.controls(hung=True)
        now = iter((0.0, 9.98))
        initial = ValueError("body proof check failed")
        with self.assertRaises(ValueError) as raised, patch.object(replay, "time", SimpleNamespace(monotonic=now.__next__)):
            try:
                raise initial
            finally:
                await replay.finish_peer(server, peer, self.output, initial)
        self.assertIs(raised.exception, initial)
        self.assertEqual(self.events, ["close server", "close peer", "wait server", "abort clients"])
        record = json.loads(self.output.read_text())
        self.assertFalse(record["clean_shutdown"])
        self.assertEqual(record["primary_exception"], "ValueError")
        self.assertEqual(record["cleanup_errors"], [{"stage": "server_wait_closed", "exception": "TimeoutError"}])

"""Exercise asynchronous RPC dispatch without a node or network access."""

import asyncio
import io
import json
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

from mature_common import RPC


class RPCDispatchTest(unittest.IsolatedAsyncioTestCase):
    async def test_actual_http_adapter_runs_off_event_loop(self):
        rpc = RPC(Path("unused-owned-test-profile"), 1)
        caller = threading.get_ident()
        calls = []

        def response(request, timeout):
            calls.append((threading.get_ident(), json.loads(request.data), timeout))
            return io.BytesIO(b'{"result":{"ready":true},"error":null}')

        with patch.object(Path, "read_bytes", return_value=b"test:owned"), patch.object(rpc.opener, "open", side_effect=response):
            result = await rpc("getblockchaininfo", timeout=3)
        self.assertEqual(result, {"ready": True})
        self.assertEqual(len(calls), 1)
        self.assertNotEqual(calls[0][0], caller)
        self.assertEqual(calls[0][1], {"jsonrpc": "2.0", "id": 1, "method": "getblockchaininfo", "params": []})
        self.assertEqual(calls[0][2], 3)

    async def test_rpc_failure_reaches_async_caller(self):
        rpc = RPC(Path("unused-owned-test-profile"), 1)
        with patch.object(Path, "read_bytes", return_value=b"test:owned"), patch.object(
            rpc.opener, "open", return_value=io.BytesIO(b'{"result":null,"error":{"code":-28}}')
        ):
            with self.assertRaisesRegex(RuntimeError, "Owned getblockchaininfo RPC returned code -28"):
                await rpc("getblockchaininfo")

    async def test_transport_failure_reaches_async_caller(self):
        rpc = RPC(Path("unused-owned-test-profile"), 1)
        with patch.object(Path, "read_bytes", return_value=b"test:owned"), patch.object(
            rpc.opener, "open", side_effect=ConnectionResetError("closed test transport")
        ):
            with self.assertRaisesRegex(ConnectionResetError, "closed test transport"):
                await asyncio.wait_for(rpc("stop", timeout=3), timeout=5)


if __name__ == "__main__":
    unittest.main()

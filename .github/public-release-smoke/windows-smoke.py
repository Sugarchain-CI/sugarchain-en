#!/usr/bin/env python3
"""Verify the public Windows installer and portable release on a disposable VM."""

import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import zipfile
from decimal import Decimal


VERSION = "31.1.1"
MAIN_GENESIS = "7d5eaec2dbb75f99feadfa524c78b7cabc1d8c8204f79d4f3a83381b811b0adc"
EXPECTED_REWARD = Decimal("42.94967296")


def load_helper(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mainnet_node_type(smoke):
    class MainnetNode(smoke.Node):
        def _start(self):
            self.wallet = None
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                self.port = listener.getsockname()[1]
            command = [
                str(self.binary), f"-datadir={self.datadir}", f"-rpcport={self.port}",
                "-server=1", "-listen=0", "-prune=550", "-blocksonly=1",
                "-maxconnections=4", "-splash=0", "-printtoconsole=0",
            ]
            self.debug_log = self.datadir / "debug.log"
            self.log = (self.datadir / "process.log").open("xb")
            self.started_ns = time.time_ns()
            try:
                self.process = subprocess.Popen(
                    command, stdout=self.log, stderr=subprocess.STDOUT,
                    env=smoke.runtime_environment(self.datadir),
                )
            except OSError:
                self.log.close()
                raise

    return MainnetNode


def observe_mainnet(node):
    info = node.wait()
    assert info["chain"] == "main", info
    assert node.rpc("getblockhash", 0) == MAIN_GENESIS
    deadline = time.monotonic() + 120
    highest_peers = 0
    highest_headers = 0
    last_blocks = 0
    while True:
        peers = node.rpc("getpeerinfo")
        chain = node.rpc("getblockchaininfo")
        highest_peers = max(highest_peers, len(peers))
        highest_headers = max(
            highest_headers, chain["headers"],
            *(max(peer.get("presynced_headers", -1), peer.get("synced_headers", -1)) for peer in peers),
        )
        last_blocks = chain["blocks"]
        if (highest_peers > 0 and highest_headers > 0) or time.monotonic() >= deadline:
            break
        time.sleep(max(0, min(1, deadline - time.monotonic())))
    # Stop network activity before checking the separate disposable wallet.
    assert node.rpc("setnetworkactive", False) is False
    return {
        "rpc_startup": "passed",
        "initial_sync": "passed" if highest_peers and highest_headers else "inconclusive",
        "max_peers": highest_peers,
        "headers_observed": highest_headers,
        "blocks_at_network_stop": last_blocks,
        "observation_limit_seconds": 120,
    }


def check_gui_window(process):
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows.argtypes = (callback_type, wintypes.LPARAM)
    user32.GetWindowThreadProcessId.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.DWORD))
    user32.GetWindowTextW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
    user32.SendMessageTimeoutW.argtypes = (
        wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
        wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_size_t),
    )
    user32.SendMessageTimeoutW.restype = ctypes.c_ssize_t
    windows = []

    @callback_type
    def collect(handle, _parameter):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(handle, ctypes.byref(owner))
        if owner.value == process.pid:
            title = ctypes.create_unicode_buffer(256)
            user32.GetWindowTextW(handle, title, len(title))
            if "Sugarchain" in title.value:
                windows.append(handle)
        return True

    deadline = time.monotonic() + 5
    while not windows:
        user32.EnumWindows(collect, 0)
        if time.monotonic() >= deadline:
            break
        if not windows:
            time.sleep(0.1)
    if not windows:
        return "inconclusive: no application window exposed by runner desktop"
    reply = ctypes.c_size_t()
    # WM_NULL confirms that the application window can process a message.
    assert user32.SendMessageTimeoutW(windows[0], 0, 0, 0, 2, 2000, ctypes.byref(reply)), (
        "Sugarchain application window did not respond"
    )
    return "passed"


def regtest_transfer(node):
    assert node.wait()["chain"] == "regtest"
    assert node.rpc("getnetworkinfo")["networkactive"] is False
    for name in ("sender", "receiver"):
        node.rpc("createwallet", name, False, False, "", False, True, True)
    node.wallet = "sender"
    mining_address = node.rpc("getnewaddress", "", "bech32")
    node.wallet = "receiver"
    address = node.rpc("getnewaddress", "", "bech32")
    assert address.startswith("rugar1q"), address
    assert node.rpc("getaddressinfo", address)["ismine"]
    first, = node.rpc("generatetoaddress", 1, mining_address)
    coinbase = node.rpc("getblock", first, 2)["tx"][0]["vout"][0]["value"]
    assert Decimal(str(coinbase)) == EXPECTED_REWARD, coinbase
    # The coin at height one becomes spendable after another 100 blocks.
    assert len(node.rpc("generatetoaddress", 100, mining_address)) == 100
    node.wallet = "sender"
    txid = node.rpc("sendtoaddress", address, 1)
    node.rpc("generatetoaddress", 1, mining_address)
    node.wallet = "receiver"
    received = node.rpc("gettransaction", txid)
    assert Decimal(str(received["amount"])) == Decimal(1), received
    assert received["confirmations"] == 1, received
    assert Decimal(str(node.rpc("getreceivedbyaddress", address, 1))) == Decimal(1)
    backup = node.datadir / "receiver-backup.sqlite"
    node.rpc("backupwallet", str(backup))
    assert backup.is_file() and backup.stat().st_size > 0
    node.wallet = None
    node.rpc("unloadwallet", "receiver", False)
    node.rpc("restorewallet", "restored", str(backup), True)
    node.wallet = "restored"
    assert node.rpc("getaddressinfo", address)["ismine"]
    restored = node.rpc("gettransaction", txid)
    assert restored["confirmations"] == received["confirmations"]
    assert restored["amount"] == received["amount"]
    assert Decimal(str(node.rpc("getbalance"))) == Decimal(1)
    return address, txid


def check_windows(crt, assets, work, smoke, installer):
    prefix = f"sugarchain-en-{VERSION}-windows-x86_64-{crt}"
    installer_path = (assets / f"{prefix}-setup.exe").resolve(strict=True)
    archive = (assets / f"{prefix}-portable.zip").resolve(strict=True)
    program_files = Path(os.environ.get("ProgramW6432", os.environ["ProgramFiles"]))
    install = program_files / "Sugarchain"
    start_menu = (
        Path(os.environ["APPDATA"])
        / "Microsoft/Windows/Start Menu/Programs/Sugarchain/Sugarchain En.lnk"
    )
    assert not install.exists(), f"Expected a fresh runner: {install}"
    assert not start_menu.exists(), f"Expected a fresh Start Menu: {start_menu}"
    installer.run_nsis(installer_path)
    gui = install / "sugarchain-qt.exe"
    assert gui.is_file() and start_menu.is_file()

    core = mainnet_node_type(smoke)
    with core(gui, work / "mainnet", "main", gui=True) as mainnet:
        mainnet_result = observe_mainnet(mainnet)
        mainnet_result["native_window_responsiveness"] = check_gui_window(mainnet.process)
        mainnet.rpc("createwallet", "receive-only", False, False, "", False, True, True)
        mainnet.wallet = "receive-only"
        main_address = mainnet.rpc("getnewaddress", "", "bech32")
        assert main_address.startswith("sugar1q"), main_address
        assert mainnet.rpc("getaddressinfo", main_address)["ismine"]
        with smoke.Node(gui, work / "regtest", "regtest", gui=True) as regtest:
            address, txid = regtest_transfer(regtest)
            regtest_window = check_gui_window(regtest.process)
            assert not mainnet.rpc("validateaddress", address)["isvalid"]
            assert not regtest.rpc("validateaddress", main_address)["isvalid"]
            regtest.wallet = "sender"
            try:
                regtest.rpc("sendtoaddress", main_address, 1)
            except RuntimeError as error:
                assert isinstance(error.args[0], dict) and error.args[0]["code"] == -5, error
            else:
                raise AssertionError("Regtest accepted a mainnet send destination")
            assert regtest.rpc("getrawmempool") == []
        assert regtest.process.returncode == 0
        with regtest.restart() as reopened:
            assert reopened.wait()["blocks"] == 102
            assert set(reopened.rpc("listwallets")) >= {"sender", "restored"}
            reopened.wallet = "restored"
            assert reopened.rpc("getaddressinfo", address)["ismine"]
            assert reopened.rpc("gettransaction", txid)["confirmations"] == 1
        assert reopened.process.returncode == 0
    assert mainnet.process.returncode == 0
    settings = work / "regtest/regtest/settings.json"
    restored_wallet = work / "regtest/regtest/wallets/restored/wallet.dat"
    assert restored_wallet.is_file()
    settings_contents = settings.read_bytes()
    wallet_contents = restored_wallet.read_bytes()
    installer.run_nsis(install / "uninstall.exe", install, uninstall=True)
    assert not gui.exists() and not start_menu.exists()
    assert settings.read_bytes() == settings_contents
    assert restored_wallet.read_bytes() == wallet_contents

    portable = work / "portable"
    with zipfile.ZipFile(archive) as handle:
        handle.extractall(portable)
    with smoke.Node(
        portable / f"{prefix}-portable/sugarchain-qt.exe",
        work / "portable-regtest", "regtest", gui=True,
    ) as node:
        assert node.wait()["chain"] == "regtest"
        assert node.rpc("getblockcount") == 0
        portable_window = check_gui_window(node.process)
    assert node.process.returncode == 0

    return {
        "installed_asset": installer_path.name,
        "portable_asset": archive.name,
        "install_default_directory": str(install),
        "start_menu": "passed",
        "installer_mode": "silent",
        "mainnet": {
            **mainnet_result, "address_prefix": "sugar1q", "clean_shutdown": True,
        },
        "regtest": {
            "address_prefix": "rugar1q", "first_block_reward_sugar": str(EXPECTED_REWARD),
            "confirmed_transfer_sugar": "1", "transaction_id": txid,
            "confirmed_height": 102, "cross_network_address_rejection": True,
            "regtest_send_rejected_mainnet_address": True,
            "restore_preserved_owner_balance_and_transaction": True,
            "restart_retained_state": True, "clean_shutdown": True,
            "native_window_responsiveness": regtest_window,
        },
        "uninstall_preserved_wallet_and_settings": True,
        "portable_gui_startup": "passed",
        "portable_window_responsiveness": portable_window,
        "interaction": "Native GUI processes with wallet actions driven through RPC",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="Verified source checkout")
    parser.add_argument("--assets", type=Path, required=True, help="Verified public download directory")
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--crt", choices=("ucrt", "msvcrt"), default="ucrt")
    args = parser.parse_args()
    if (os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or not ctypes.windll.shell32.IsUserAnAdmin()):
        parser.error("Run on an elevated, disposable GitHub-hosted Windows runner")
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    work = args.workdir.resolve()
    if runner_temp == work or not work.is_relative_to(runner_temp):
        parser.error("The working directory must be a fresh child of RUNNER_TEMP")
    work.mkdir(parents=True, exist_ok=False)
    source = args.source.resolve(strict=True) / ".github"
    smoke = load_helper("windows_runtime", source / "ci-windows-smoke.py")
    installer = load_helper("windows_installer", source / "ci-windows-installer.py")
    report = check_windows(args.crt, args.assets.resolve(strict=True), work, smoke, installer)
    (work / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

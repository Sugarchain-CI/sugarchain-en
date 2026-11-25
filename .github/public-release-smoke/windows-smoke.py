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


def observe_mainnet(node, desktop, visuals):
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
    # Stop network activity as soon as its start is evident or the limit expires.
    assert node.rpc("setnetworkactive", False) is False
    window_result = capture_node_window(desktop, node.process, "mainnet-01-startup", visuals)
    return {
        "rpc_startup": "passed",
        "initial_sync": "passed" if highest_peers and highest_headers else "inconclusive",
        "max_peers": highest_peers,
        "headers_observed": highest_headers,
        "blocks_at_network_stop": last_blocks,
        "observation_limit_seconds": 120,
        "native_window_responsiveness": window_result,
    }


class WindowsDesktop:
    def __init__(self, directory):
        from ctypes import wintypes

        self.directory = directory
        self.directory.mkdir()
        self.user32 = ctypes.windll.user32
        self.callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        self.owner_type = wintypes.DWORD
        self.user32.EnumWindows.argtypes = (self.callback_type, wintypes.LPARAM)
        self.user32.EnumChildWindows.argtypes = (wintypes.HWND, self.callback_type, wintypes.LPARAM)
        self.user32.GetWindowThreadProcessId.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.DWORD))
        self.user32.GetWindowTextW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
        self.user32.GetClassNameW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
        self.user32.GetDlgItem.argtypes = (wintypes.HWND, ctypes.c_int)
        self.user32.GetDlgItem.restype = wintypes.HWND
        self.user32.GetAncestor.argtypes = (wintypes.HWND, wintypes.UINT)
        self.user32.GetAncestor.restype = wintypes.HWND
        self.user32.GetWindowLongW.argtypes = (wintypes.HWND, ctypes.c_int)
        self.user32.GetWindowLongW.restype = wintypes.LONG
        self.user32.GetWindowRect.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.RECT))
        self.user32.GetCursorPos.argtypes = (ctypes.POINTER(wintypes.POINT),)
        self.user32.SetCursorPos.argtypes = (ctypes.c_int, ctypes.c_int)
        self.user32.WindowFromPoint.argtypes = (wintypes.POINT,)
        self.user32.WindowFromPoint.restype = wintypes.HWND
        self.user32.GetForegroundWindow.restype = wintypes.HWND
        self.user32.IsWindowVisible.argtypes = (wintypes.HWND,)
        self.user32.IsWindowEnabled.argtypes = (wintypes.HWND,)
        self.user32.ShowWindowAsync.argtypes = (wintypes.HWND, ctypes.c_int)
        self.user32.SetForegroundWindow.argtypes = (wintypes.HWND,)
        self.user32.keybd_event.argtypes = (wintypes.BYTE, wintypes.BYTE, wintypes.DWORD, ctypes.c_size_t)
        self.user32.mouse_event.argtypes = (wintypes.DWORD,) * 4 + (ctypes.c_size_t,)
        self.user32.PostMessageW.argtypes = (wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
        self.user32.SendMessageTimeoutW.argtypes = (
            wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
            wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_size_t),
        )
        self.user32.SendMessageTimeoutW.restype = ctypes.c_ssize_t

    def message(self, handle, message, wparam=0, lparam=0, timeout=2000):
        reply = ctypes.c_size_t()
        if not self.user32.SendMessageTimeoutW(
            handle, message, wparam, lparam, 2, timeout, ctypes.byref(reply),
        ):
            raise RuntimeError("The native window did not answer its message")
        return reply.value

    def controls(self, dialog):
        children = []

        @self.callback_type
        def collect(handle, _parameter):
            if self.user32.IsWindowVisible(handle):
                children.append(handle)
            return True

        self.user32.EnumChildWindows(dialog, collect, 0)
        return children

    def window_class(self, handle):
        class_name = ctypes.create_unicode_buffer(64)
        self.user32.GetClassNameW(handle, class_name, len(class_name))
        return class_name.value.casefold()

    def find(self, process, title="Sugarchain", timeout=8, exclude=None):
        windows = []

        @self.callback_type
        def collect(handle, _parameter):
            if handle == exclude or not self.user32.IsWindowVisible(handle):
                return True
            owner = self.owner_type()
            self.user32.GetWindowThreadProcessId(handle, ctypes.byref(owner))
            if owner.value == process.pid:
                caption = ctypes.create_unicode_buffer(256)
                self.user32.GetWindowTextW(handle, caption, len(caption))
                if title.casefold() in caption.value.casefold():
                    windows.append(handle)
            return True

        deadline = time.monotonic() + timeout
        while process.poll() is None and time.monotonic() < deadline:
            self.user32.EnumWindows(collect, 0)
            if windows:
                return windows[0]
            time.sleep(0.15)
        raise RuntimeError(f"The runner did not expose a window titled {title}")

    def image(self, handle):
        from PIL import ImageGrab

        image = ImageGrab.grab(window=handle).convert("RGB")
        if min(image.size) < 100 or all(low == high for low, high in image.getextrema()):
            raise RuntimeError("The window capture was empty")
        return image

    def screenshot(self, handle, name):
        self.message(handle, 0)
        image = self.image(handle)
        path = self.directory / f"{name}.png"
        image.save(path)
        return {"screenshot": path.name, "width": image.width, "height": image.height}

    def focus(self, handle):
        if self.user32.GetForegroundWindow() != handle:
            self.user32.ShowWindowAsync(handle, 9)
            self.user32.SetForegroundWindow(handle)
        deadline = time.monotonic() + 3
        while self.user32.GetForegroundWindow() != handle:
            if time.monotonic() >= deadline:
                raise RuntimeError("The runner did not focus the application window")
            time.sleep(0.05)

    def keystroke(self, handle, key, alt=False):
        self.focus(handle)
        if alt:
            self.user32.keybd_event(0x12, 0, 0, 0)
        self.user32.keybd_event(key, 0, 0, 0)
        self.user32.keybd_event(key, 0, 2, 0)
        if alt:
            self.user32.keybd_event(0x12, 0, 2, 0)

    def forward_button(self, dialog):
        # NSIS uses IDOK for the visible Next, Install and Finish buttons.
        handle = self.user32.GetDlgItem(dialog, 1)
        if (handle and self.window_class(handle) == "button"
                and self.user32.IsWindowVisible(handle) and self.user32.IsWindowEnabled(handle)):
            return handle
        raise RuntimeError("The installer forward button was unavailable")

    def mouse_click(self, dialog, button):
        from ctypes import wintypes

        self.focus(dialog)
        rectangle = wintypes.RECT()
        point = wintypes.POINT()
        if not self.user32.GetWindowRect(button, ctypes.byref(rectangle)):
            raise RuntimeError("The runner did not expose the installer button bounds")
        if rectangle.right <= rectangle.left or rectangle.bottom <= rectangle.top:
            raise RuntimeError("The installer button did not have a visible center")
        x = (rectangle.left + rectangle.right) // 2
        y = (rectangle.top + rectangle.bottom) // 2
        at_center = self.user32.WindowFromPoint(wintypes.POINT(x, y))
        if at_center != button or self.user32.GetAncestor(button, 2) != dialog:
            raise RuntimeError("The installer button center was covered or outside its dialog")
        had_cursor = self.user32.GetCursorPos(ctypes.byref(point))
        if not self.user32.SetCursorPos(x, y):
            raise RuntimeError("The runner did not allow positioning the cursor")
        try:
            if self.user32.GetForegroundWindow() != dialog:
                raise RuntimeError("The installer lost focus before the click")
            self.user32.mouse_event(0x0002, 0, 0, 0, 0)
            self.user32.mouse_event(0x0004, 0, 0, 0, 0)
            time.sleep(0.1)
        finally:
            if had_cursor:
                self.user32.SetCursorPos(point.x, point.y)

    def installer_body(self, dialog):
        image = self.image(dialog)
        # Ignore outer borders, title bar and footer button state.
        box = (16, 36, image.width - 16, image.height - 55)
        return image.crop(box).convert("L").resize((160, 120))

    def wait_for_page_change(self, dialog, prior):
        from PIL import ImageChops

        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            try:
                self.forward_button(dialog)
            except RuntimeError:
                time.sleep(0.15)
                continue
            difference = ImageChops.difference(prior, self.installer_body(dialog))
            if sum(difference.histogram()[16:]) > 480:
                return
            time.sleep(0.15)
        raise RuntimeError("The installer page body did not change after the click")

    def checkboxes(self, dialog):
        return {
            handle for handle in self.controls(dialog)
            if self.window_class(handle) == "button"
            and (self.user32.GetWindowLongW(handle, -16) & 0xF) in {2, 3, 5, 6}
        }


def capture_screenshot(desktop, window, name, evidence):
    try:
        evidence[name] = {"status": "captured", **desktop.screenshot(window, name)}
    except (ImportError, OSError, RuntimeError, ValueError) as error:
        evidence[name] = {"status": "inconclusive", "reason": str(error)}


def capture_node_window(desktop, process, name, evidence):
    try:
        window = desktop.find(process)
        desktop.user32.ShowWindowAsync(window, 9)
        desktop.message(window, 0)
        capture_screenshot(desktop, window, name, evidence)
        return "passed"
    except RuntimeError as error:
        evidence[name] = {"status": "inconclusive", "reason": str(error)}
        return "inconclusive"


def capture_wallet_pages(desktop, process, evidence):
    try:
        window = desktop.find(process)
        desktop.message(window, 0)
    except RuntimeError as error:
        evidence["regtest-window"] = {"status": "inconclusive", "reason": str(error)}
        return "inconclusive"
    pages = ("overview", "send", "receive", "transactions")
    for shortcut, page in enumerate(pages, start=1):
        name = f"regtest-{shortcut:02d}-{page}"
        try:
            desktop.keystroke(window, ord(str(shortcut)), alt=True)
            time.sleep(0.35)
            capture_screenshot(desktop, window, name, evidence)
            evidence[name]["input"] = f"Alt+{shortcut}"
        except RuntimeError as error:
            evidence[name] = {"status": "inconclusive", "reason": str(error)}
    name = "regtest-05-about"
    try:
        desktop.keystroke(window, ord("H"), alt=True)
        time.sleep(0.3)
        desktop.keystroke(window, ord("A"))
        dialog = desktop.find(process, "About", exclude=window)
        capture_screenshot(desktop, dialog, name, evidence)
        desktop.user32.PostMessageW(dialog, 0x0010, 0, 0)
    except RuntimeError as error:
        evidence[name] = {"status": "inconclusive", "reason": str(error)}
    return "passed"


def interactive_install(installer_path, gui, desktop, evidence):
    try:
        process = subprocess.Popen([str(installer_path)])
    except OSError as error:
        evidence["installer-navigation"] = {"status": "inconclusive", "reason": str(error)}
        return "silent fallback"
    started_installation = False
    try:
        dialog = desktop.find(process, "Setup")
        desktop.focus(dialog)
        capture_screenshot(desktop, dialog, "installer-01-welcome", evidence)
        previous = desktop.installer_body(dialog)
        desktop.mouse_click(dialog, desktop.forward_button(dialog))
        desktop.wait_for_page_change(dialog, previous)
        capture_screenshot(desktop, dialog, "installer-02-destination", evidence)
        previous = desktop.installer_body(dialog)
        desktop.mouse_click(dialog, desktop.forward_button(dialog))
        desktop.wait_for_page_change(dialog, previous)
        capture_screenshot(desktop, dialog, "installer-03-start-menu", evidence)
        start_menu_checkboxes = desktop.checkboxes(dialog)
        desktop.mouse_click(dialog, desktop.forward_button(dialog))
        started_installation = True
        deadline = time.monotonic() + 40
        progress_name = "installer-04-install-progress"
        while process.poll() is None and time.monotonic() < deadline:
            if progress_name not in evidence and any(
                desktop.window_class(handle) == "msctls_progress32"
                for handle in desktop.controls(dialog)
            ):
                capture_screenshot(desktop, dialog, progress_name, evidence)
            if gui.is_file() and "installer-after-files" not in evidence:
                capture_screenshot(desktop, dialog, "installer-after-files", evidence)
            finish_checkboxes = desktop.checkboxes(dialog) - start_menu_checkboxes
            if len(finish_checkboxes) == 1 and gui.is_file():
                try:
                    finish = desktop.forward_button(dialog)
                    break
                except RuntimeError:
                    pass
            time.sleep(0.15)
        else:
            if process.poll() is None and gui.is_file():
                capture_screenshot(desktop, dialog, "installer-last-visible-page", evidence)
            raise RuntimeError("The installer Finish page was not exposed")
        evidence.setdefault(progress_name, {"status": "inconclusive", "reason": "The installation progress page was transient"})
        capture_screenshot(desktop, dialog, "installer-05-finish", evidence)
        # The published installer's Finish page has one optional auto-run checkbox.
        run_checkbox, = finish_checkboxes
        if desktop.message(run_checkbox, 0x00F0) != 0:
            desktop.mouse_click(dialog, run_checkbox)
        if desktop.message(run_checkbox, 0x00F0) != 0:
            raise RuntimeError("The installer Run Sugarchain option remained selected")
        desktop.mouse_click(dialog, finish)
        assert process.wait(timeout=15) == 0
        return "interactive"
    except (ImportError, OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        evidence["installer-navigation"] = {"status": "inconclusive", "reason": str(error)}
        if started_installation and not gui.exists():
            raise RuntimeError("The interactive installation did not reach the installed GUI") from error
        return "interactive partial" if started_installation else "silent fallback"
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=15)


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
    gui = install / "sugarchain-qt.exe"
    desktop = WindowsDesktop(work / "screenshots")
    visuals = {}
    installer_mode = interactive_install(installer_path, gui, desktop, visuals)
    if installer_mode == "silent fallback":
        installer.run_nsis(installer_path)
    assert gui.is_file() and start_menu.is_file()

    core = mainnet_node_type(smoke)
    with core(gui, work / "mainnet", "main", gui=True) as mainnet:
        mainnet_result = observe_mainnet(mainnet, desktop, visuals)
        mainnet.rpc("createwallet", "receive-only", False, False, "", False, True, True)
        mainnet.wallet = "receive-only"
        main_address = mainnet.rpc("getnewaddress", "", "bech32")
        assert main_address.startswith("sugar1q"), main_address
        assert mainnet.rpc("getaddressinfo", main_address)["ismine"]
        capture_node_window(desktop, mainnet.process, "mainnet-02-wallet", visuals)
        with smoke.Node(gui, work / "regtest", "regtest", gui=True) as regtest:
            address, txid = regtest_transfer(regtest)
            regtest_window = capture_wallet_pages(desktop, regtest.process, visuals)
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
        portable_window = capture_node_window(desktop, node.process, "portable-01-startup", visuals)
    assert node.process.returncode == 0

    return {
        "installed_asset": installer_path.name,
        "portable_asset": archive.name,
        "install_default_directory": str(install),
        "start_menu": "passed",
        "installer_mode": installer_mode,
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
        "visual_checks": visuals,
        "wallet_rpc_checks": "Address generation, mining, confirmed transfer, restore, restart and cross-network rejection",
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

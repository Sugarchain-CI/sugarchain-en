#!/usr/bin/env python3
# Copyright (c) 2026 The Sugarchain En developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Exercise ordinary data-directory selection on a fresh GitHub-hosted runner.

The native preference and directory fixtures require unused locations.
Only fixtures created in those locations are removed.
"""

import argparse
from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time


SMOKE_SPEC = importlib.util.spec_from_file_location("native_smoke", Path(__file__).with_name("ci-windows-smoke.py"))
SMOKE = importlib.util.module_from_spec(SMOKE_SPEC)
SMOKE_SPEC.loader.exec_module(SMOKE)

CURRENT = "Sugarchain En"
PREVIOUS = "Sugarchain Komorebi"
LEGACY = "Sugarchain-Qt"


def require_absent(path):
    if os.path.lexists(path):
        raise RuntimeError(f"Expected an unused native directory: {path}")


@contextmanager
def windows_profile():
    import ctypes
    import winreg

    def get_folder(folder):
        path = ctypes.create_unicode_buffer(260)
        if not ctypes.windll.shell32.SHGetSpecialFolderPathW(None, path, folder, False):
            raise RuntimeError(f"Could not resolve Windows folder {folder}")
        return Path(path.value) / "Sugarchain"

    def delete_key(key_name):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_name) as key:
                children = [winreg.EnumKey(key, i) for i in range(winreg.QueryInfoKey(key)[0])]
        except FileNotFoundError:
            return
        for child in children:
            delete_key(f"{key_name}\\{child}")
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_name)

    root = r"Software\Sugarchain"
    local, roaming = get_folder(0x1C), get_folder(0x1A)
    for directory in (local, roaming):
        require_absent(directory)
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, root):
            raise RuntimeError("Expected an unused Sugarchain registry profile")
    except FileNotFoundError:
        pass

    def save(profile, directory):
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, f"{root}\\{profile}") as key:
            winreg.SetValueEx(key, "strDataDir", 0, winreg.REG_SZ, str(directory))

    try:
        yield local, roaming, save
    finally:
        delete_key(root)
        for directory in (local, roaming):
            if directory.is_dir():
                shutil.rmtree(directory)


@contextmanager
def mac_profile():
    directory = Path(os.environ["HOME"]) / "Library/Application Support/Sugarchain"
    require_absent(directory)

    # The fixtures use the same native per-user preference domains as Qt.
    domains = [f"org.sugarchain.{profile}{suffix}"
               for profile in (CURRENT, PREVIOUS, LEGACY) for suffix in ("", "-regtest")]
    for domain in domains:
        require_absent(Path(os.environ["HOME"]) / "Library/Preferences" / f"{domain}.plist")
        check = subprocess.run(["defaults", "read", domain], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check.returncode == 0:
            raise RuntimeError(f"Expected an unused preference domain: {domain}")

    def save(profile, selected):
        subprocess.run(["defaults", "write", f"org.sugarchain.{profile}", "strDataDir", "-string", str(selected)], check=True)

    try:
        yield directory, None, save
    finally:
        for domain in domains:
            subprocess.run(["defaults", "delete", domain], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if directory.is_dir():
            shutil.rmtree(directory)


class NativeNode(SMOKE.Node):
    def __init__(self, binary, datadir, output, *, gui=False, extra=()):
        self.chain = "regtest"
        self.wallet = None
        self.cookie = datadir / "regtest/.cookie"
        self.debug_log = datadir / "regtest/debug.log"
        self.started_ns = time.time_ns()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        command = [
            str(binary), "-regtest", f"-rpcport={self.port}", "-server=1",
            "-listen=0", "-connect=0", "-dnsseed=0", "-discover=0", "-networkactive=0",
            "-maxconnections=0", "-keypool=10", "-printtoconsole=0", *extra,
        ]
        if gui:
            command += ["-splash=0", "-min"]
        env = SMOKE.runtime_environment(output.parent)
        if sys.platform == "darwin":
            env["QT_QPA_PLATFORM"] = "cocoa"
        self.log = output.open("xb")
        try:
            self.process = subprocess.Popen(command, stdout=self.log, stderr=subprocess.STDOUT, env=env)
        except OSError:
            self.log.close()
            raise


def blockcount(cli, node, extra):
    result = subprocess.check_output([
        str(cli), "-regtest", f"-rpcport={node.port}", *extra, "getblockcount",
    ], text=True, timeout=30)
    return int(result.strip())


def alternate(binaries, datadir, workdir, *, extra=(), client_extra=(), walletdir=None):
    daemon, gui, cli = binaries
    wallet = "shared-wallet"
    workdir.mkdir()

    with NativeNode(daemon, datadir, workdir / "daemon.log", extra=extra) as node:
        assert node.wait()["blocks"] == 0
        assert blockcount(cli, node, client_extra) == 0
        assert node.rpc("createwallet", wallet, False, False, "", False, True, True)["name"] == wallet
        node.wallet = wallet
        address = node.rpc("getnewaddress")
        tip, = node.rpc("generatetoaddress", 1, address)

    with NativeNode(gui, datadir, workdir / "gui.log", gui=True, extra=extra) as node:
        assert node.wait()["bestblockhash"] == tip
        assert wallet in node.rpc("listwallets")
        node.wallet = wallet
        assert node.rpc("getaddressinfo", address)["ismine"]
        tip, = node.rpc("generatetoaddress", 1, address)

    with NativeNode(daemon, datadir, workdir / "restart.log", extra=extra) as node:
        assert node.wait()["bestblockhash"] == tip
        assert blockcount(cli, node, client_extra) == 2
        assert wallet in node.rpc("listwallets")
        node.wallet = wallet
        assert node.rpc("getaddressinfo", address)["ismine"]

    expected_walletdir = datadir / "regtest/wallets" if walletdir is None else walletdir
    assert (expected_walletdir / wallet / "wallet.dat").is_file()
    print(f"{workdir.name} daemon, GUI and CLI shared a chain and wallet", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("daemon", "gui", "cli", "workdir"):
        parser.add_argument(f"--{key}", type=Path, required=True)
    args = parser.parse_args()
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or sys.platform not in ("win32", "darwin")):
        parser.error("A fresh GitHub-hosted Windows or macOS runner is required")
    binaries = tuple(path.resolve(strict=True) for path in (args.daemon, args.gui, args.cli))
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    workdir = args.workdir.resolve()
    if not workdir.is_relative_to(runner_temp):
        parser.error("The work directory must be under RUNNER_TEMP")
    workdir.mkdir()

    profile = windows_profile if sys.platform == "win32" else mac_profile
    with profile() as (standard, roaming, save):
        alternate(binaries, standard, workdir / "fresh-default")
        if roaming is not None:
            save(CURRENT, standard)
            roaming.mkdir()
            alternate(binaries, roaming, workdir / "legacy-roaming")
            # Use a distinct location to verify that the current preference
            # supersedes the saved standard path after an ordinary restart.
            saved_profile = CURRENT
        else:
            saved_profile = PREVIOUS

        custom = workdir / "custom \uC9C0\uAC11 data"
        custom.mkdir()
        save(saved_profile, custom)
        alternate(binaries, custom, workdir / "saved-custom")

        explicit = workdir / "explicit-data"
        walletdir = workdir / "explicit-wallets"
        explicit.mkdir()
        walletdir.mkdir()
        datadir_option = (f"-datadir={explicit}",)
        alternate(binaries, explicit, workdir / "explicit-override",
                  extra=(*datadir_option, f"-walletdir={walletdir}"),
                  client_extra=datadir_option, walletdir=walletdir)

        redirected = workdir / "config-data"
        redirected.mkdir()
        config = workdir / "redirect.conf"
        config.write_text(f"datadir={redirected}\n", encoding="utf-8")
        config_option = (f"-conf={config}",)
        alternate(binaries, redirected, workdir / "config-override",
                  extra=config_option, client_extra=config_option)


if __name__ == "__main__":
    main()

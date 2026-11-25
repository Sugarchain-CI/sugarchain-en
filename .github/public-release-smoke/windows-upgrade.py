#!/usr/bin/env python3
"""Check the public 31.1.0 to 31.1.1 installer upgrade on a disposable Windows runner."""

import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time


WALLET = "published-upgrade"
PROFILE_LOG = "preserved-profile.log"
INSTALLER = re.compile(r"sugarchain-en-(31\.1\.[01])-windows-x86_64-(ucrt|msvcrt)-setup\.exe")


def load_windows_helper():
    spec = importlib.util.spec_from_file_location("public_windows_smoke", Path(__file__).with_name("windows-smoke.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def profile_node_class(smoke):
    class ProfileNode(smoke.Node):
        def __init__(self, binary, profile, log):
            self.binary = binary
            self.datadir = profile
            self.chain = "regtest"
            self.gui = True
            self.cookie = profile / "regtest/.cookie"
            self.debug_log = profile / "regtest" / PROFILE_LOG
            self.wallet = None
            self.started_ns = time.time_ns()
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                self.port = listener.getsockname()[1]
            command = [
                str(binary), f"-datadir={profile}", f"-rpcport={self.port}",
                "-regtest", "-server=1", "-networkactive=0", "-listen=0",
                "-connect=0", "-dnsseed=0", "-discover=0", "-splash=0", "-printtoconsole=0",
            ]
            self.log = log.open("xb")
            try:
                self.process = subprocess.Popen(
                    command, stdout=self.log, stderr=subprocess.STDOUT,
                    env=smoke.runtime_environment(profile),
                )
            except OSError:
                self.log.close()
                raise

    return ProfileNode


def version(install, profile, expected):
    cli = install / "daemon/sugarchain-cli.exe"
    output = subprocess.check_output(
        [str(cli), f"-datadir={profile}", "-version"], text=True, timeout=15,
    )
    match = re.search(r"(?<![0-9])" + re.escape(expected) + r"(?![0-9])", output)
    if not match:
        raise RuntimeError(f"The installed CLI version did not match {expected}")
    return output.splitlines()[0]


def check_profile(node):
    info = node.wait()
    assert info["chain"] == "regtest" and info["blocks"] == 0, info
    assert node.rpc("getnetworkinfo")["networkactive"] is False
    log = Path(node.rpc("getrpcinfo")["logpath"]).resolve(strict=True)
    assert log == node.debug_log.resolve(strict=True), log


def registered_install():
    import winreg

    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, r"SOFTWARE\Sugarchain En",
        0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
    ) as key:
        return Path(winreg.QueryValueEx(key, "Path")[0])


def check_upgrade(args, old, new, work, report):
    windows = load_windows_helper()
    helpers = args.source.resolve(strict=True) / ".github"
    smoke = windows.load_helper("windows_runtime", helpers / "ci-windows-smoke.py")
    installer = windows.load_helper("windows_installer", helpers / "ci-windows-installer.py")
    desktop = windows.WindowsDesktop(work / "screenshots")
    node_type = profile_node_class(smoke)
    program_files = Path(os.environ.get("ProgramW6432", os.environ["ProgramFiles"]))
    previous_default = program_files / "Sugarchain En"
    new_default = program_files / "Sugarchain"
    assert not previous_default.exists() and not new_default.exists(), "Expected a clean Windows installation"
    try:
        registered_install()
    except FileNotFoundError:
        pass
    else:
        raise RuntimeError("An existing Sugarchain installation was already registered")

    profile = work / "synthetic-profile"
    profile.mkdir()
    config = profile / "sugarchain.conf"
    config.write_text(f"debuglogfile={PROFILE_LOG}\n", encoding="ascii")
    expected_config = config.read_bytes()
    settings = profile / "regtest/settings.json"
    wallet_path = profile / "regtest/wallets" / WALLET / "wallet.dat"
    visuals = report["visual_checks"] = {}

    report["phase"] = "old-install"
    installer.run_nsis(old)
    install = registered_install()
    assert install == previous_default, install
    old_gui = install / "sugarchain-qt.exe"
    assert old_gui.is_file()
    report["old_cli_version"] = version(install, profile, "31.1.0")
    with node_type(old_gui, profile, work / "old-process.log") as old_node:
        check_profile(old_node)
        old_node.rpc("createwallet", WALLET, False, False, "", False, True, True)
        old_node.wallet = WALLET
        address = old_node.rpc("getnewaddress", "upgrade-check", "bech32")
        info = old_node.rpc("getaddressinfo", address)
        assert info["ismine"] and address.startswith("bcrt1q"), info
        script = info["scriptPubKey"]
        windows.capture_node_window(desktop, old_node.process, "upgrade-01-old-wallet", visuals)
    assert old_node.process.returncode == 0 and wallet_path.is_file()
    assert WALLET in json.loads(settings.read_text(encoding="utf-8"))["wallet"]

    report["phase"] = "install-upgrade"
    installer.run_nsis(new)
    assert registered_install() == install
    assert not new_default.exists()
    assert wallet_path.is_file() and config.read_bytes() == expected_config
    assert WALLET in json.loads(settings.read_text(encoding="utf-8"))["wallet"]
    report["new_cli_version"] = version(install, profile, "31.1.1")

    report["phase"] = "open-upgraded-wallet"
    with node_type(old_gui, profile, work / "new-process.log") as new_node:
        check_profile(new_node)
        assert WALLET in new_node.rpc("listwallets"), "The original wallet was not loaded at startup"
        new_node.wallet = WALLET
        new_info = new_node.rpc("getaddressinfo", address)
        assert new_info["ismine"] and new_info["scriptPubKey"] == script, new_info
        latest_address = new_node.rpc("getnewaddress", "", "bech32")
        assert latest_address.startswith("rugar1q"), latest_address
        windows.capture_node_window(desktop, new_node.process, "upgrade-02-upgraded-wallet", visuals)
    assert new_node.process.returncode == 0
    assert wallet_path.is_file() and config.read_bytes() == expected_config
    assert WALLET in json.loads(settings.read_text(encoding="utf-8"))["wallet"]
    report.update({
        "phase": "complete",
        "install_directory_preserved": True,
        "wallet_loaded_at_startup": True,
        "old_address_ownership_preserved": True,
        "new_address_prefix": "rugar1q",
        "profile_configuration_preserved_and_used": True,
        "clean_shutdowns": True,
        "profile": "Explicit, synthetic regtest directory held at genesis",
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="Source checkout containing existing helpers")
    parser.add_argument("--old-installer", type=Path, required=True, help="PGP-verified 31.1.0 installer")
    parser.add_argument("--new-installer", type=Path, required=True, help="PGP-verified 31.1.1 installer")
    parser.add_argument("--workdir", type=Path, required=True)
    args = parser.parse_args()
    if (os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or not ctypes.windll.shell32.IsUserAnAdmin()):
        parser.error("Run on an elevated, disposable GitHub-hosted Windows runner")
    old = args.old_installer.resolve(strict=True)
    new = args.new_installer.resolve(strict=True)
    old_match = INSTALLER.fullmatch(old.name)
    new_match = INSTALLER.fullmatch(new.name)
    if (not old_match or not new_match or old_match[1] != "31.1.0"
            or new_match[1] != "31.1.1" or old_match[2] != new_match[2]):
        parser.error("Supply the 31.1.0 and 31.1.1 public installers for the same CRT")
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    work = args.workdir.resolve()
    if runner_temp == work or not work.is_relative_to(runner_temp):
        parser.error("The working directory must be a fresh child of RUNNER_TEMP")
    work.mkdir(parents=True, exist_ok=False)
    report = {"old_asset": old.name, "new_asset": new.name, "crt": old_match[2]}
    try:
        check_upgrade(args, old, new, work, report)
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["reason"] = str(error)[:500]
        raise
    finally:
        (work / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()

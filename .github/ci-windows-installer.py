#!/usr/bin/env python3
# Copyright (c) 2026 The Sugarchain En developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Verify silent install, in-place upgrade, native runtime, and safe uninstall."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def nsis_command(program, install_dir=None, uninstall=False):
    # NSIS consumes the entire final /D= or _?= suffix, including spaces.
    # Python's list2cmdline would quote this argument and change NSIS parsing.
    if '"' in str(program) or '"' in str(install_dir):
        raise ValueError("NSIS command paths must not contain quotes")
    command = f'"{program}" /S'
    if install_dir is None:
        return command
    suffix = "_?=" if uninstall else "/D="
    return f"{command} {suffix}{install_dir}"


def run_nsis(program, install_dir=None, uninstall=False, check=True):
    return subprocess.run(nsis_command(program, install_dir, uninstall),
                          check=check, timeout=180, shell=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installer", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--with-wallet-restart", action="store_true",
                        help="Check persistence across two native GUI launches after upgrading the installation")
    args = parser.parse_args()
    if os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true":
        parser.error("Installer checks require an ephemeral Windows GitHub Actions runner")
    import winreg

    installer = args.installer.resolve(strict=True)
    workdir = args.work_dir.resolve()
    workdir.mkdir(parents=True, exist_ok=False)
    install = workdir / "Sugarchain En install"
    keyname = r"SOFTWARE\Sugarchain En"
    legacy_key = r"SOFTWARE\Sugarchain Komorebi"
    registry_view = winreg.KEY_WOW64_64KEY
    program_files = Path(os.environ.get("ProgramW6432", os.environ["ProgramFiles"]))
    default_install = program_files / "Sugarchain"
    previous_default = program_files / "Sugarchain En"

    def registry_value(name, product_key=keyname):
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, product_key, 0, winreg.KEY_READ | registry_view) as key:
            return winreg.QueryValueEx(key, name)[0]

    def assert_not_registered(product_key):
        try:
            value = registry_value("Path", product_key)
        except FileNotFoundError:
            return
        raise AssertionError(f"Unexpected installation registered under {product_key}: {value}")

    for product_key in (keyname, legacy_key, f"{legacy_key} (64-bit)"):
        assert_not_registered(product_key)
    for directory in (default_install, previous_default):
        assert not directory.exists(), f"Unexpected files in {directory}"

    run_nsis(installer)
    assert Path(registry_value("Path")) == default_install
    assert (default_install / "sugarchain-qt.exe").is_file()
    run_nsis(default_install / "uninstall.exe", default_install, uninstall=True)
    assert_not_registered(keyname)

    # Reproduce the legacy registration and files that the upgrade recognizes.
    default_install.mkdir(exist_ok=True)
    for name in ("sugarchain-qt.exe", "uninstall.exe"):
        (default_install / name).write_bytes(b"legacy installation fixture")
    legacy_config = default_install / "sugarchain.conf"
    legacy_config.write_bytes(b"# legacy configuration\r\nlisten=0\r\n")
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, legacy_key, 0, winreg.KEY_SET_VALUE | registry_view) as key:
        winreg.SetValueEx(key, "Path", 0, winreg.REG_SZ, str(default_install))
    ignored = workdir / "Ignored legacy override"
    run_nsis(installer, ignored)
    assert Path(registry_value("Path")) == default_install
    assert not ignored.exists()
    assert_not_registered(legacy_key)
    run_nsis(default_install / "uninstall.exe", default_install, uninstall=True)
    assert legacy_config.read_bytes() == b"# legacy configuration\r\nlisten=0\r\n"
    assert_not_registered(keyname)

    run_nsis(installer, previous_default)
    run_nsis(installer)
    assert Path(registry_value("Path")) == previous_default
    run_nsis(previous_default / "uninstall.exe", previous_default, uninstall=True)
    assert_not_registered(keyname)

    run_nsis(installer, install)
    programs = [install / name for name in ("sugarchain.exe", "sugarchain-qt.exe")]
    programs += [install / "daemon" / name for name in ("sugarchaind.exe", "sugarchain-cli.exe", "sugarchain-wallet.exe", "sugarchain-tx.exe", "sugarchain-util.exe")]
    assert all(path.is_file() for path in programs), programs
    assert not list(install.rglob("test_bitcoin*.exe")), "Production installer contains test programs"
    assert not list(install.rglob("bench_*.exe")), "Production installer contains benchmarks"
    assert Path(registry_value("Path")) == install
    startmenu = Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs" / registry_value("StartMenuGroup")
    obsolete = [startmenu / f"Sugarchain En ({network}).lnk" for network in ("testnet", "testnet4", "test signet")]
    assert not any(path.exists() for path in obsolete)

    config = install / "sugarchain.conf"
    config.write_text("# CI configuration preservation sentinel\nlisten=0\n")
    extra = install / "user-file.txt"
    extra.write_text("Installer must preserve unowned files.\n")
    expected_config = config.read_bytes()
    expected_extra = extra.read_bytes()
    for path in obsolete:
        path.write_text("Obsolete launcher sentinel\n")
    ignored = workdir / "Ignored En override"
    run_nsis(installer, ignored)
    assert Path(registry_value("Path")) == install
    assert not ignored.exists()
    assert config.read_bytes() == expected_config
    assert extra.read_bytes() == expected_extra
    assert not any(path.exists() for path in obsolete)

    smoke = Path(__file__).with_name("ci-windows-smoke.py")
    smoke_command = [sys.executable, str(smoke), "--bindir", str(install)]
    if args.with_wallet_restart:
        subprocess.run([*smoke_command, "--verify-wallet-restart", "--work-dir", str(workdir / "installed-wallet-restart")],
                       check=True, timeout=300)
    subprocess.run([*smoke_command, "--work-dir", str(workdir / "installed-runtime")], check=True, timeout=300)
    # Use no shell; all paths belong to this fresh runner-specific workspace.
    uninstaller = install / "uninstall.exe"
    assert run_nsis(uninstaller, workdir, uninstall=True, check=False).returncode != 0
    assert Path(registry_value("Path")) == install
    assert all(path.is_file() for path in programs)
    run_nsis(uninstaller, install, uninstall=True)
    assert_not_registered(keyname)
    assert not any(path.exists() for path in programs), "Uninstaller left packaged production programs"
    assert config.read_bytes() == expected_config
    assert extra.read_bytes() == expected_extra
    report = {"production_binaries": len(programs), "default_install": "passed", "legacy_upgrade": "passed",
              "previous_default_upgrade": "passed", "custom_path_upgrade": "passed", "native_runtime": "passed",
              "uninstall_preserves_user_files": "passed"}
    if args.with_wallet_restart:
        report["gui_wallet_restart"] = "passed"
    (workdir / "installer-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

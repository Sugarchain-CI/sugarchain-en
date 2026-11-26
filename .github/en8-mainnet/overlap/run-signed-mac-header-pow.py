"""Run the unmodified source functional test against an extracted macOS package."""

import argparse
import configparser
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys


def config_for(source, package):
    config = configparser.ConfigParser(interpolation=None)
    config.optionxform = str
    config["environment"] = {
        "CLIENT_NAME": "Sugarchain En",
        "CLIENT_BUGREPORT": "https://github.com/decryp2kanon/sugarchain-en/issues",
        "SRCDIR": str(source),
        "BUILDDIR": str(package),
        "EXEEXT": "",
        "RPCAUTH": str(source / "share" / "rpcauth" / "rpcauth.py"),
        "SUPPORTED_CHAINS": "main,testnet7,regtest",
    }
    config["components"] = {
        "ENABLE_BITCOIND": "true",
        "ENABLE_CLI": "true",
        "ENABLE_WALLET": "true",
    }
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True, help="Source-verified CLI package directory containing bin/")
    parser.add_argument("--work", type=Path, required=True, help="New test output directory")
    options = parser.parse_args()

    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("The signed Mac test requires native Apple Silicon")
    source = options.source.resolve(strict=True)
    package = options.package.resolve(strict=True)
    test = source / "test" / "functional" / "p2p_sugarchain_header_pow.py"
    fixture = source / "src" / "test" / "data" / "sugarchain_headers.raw"
    if not test.is_file() or fixture.stat().st_size != 6_000 * 80:
        raise RuntimeError("The source must contain the current functional test and its 6,000-header fixture")

    for name in ("sugarchaind", "sugarchain-cli"):
        binary = package / "bin" / name
        with binary.open("rb") as handle:
            if handle.read(8) != bytes.fromhex("cffaedfe0c000001"):
                raise RuntimeError(f"Expected a thin Apple Silicon executable: {binary}")
        subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(binary)], check=True)

    work = options.work.resolve()
    work.mkdir(parents=True)
    config_path = work / "config.ini"
    with config_path.open("w", encoding="utf-8") as handle:
        config_for(source, package).write(handle)
    environment = os.environ.copy()
    # Use the package selected in config.ini and ignore optional shell overrides.
    for name in ("BITCOIND", "BITCOINCLI", "BITCOIN_BIN", "BITCOIN_CMD", "PREVIOUS_RELEASES_DIR"):
        environment.pop(name, None)
    command = [
        sys.executable, "-B", str(test), "--configfile", str(config_path),
        "--tmpdir", str(work / "test-data"), "--cachedir", str(work / "cache"),
        "--nocleanup", "--v1transport", "--timeout-factor=2",
    ]
    with (work / "functional.log").open("wb") as output:
        with subprocess.Popen(command, cwd=work, env=environment, stdout=output, stderr=output, start_new_session=True) as proc:
            try:
                return_code = proc.wait(timeout=240)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
                raise SystemExit(f"Header proof functional test exceeded 240 seconds; see {work / 'functional.log'}")
    print(f"Header proof functional test exit {return_code}; log {work / 'functional.log'}", flush=True)
    if return_code:
        raise SystemExit(return_code)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Exercise the public macOS GUI and companion CLI on a disposable GitHub runner."""

import argparse
import json
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time
from decimal import Decimal
from pathlib import Path

SUBSIDY = Decimal("42.94967296")
AMOUNT = Decimal("1.00000000")
MAINNET_WINDOW_SECONDS = 110
STARTUP_SECONDS = 50
WINDOW_HELPER = r"""
import ApplicationServices
import CoreGraphics
import Foundation

let pid = pid_t(CommandLine.arguments[1])!
if CommandLine.arguments.count == 2 {
    let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID)
    for window in (windows as? [[String: Any]] ?? []) {
        guard window[kCGWindowOwnerPID as String] as? Int == Int(pid),
              window[kCGWindowLayer as String] as? Int == 0,
              let bounds = window[kCGWindowBounds as String] as? [String: Double],
              (bounds["Width"] ?? 0) >= 120, (bounds["Height"] ?? 0) >= 80,
              let number = window[kCGWindowNumber as String] as? Int else { continue }
        print(number)
        exit(0)
    }
    print("No visible application window")
    exit(2)
}

guard AXIsProcessTrusted() else {
    print("Accessibility permission unavailable")
    exit(3)
}

func attribute(_ element: AXUIElement, _ key: String) -> CFTypeRef? {
    var value: CFTypeRef?
    guard AXUIElementCopyAttributeValue(element, key as CFString, &value) == .success else {
        return nil
    }
    return value
}

let target = CommandLine.arguments[2].lowercased()
let application = AXUIElementCreateApplication(pid)
AXUIElementSetMessagingTimeout(application, 0.5)
var pending = [(application, 0)]
if let bar = attribute(application, kAXMenuBarAttribute), CFGetTypeID(bar) == AXUIElementGetTypeID() {
    pending.append((unsafeBitCast(bar, to: AXUIElement.self), 0))
}
for _ in 0..<450 {
    guard let (element, depth) = pending.popLast() else { break }
    let role = attribute(element, kAXRoleAttribute) as? String ?? ""
    if ["AXButton", "AXRadioButton", "AXTab", "AXMenuItem"].contains(role) {
        for key in [kAXTitleAttribute, kAXDescriptionAttribute, kAXHelpAttribute] {
            let title = (attribute(element, key) as? String ?? "").replacingOccurrences(of: "&", with: "").lowercased()
            if title == target || (target == "about" && title.hasPrefix("about sugarchain")) {
                if AXUIElementPerformAction(element, kAXPressAction as CFString) == .success {
                    print("Pressed \(title)")
                    exit(0)
                }
            }
        }
    }
    if depth < 16, let children = attribute(element, kAXChildrenAttribute) as? [AXUIElement] {
        pending.append(contentsOf: children.reversed().map { ($0, depth + 1) })
    }
}
print("No accessible control for \(target)")
exit(4)
"""


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class VisualChecks:
    def __init__(self, scratch, output):
        self.records = {
            name: {"status": "not_run", "reason": "The required application state was not reached"}
            for name in (
                "mainnet-startup", "mainnet-sync", "regtest-wallet", "regtest-overview",
                "regtest-send", "regtest-receive", "regtest-transactions", "regtest-about",
            )
        }
        self.root = output / "screenshots"
        self.root.mkdir(exist_ok=True)
        self.helper = scratch / "window-inspector"
        source = scratch / "window-inspector.swift"
        source.write_text(WINDOW_HELPER, encoding="utf-8")
        try:
            self.command(["/usr/bin/xcrun", "swiftc", str(source), "-o", str(self.helper)], timeout=30)
            self.helper_error = None
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
            self.helper_error = str(error)[-400:]

    @staticmethod
    def command(args, *, timeout=4):
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout).strip() or f"Return code {result.returncode}")
        return result.stdout.strip()

    def window(self, pid):
        if self.helper_error:
            raise RuntimeError(self.helper_error)
        return int(self.command([str(self.helper), str(pid)]))

    def screenshot(self, pid, name, *, different_window=None):
        path = self.root / f"{name}.png"
        try:
            window = self.window(pid)
            require(window != different_window, "The About window did not appear separately")
            self.command(["/usr/sbin/screencapture", "-x", "-o", "-l", str(window), str(path)])
            with path.open("rb") as image:
                header = image.read(24)
            require(header.startswith(b"\x89PNG\r\n\x1a\n") and len(header) == 24, "Screenshot did not produce a PNG")
            width, height = struct.unpack(">II", header[16:24])
            require(width >= 120 and height >= 80, "Screenshot dimensions were too small")
            self.records[name] = {"status": "captured", "path": f"screenshots/{path.name}", "width": width, "height": height}
        except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as error:
            path.unlink(missing_ok=True)
            self.records[name] = {"status": "not_run", "reason": str(error)[-400:]}

    def wallet_views(self, pid):
        self.screenshot(pid, "regtest-wallet")
        for view in ("overview", "send", "receive", "transactions", "about"):
            name = f"regtest-{view}"
            try:
                if self.helper_error:
                    raise RuntimeError(self.helper_error)
                old_window = self.window(pid) if view == "about" else None
                pressed = self.command([str(self.helper), str(pid), view])
                time.sleep(0.5)
                self.screenshot(pid, name, different_window=old_window)
                self.records[name]["navigation"] = pressed
            except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as error:
                self.records[name] = {"status": "not_run", "reason": str(error)[-400:]}


class GuiNode:
    def __init__(self, gui, cli, data, chain):
        self.gui = gui
        self.cli = cli
        self.data = data
        self.chain = chain
        self.chain_data = data / "regtest" if chain == "regtest" else data
        self.process = None
        self.clean_exit = False

    def __enter__(self):
        self.data.mkdir(exist_ok=True)
        with socket.socket() as port_socket:
            port_socket.bind(("127.0.0.1", 0))
            self.port = port_socket.getsockname()[1]
        self.common = [f"-datadir={self.data}", f"-chain={self.chain}", f"-rpcport={self.port}"]
        network = ["-prune=550", "-maxconnections=3"]
        if self.chain == "regtest":
            network = ["-connect=0", "-dnsseed=0", "-fixedseeds=0", "-networkactive=0", "-fallbackfee=0.0002"]
        env = os.environ.copy()
        for name in ("QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH"):
            env.pop(name, None)
        env["QT_QPA_PLATFORM"] = "cocoa"
        self.output = self.data / f"process-{self.port}.log"
        args = [
            str(self.gui), *self.common, "-server=1", "-listen=0", "-listenonion=0",
            "-discover=0", "-natpmp=0", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
            "-dbcache=32", "-par=1", "-keypool=10", "-splash=0", "-printtoconsole=0",
            *network,
        ]
        with self.output.open("wb") as log:
            self.process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, env=env)
        return self

    def rpc(self, method, *params, wallet=None, named=False, timeout=8):
        args = [str(self.cli), *self.common, f"-rpcclienttimeout={max(1, int(timeout))}"]
        if wallet is not None:
            args.append(f"-rpcwallet={wallet}")
        if named:
            args.append("-named")
        result = subprocess.run(
            [*args, method, *map(str, params)], capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode != 0:
            raise RuntimeError(f"{method} failed ({result.returncode}): {result.stderr.strip()[-400:]}")
        body = result.stdout.strip()
        try:
            return json.loads(body, parse_float=Decimal)
        except json.JSONDecodeError:
            return body

    def ready(self, deadline):
        last_error = "RPC was unavailable"
        while time.monotonic() < deadline:
            require(self.process.poll() is None, f"Cocoa app exited during startup ({self.process.returncode})")
            try:
                return self.rpc("getblockchaininfo", timeout=min(4, max(0.2, deadline - time.monotonic())))
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                last_error = str(error)
                time.sleep(0.25)
        raise RuntimeError(f"Cocoa app did not reach RPC before its startup deadline. {last_error}")

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            require(self.process.poll() is None, f"Cocoa app exited before shutdown ({self.process.returncode})")
            self.rpc("stop", timeout=4)
            self.clean_exit = self.process.wait(timeout=12) == 0
            require(self.clean_exit, f"Cocoa app shutdown returned {self.process.returncode}")
        except (RuntimeError, subprocess.TimeoutExpired):
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=4)
            if exc_type is None:
                raise


def test_regtest(gui, cli, datadir, evidence, visuals):
    with GuiNode(gui, cli, datadir, "regtest") as node:
        info = node.ready(time.monotonic() + STARTUP_SECONDS)
        require(info["chain"] == "regtest" and info["blocks"] == 0, f"Expected fresh regtest, got {info['chain']}")
        require(node.rpc("getnetworkinfo")["connections"] == 0, "Regtest unexpectedly connected to a peer")
        for name in ("sender", "receiver"):
            node.rpc("createwallet", f"wallet_name={name}", "load_on_startup=true", named=True)
        sender = node.rpc("getnewaddress", "", "bech32", wallet="sender")
        receiver = node.rpc("getnewaddress", "", "bech32", wallet="receiver")
        require(sender.startswith("rugar1q") and receiver.startswith("rugar1q"), "Unexpected regtest address prefix")
        evidence["receive_address"] = receiver
        validation = node.rpc("validateaddress", receiver)
        require(validation["isvalid"], "Regtest rejected its own receive address")
        block_hash = node.rpc("generatetoaddress", 1, sender)[0]
        reward = node.rpc("getblock", block_hash, 2)["tx"][0]["vout"][0]["value"]
        require(reward == SUBSIDY, f"First block reward was {reward} SUGAR")
        evidence["first_subsidy_sugar"] = str(reward)
        node.rpc("generatetoaddress", 100, sender, timeout=60)
        txid = node.rpc("sendtoaddress", receiver, str(AMOUNT), wallet="sender")
        node.rpc("generatetoaddress", 1, sender)
        transfer = node.rpc("gettransaction", txid, wallet="receiver")
        require(transfer["confirmations"] >= 1 and transfer["amount"] == AMOUNT, "Recipient transfer was not confirmed")
        evidence["transfer"] = {"txid": txid, "received_sugar": str(transfer["amount"]), "confirmations": transfer["confirmations"]}
        backup = datadir / "synthetic-receiver.backup"
        node.rpc("backupwallet", backup, wallet="receiver")
        node.rpc("restorewallet", "restored", backup, "true")
        original = node.rpc("getbalances", wallet="receiver")["mine"]["trusted"]
        restored = node.rpc("getbalances", wallet="restored")["mine"]["trusted"]
        ownership = node.rpc("getaddressinfo", receiver, wallet="restored")["ismine"]
        require(ownership and restored == original == AMOUNT, "Restored wallet did not match receiver address ownership and balance")
        evidence["backup_restore"] = {"owns_receive_address": ownership, "confirmed_balance_sugar": str(restored)}
        visuals.wallet_views(node.process.pid)
    evidence["shutdown"] = "passed"
    return receiver


def test_mainnet(gui, cli, datadir, regtest_address, evidence, visuals):
    start = time.monotonic()
    with GuiNode(gui, cli, datadir, "main") as node:
        deadline = start + MAINNET_WINDOW_SECONDS
        initial = node.ready(min(deadline, start + STARTUP_SECONDS))
        require(initial["chain"] == "main", f"Expected mainnet, got {initial['chain']}")
        require(node.rpc("getnetworkinfo")["networkactive"], "Mainnet networking did not start")
        node.rpc("createwallet", "synthetic-mainnet")
        address = node.rpc("getnewaddress", "", "bech32", wallet="synthetic-mainnet")
        require(address.startswith("sugar1q"), "Unexpected mainnet address prefix")
        require(node.rpc("validateaddress", address)["isvalid"], "Mainnet rejected its own receive address")
        evidence.update({"startup": "passed", "receive_address": address, "initial_headers": initial["headers"]})
        if time.monotonic() + 12 < deadline:
            visuals.screenshot(node.process.pid, "mainnet-startup")
        if regtest_address:
            require(not node.rpc("validateaddress", regtest_address)["isvalid"], "Mainnet accepted a regtest address")
            evidence["rejects_regtest_address"] = True
        peers_connected, headers, presynced = 0, initial["headers"], 0
        while time.monotonic() + 6 < deadline:
            status = node.rpc("getblockchaininfo", timeout=3)
            peers = node.rpc("getpeerinfo", timeout=3)
            peers_connected = max(peers_connected, sum(peer["version"] > 0 for peer in peers))
            headers = max(headers, status["headers"])
            presynced = max([presynced, *(peer.get("presynced_headers", 0) for peer in peers)])
            if peers_connected and (headers > 0 or presynced > 0):
                break
            time.sleep(1)
        evidence.update({
            "peers_connected": peers_connected,
            "headers": headers,
            "presynced_headers": presynced,
            "initial_sync": "passed" if peers_connected and (headers > 0 or presynced > 0) else "inconclusive",
            "observation_seconds": round(time.monotonic() - start, 1),
        })
        node.rpc("setnetworkactive", "false", timeout=3)
        if evidence["initial_sync"] == "passed":
            visuals.screenshot(node.process.pid, "mainnet-sync")
    evidence["shutdown"] = "passed"
    return address


def test_restart(gui, cli, datadir, mainnet_address, regtest, evidence):
    with GuiNode(gui, cli, datadir, "regtest") as node:
        info = node.ready(time.monotonic() + STARTUP_SECONDS)
        require(info["blocks"] == 102, f"Unexpected regtest height after restart: {info['blocks']}")
        require({"sender", "receiver", "restored"} <= set(node.rpc("listwallets")), "Saved test wallets did not reopen")
        transfer = node.rpc("gettransaction", regtest["transfer"]["txid"], wallet="receiver")
        require(transfer["confirmations"] >= 1 and transfer["amount"] == AMOUNT, "Confirmed transfer did not survive restart")
        require(node.rpc("getaddressinfo", regtest["receive_address"], wallet="restored")["ismine"], "Restored address was lost at restart")
        if mainnet_address:
            require(not node.rpc("validateaddress", mainnet_address)["isvalid"], "Regtest accepted a mainnet address")
            evidence["rejects_mainnet_address"] = True
    evidence["shutdown"] = "passed"
    evidence["height"] = 102


def record_diagnostics(data, output, label):
    for path in sorted(data.glob("process-*.log")):
        with path.open("rb") as source:
            source.seek(max(path.stat().st_size - 4096, 0))
            (output / f"{label}-{path.name}").write_bytes(source.read())


def run_check(result, step, call):
    row = result.setdefault(step, {})
    try:
        value = call(row)
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        row.update({"status": "failed", "error": str(error)[-500:]})
        return None
    row["status"] = "passed"
    if row.get("initial_sync") == "inconclusive":
        row["status"] = "inconclusive"
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == "darwin" and os.environ.get("GITHUB_ACTIONS") == "true", "Requires a disposable macOS GitHub Actions runner")
    app = args.app.resolve()
    cli = args.cli.resolve()
    gui = app / "Contents/MacOS/Sugarchain-Qt"
    require(app.name == "Sugarchain-Qt.app" and gui.is_file() and cli.is_file(), "Expected the extracted public macOS GUI and CLI")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    result = {
        "tag": "v31.1.1-en.1",
        "architecture": platform.machine(),
        "platform": platform.platform(),
    }
    with tempfile.TemporaryDirectory(prefix="sugarchain-public-macos-", dir=os.environ["RUNNER_TEMP"]) as temp:
        area = Path(temp)
        integrity = result["package"] = {}
        try:
            for binary in (app, cli):
                subprocess.run(["codesign", "--verify", "--deep", "--strict", str(binary)], check=True, capture_output=True, text=True)
            integrity["code_signature"] = "passed"
            architectures = subprocess.check_output(["lipo", "-archs", str(gui)], text=True).split()
            require(platform.machine() in architectures, f"Bundle architecture {architectures} does not match this runner")
            version = subprocess.check_output([str(cli), f"-datadir={area}", "-version"], text=True, timeout=10)
            require(re.search(r"(?<!\d)31\.1\.1(?!\d)", version), "CLI version did not match 31.1.1")
            integrity.update({"status": "passed", "cli_version": version.splitlines()[0], "architectures": architectures})
        except (RuntimeError, OSError, subprocess.SubprocessError) as error:
            integrity.update({"status": "failed", "error": str(error)[-500:]})
        try:
            assessment = subprocess.run(
                ["spctl", "--assess", "--type", "execute", "--verbose=2", str(app)],
                capture_output=True, text=True, timeout=10,
            )
            integrity["gatekeeper_policy_assessment"] = {
                "exit_code": assessment.returncode,
                "output": (assessment.stderr or assessment.stdout).strip()[-300:],
                "quarantined_first_launch_tested": False,
            }
        except (OSError, subprocess.TimeoutExpired) as error:
            integrity["gatekeeper_policy_assessment"] = {"status": "not_run", "error": str(error)[-200:]}
        if integrity["status"] == "passed":
            visuals = VisualChecks(area, output)
            result["ui"] = visuals.records
            regtest_data = area / "regtest-data"
            mainnet_data = area / "mainnet-data"
            receiver = run_check(result, "regtest", lambda row: test_regtest(gui, cli, regtest_data, row, visuals))
            mainnet_address = run_check(result, "mainnet", lambda row: test_mainnet(gui, cli, mainnet_data, receiver, row, visuals))
            if receiver:
                run_check(result, "restart", lambda row: test_restart(gui, cli, regtest_data, mainnet_address, result["regtest"], row))
            else:
                result["restart"] = {"status": "not_run", "reason": "Regtest did not complete"}
            record_diagnostics(regtest_data, output, "regtest")
            record_diagnostics(mainnet_data, output, "mainnet")
    (output / "results.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({step: detail["status"] for step, detail in result.items() if isinstance(detail, dict) and "status" in detail}))
    return int(any(detail.get("status") == "failed" for detail in result.values() if isinstance(detail, dict)))


if __name__ == "__main__":
    sys.exit(main())

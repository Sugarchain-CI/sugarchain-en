"""Start the signed static-Qt package and its bundled command-line tools."""

import argparse
from pathlib import Path
import runpy
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "bindir", "gui", "work"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    helper_dir = args.source / "contrib" / "macdeploy"
    sys.path.insert(0, str(helper_dir))
    helpers = runpy.run_path(str(helper_dir / "verify-native.py"))
    node_for = helpers["Node"]
    require = helpers["require"]
    args.work.mkdir()
    for name in ("sugarchain", "sugarchaind", "sugarchain-cli", "sugarchain-wallet", "sugarchain-tx", "sugarchain-util"):
        helpers["check_version"](args.bindir / name, args.work / "versions")

    for binary, chain in ((args.bindir / "sugarchaind", "main"), (args.gui, "regtest")):
        directory = args.work / chain
        with node_for(binary, directory, chain, gui=binary == args.gui) as node:
            require(helpers["check_chain"](node, chain)["blocks"] == 0, "The smoke profile must be fresh")
            blockcount = subprocess.check_output(
                [str(args.bindir / "sugarchain-cli"), f"-datadir={directory}", f"-chain={chain}",
                 f"-rpcport={node.port}", "getblockcount"], text=True, timeout=30)
            require(blockcount.strip() == "0", "The packaged CLI did not reach the isolated node")
            node.rpc("createwallet", "release-test")
            address = node.rpc("getnewaddress", "", "bech32")
            if chain == "main":
                require(address.startswith("sugar1q"), "Unexpected Mainnet wallet address")
            else:
                blocks = node.rpc("generatetoaddress", 1, address)
                require(len(blocks) == 1 and node.rpc("getblockcount") == 1, "Regtest mining failed")
        print(f"{chain}: signed package startup, wallet, installed CLI and clean shutdown passed", flush=True)


if __name__ == "__main__":
    main()

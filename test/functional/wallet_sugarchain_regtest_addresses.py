#!/usr/bin/env python3
# Copyright (c) 2026 The Sugarchain En developers
# Distributed under the MIT software license, see the accompanying file COPYING.
"""Open a wallet with previous En regtest addresses under the native address profile."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class SugarchainRegtestAddressTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.use_bitcoin_regtest = False
        self.wallet_names = []
        self.extra_args = [["-test=bitcoinregtest"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("regtest_wallet", load_on_startup=True)
        node.createwallet("watch_only", disable_private_keys=True, load_on_startup=True)
        wallet = node.get_wallet_rpc("regtest_wallet")
        watch = node.get_wallet_rpc("watch_only")
        address_types = (
            ("legacy", ("m", "n"), "R"),
            ("p2sh-segwit", ("2",), "r"),
            ("bech32", ("bcrt1q",), "rugar1q"),
        )
        old_addresses = {}
        for address_type, old_prefix, native_prefix in address_types:
            old = wallet.getnewaddress(label=address_type, address_type=address_type)
            assert old.startswith(old_prefix), old
            descriptor = node.getdescriptorinfo(f"addr({old})")["descriptor"]
            assert_equal(watch.importdescriptors([{"desc": descriptor, "timestamp": "now"}]), [{"success": True}])
            old_addresses[old] = (address_type, native_prefix, descriptor)

        self.restart_node(0, extra_args=[])
        assert_equal(set(node.listwallets()), {"regtest_wallet", "watch_only"})
        wallet = node.get_wallet_rpc("regtest_wallet")
        watch = node.get_wallet_rpc("watch_only")
        for old, (address_type, native_prefix, descriptor) in old_addresses.items():
            address_info = wallet.getaddressinfo(old)
            assert_equal(address_info["ismine"], True)
            assert_equal(address_info["labels"], [address_type])
            native = address_info["address"]
            assert native.startswith(native_prefix), native
            assert_equal(wallet.getaddressinfo(native)["ismine"], True)
            assert_equal(watch.getaddressinfo(native)["ismine"], True)
            assert descriptor in [record["desc"] for record in watch.listdescriptors()["descriptors"]]
            new_address = wallet.getnewaddress(address_type=address_type)
            assert new_address.startswith(native_prefix), new_address


if __name__ == "__main__":
    SugarchainRegtestAddressTest(__file__).main()

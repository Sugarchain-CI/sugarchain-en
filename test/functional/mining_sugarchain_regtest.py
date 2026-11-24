#!/usr/bin/env python3
# Copyright (c) 2026 The Sugarchain En developers
# Distributed under the MIT software license, see the accompanying file COPYING.
"""Mine the first block under the default Sugarchain regtest rules."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class SugarchainRegtestMiningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.use_bitcoin_regtest = False

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockchaininfo()["chain"], "regtest")
        block_hash, = self.generatetodescriptor(node, 1, "raw(51)")
        block = node.getblock(block_hash, 2)
        assert_equal(block["height"], 1)
        assert_equal(block["tx"][0]["vout"][0]["value"], Decimal("42.94967296"))


if __name__ == "__main__":
    SugarchainRegtestMiningTest(__file__).main()

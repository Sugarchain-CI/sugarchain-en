#!/usr/bin/env python3
# Copyright (c) 2026 The Sugarchain En developers
# Distributed under the MIT software license, see the accompanying file COPYING.
"""Validate the historical Sugarchain testnet with real peers and wallet transactions."""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.segwit_addr import encode_segwit_address
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

GENESIS = "14f06e88eec9b21214a1eb54eee3cc03ceaf78ead1b16e40d8a383a5ff3e5e24"
SUBSIDY = Decimal("42.94967296")
TRANSFER_AMOUNT = Decimal("1.00000000")
MAX_MINING_BATCH = 20
MAX_HASH_ATTEMPTS = 250_000
SENDER = "testnet_sender"
RECEIVER = "testnet_receiver"
RESTORED = "testnet_restored"


class SugarchainTestnetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "testnet7"
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.wallet_names = []
        self.rpc_timeout = 180
        self.extra_args = [["-dnsseed=0", "-fixedseeds=0"] for _ in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_blocks(self, miner, count, address):
        blocks = []
        while count:
            batch_size = min(count, MAX_MINING_BATCH)
            batch = self.generatetoaddress(miner, batch_size, address, maxtries=MAX_HASH_ATTEMPTS)
            assert_equal(len(batch), batch_size)
            blocks.extend(batch)
            count -= batch_size
        return blocks

    def check_receive(self, wallet, address, txid):
        assert wallet.getaddressinfo(address)["ismine"]
        transaction = wallet.gettransaction(txid)
        assert_equal(transaction["amount"], TRANSFER_AMOUNT)
        assert_equal(transaction["confirmations"], 1)
        assert_equal(wallet.getbalances()["mine"]["trusted"], TRANSFER_AMOUNT)

    def run_test(self):
        miner, peer = self.nodes
        for node in self.nodes:
            assert_equal(node.getblockchaininfo()["chain"], "test")
            assert_equal(node.getblockhash(0), GENESIS)
            genesis = node.getblockheader(GENESIS)
            assert_equal(genesis["time"], 1795575600)
            assert_equal(genesis["nonce"], 1320)
            assert_equal(genesis["bits"], "1f3fffff")
            assert_equal(node.getblockcount(), 0)
            assert_equal(node.getconnectioncount(), 1)

        miner.createwallet(wallet_name=SENDER, load_on_startup=True)
        peer.createwallet(wallet_name=RECEIVER, load_on_startup=True)
        sender = miner.get_wallet_rpc(SENDER)
        receiver = peer.get_wallet_rpc(RECEIVER)
        mining_address = sender.getnewaddress(address_type="bech32")
        receive_address = receiver.getnewaddress(address_type="bech32")

        self.log.info("Check native testnet addresses and cross-network rejection")
        assert mining_address.startswith("tugar1q"), mining_address
        assert receive_address.startswith("tugar1q"), receive_address
        assert peer.validateaddress(receive_address)["isvalid"]
        witness_program = bytes(range(20))
        for hrp in ("sugar", "rugar"):
            address = encode_segwit_address(hrp, 0, witness_program)
            assert_equal(peer.validateaddress(address)["isvalid"], False)

        self.log.info("Mine and relay a native block from the Testnet7 genesis")
        block_hash, = self.mine_blocks(miner, 1, mining_address)
        block = peer.getblock(block_hash, 2)
        assert_equal(block["height"], 1)
        assert_equal(block["previousblockhash"], GENESIS)
        assert_equal(block["tx"][0]["vout"][0]["value"], SUBSIDY)
        assert_equal(peer.getbestblockhash(), block_hash)

        self.log.info("Mature the first coinbase and transfer 1 SUGAR across the peer connection")
        self.mine_blocks(miner, COINBASE_MATURITY, mining_address)
        txid = sender.sendtoaddress(receive_address, TRANSFER_AMOUNT)
        self.sync_mempools()
        assert txid in peer.getrawmempool()
        self.mine_blocks(miner, 1, mining_address)
        self.check_receive(receiver, receive_address, txid)

        self.log.info("Restore the receiving wallet and check it after a clean node restart")
        backup = peer.datadir_path / "testnet-receiver.backup"
        receiver.backupwallet(str(backup))
        peer.restorewallet(RESTORED, str(backup), load_on_startup=True)
        self.check_receive(peer.get_wallet_rpc(RESTORED), receive_address, txid)
        self.restart_node(1)
        self.connect_nodes(1, 0)
        self.sync_blocks()
        assert_equal(peer.getblockcount(), COINBASE_MATURITY + 2)
        assert_equal(set(peer.listwallets()), {RECEIVER, RESTORED})
        for name in (RECEIVER, RESTORED):
            self.check_receive(peer.get_wallet_rpc(name), receive_address, txid)


if __name__ == "__main__":
    SugarchainTestnetTest(__file__).main()

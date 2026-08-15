#!/usr/bin/env python3
# Copyright (c) 2026 Yelpful Technologies
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Mine to Dilithium addresses via generatetoaddress and spend the coinbase."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class WalletDilithiumMiningTest(BitcoinTestFramework):
    def add_options(self, parser):
        # Dilithium spendable keys require the legacy ScriptPubKeyMan path
        # (descriptor wallets cannot hold them on QubitCoin).
        self.add_wallet_options(parser, descriptors=False, legacy=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()
        # QubitCoin is Dilithium-only: skip importing the framework's ECDSA
        # deterministic coinbase keys and create a fresh Dilithium wallet.
        self.nodes[0].createwallet(
            wallet_name=self.default_wallet_name,
            descriptors=False,
            load_on_startup=True,
        )

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Generate a Dilithium address")
        addr = node.getnewaddress("", "dilithium")
        info = node.getaddressinfo(addr)
        assert_equal(info["ispostquantum"], True)
        assert_equal(info["ismine"], True)
        assert_equal(len(info["pubkey"]), 1952 * 2)  # hex-encoded ML-DSA-65 pubkey

        height_before = node.getblockcount()
        self.log.info("Mine blocks to the Dilithium address with generatetoaddress")
        hashes = self.generatetoaddress(node, 101, addr)
        assert_equal(len(hashes), 101)
        assert_equal(node.getblockcount(), height_before + 101)

        tip = node.getblock(hashes[-1], 2)
        coinbase_outs = tip["tx"][0]["vout"]
        # Coinbase must pay the Dilithium destination's P2PKH script. getblock may
        # display the same 20-byte hash as a legacy address (ExtractDestination),
        # so compare scriptPubKey hex rather than the encoded address string.
        assert_equal(coinbase_outs[0]["scriptPubKey"]["hex"], info["scriptPubKey"])

        balance = node.getbalance()
        assert_greater_than(balance, 0)

        self.log.info("Spend matured Dilithium coinbase to another Dilithium address")
        dest = node.getnewaddress("", "dilithium")
        txid = node.sendtoaddress(dest, 10)
        self.generatetoaddress(node, 1, addr)
        tx = node.gettransaction(txid)
        assert_equal(tx["confirmations"], 1)


if __name__ == "__main__":
    WalletDilithiumMiningTest(__file__).main()

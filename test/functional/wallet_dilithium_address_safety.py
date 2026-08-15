#!/usr/bin/env python3
# Copyright (c) 2026 Yelpful Technologies
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Refuse to pay address types that QubitCoin can never spend.

Only ML-DSA-65 keys can sign here, so paying a legacy P2PKH, P2SH, P2WPKH,
P2WSH or Taproot address burns the funds with no way to recover them. Every RPC
that turns an address into an output must refuse, and validateaddress must say
so rather than reporting a bare "isvalid: true".
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

# Any valid secp256k1 point works; it is only ever hashed into an address here.
ECDSA_PUBKEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

BURN_ERROR = "Sending to this address would burn the funds"
AMOUNT = 1


class WalletDilithiumAddressSafetyTest(BitcoinTestFramework):
    def add_options(self, parser):
        # Dilithium spendable keys require the legacy ScriptPubKeyMan path.
        self.add_wallet_options(parser, descriptors=False, legacy=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()
        # QubitCoin is Dilithium-only: skip the framework's ECDSA deterministic
        # coinbase keys and create a fresh Dilithium wallet.
        self.nodes[0].createwallet(
            wallet_name=self.default_wallet_name,
            descriptors=False,
            load_on_startup=True,
        )

    def unspendable_addresses(self):
        """One address per dead type, encoded by the node itself.

        Derived through descriptors rather than hardcoded so the strings carry
        this network's base58 version bytes and bech32 HRP: a literal Bitcoin
        address would be rejected merely for belonging to another chain, which
        would not exercise the guard at all.
        """
        node = self.nodes[0]
        addresses = {}
        for name, descriptor in [
            ("legacy P2PKH", f"pkh({ECDSA_PUBKEY})"),
            ("P2SH", f"sh(wpkh({ECDSA_PUBKEY}))"),
            ("P2WPKH", f"wpkh({ECDSA_PUBKEY})"),
            ("P2WSH", f"wsh(pkh({ECDSA_PUBKEY}))"),
            ("P2TR", f"tr({ECDSA_PUBKEY})"),
        ]:
            checksummed = node.getdescriptorinfo(descriptor)["descriptor"]
            addresses[name] = node.deriveaddresses(checksummed)[0]
        return addresses

    def test_validateaddress(self, dilithium, dead):
        self.log.info("validateaddress distinguishes spendable from unspendable")
        node = self.nodes[0]

        info = node.validateaddress(dilithium)
        assert_equal(info["isvalid"], True)
        assert_equal(info["ispostquantum"], True)
        assert "warnings" not in info

        for name, address in dead.items():
            info = node.validateaddress(address)
            # Well-formed for this network, which is exactly why the warning is
            # needed: "isvalid" alone would read as "safe to pay".
            assert_equal(info["isvalid"], True)
            assert_equal(info["ispostquantum"], False)
            assert_equal(len(info["warnings"]), 1)
            assert BURN_ERROR in info["warnings"][0], (name, info["warnings"])

            # getaddressinfo agrees, for wallets inspecting a pasted address.
            assert_equal(node.getaddressinfo(address)["ispostquantum"], False)

    def test_sends_are_refused(self, dilithium, dead):
        self.log.info("Every send RPC refuses an unspendable destination")
        node = self.nodes[0]

        for name, address in dead.items():
            self.log.info(f"  {name}: {address}")
            assert_raises_rpc_error(-5, BURN_ERROR, node.sendtoaddress, address, AMOUNT)
            assert_raises_rpc_error(-5, BURN_ERROR, node.sendmany, "", {address: AMOUNT})
            assert_raises_rpc_error(-5, BURN_ERROR, node.send, {address: AMOUNT}, None, "unset", None)
            assert_raises_rpc_error(-5, BURN_ERROR, node.sendall, [address])
            assert_raises_rpc_error(-5, BURN_ERROR, node.walletcreatefundedpsbt,
                                    [], [{address: AMOUNT}])
            # Also blocked one layer down, where addresses become outputs, so
            # the manual create/sign/broadcast route cannot walk around it.
            assert_raises_rpc_error(-5, BURN_ERROR, node.createrawtransaction,
                                    [], [{address: AMOUNT}])

            # A good recipient does not launder a bad one in the same call.
            assert_raises_rpc_error(-5, BURN_ERROR, node.sendmany, "",
                                    {dilithium: AMOUNT, address: AMOUNT})

    def test_change_address_is_refused(self, dilithium, dead):
        self.log.info("Custom change addresses are refused too")
        node = self.nodes[0]
        raw = node.createrawtransaction([], [{dilithium: AMOUNT}])

        for name, address in dead.items():
            assert_raises_rpc_error(-5, BURN_ERROR, node.fundrawtransaction, raw,
                                    {"change_address": address})
            assert_raises_rpc_error(-5, BURN_ERROR, node.walletcreatefundedpsbt,
                                    [], [{dilithium: AMOUNT}], 0, {"change_address": address})

        # Change to a Dilithium address is still accepted.
        funded = node.fundrawtransaction(raw, {"change_address": dilithium})
        assert_greater_than(funded["fee"], 0)

    def test_script_derived_addresses_match_getnewaddress(self, dilithium):
        """listunspent / gettransaction / getblock use the Dilithium encoding.

        A P2PKH script is byte-identical to leftover ECDSA P2PKH. Before the
        ExtractDestination fix those RPCs emitted the ECDSA version byte, which
        burn protection then refused even though the Dilithium key can spend it.
        """
        self.log.info("Script-derived Dilithium outputs keep the Dilithium address")
        node = self.nodes[0]

        dest = node.getnewaddress("", "dilithium")
        assert_equal(node.validateaddress(dest)["ispostquantum"], True)
        txid = node.sendtoaddress(dest, AMOUNT)
        self.generatetoaddress(node, 1, dilithium)

        # listunspent must show the same address getnewaddress issued, not the
        # leftover ECDSA encoding of the same hash160.
        unspent = [u for u in node.listunspent(1, 9999999, [dest]) if u["txid"] == txid]
        assert_equal(len(unspent), 1)
        listed = unspent[0]["address"]
        assert_equal(listed, dest)
        assert_equal(node.validateaddress(listed)["ispostquantum"], True)

        # Wallet-owned Dilithium outputs must not be shown with the leftover
        # ECDSA version byte (d... on regtest / D... on mainnet).
        for u in node.listunspent():
            address = u.get("address")
            if address:
                assert node.validateaddress(address)["ispostquantum"], \
                    f"listunspent showed leftover encoding {address}"

        # That listed address is payable — the launch-blocker was that it was not.
        paid = node.sendtoaddress(listed, AMOUNT)
        assert_equal(len(paid), 64)

        # gettransaction details and getblock must not emit the ECDSA encoding.
        details = node.gettransaction(txid)["details"]
        received = [d["address"] for d in details if d.get("category") == "receive"]
        assert dest in received
        for address in received:
            assert_equal(node.validateaddress(address)["ispostquantum"], True)

        raw = node.gettransaction(txid, False, True)
        decoded = raw["decoded"] if "decoded" in raw else node.decoderawtransaction(raw["hex"])
        for vout in decoded["vout"]:
            address = vout["scriptPubKey"].get("address")
            if address:
                assert_equal(node.validateaddress(address)["ispostquantum"], True)

        tip = node.getblock(node.getbestblockhash(), 2)
        for tx in tip["tx"]:
            for vout in tx["vout"]:
                address = vout["scriptPubKey"].get("address")
                if address:
                    assert node.validateaddress(address)["ispostquantum"], \
                        f"getblock showed leftover encoding {address}"

    def test_dilithium_sends_still_work(self, dilithium):
        self.log.info("Sending to Dilithium addresses is unaffected")
        node = self.nodes[0]
        second = node.getnewaddress("", "dilithium")

        sent = [
            node.sendtoaddress(dilithium, AMOUNT),
            node.sendmany("", {dilithium: AMOUNT, second: AMOUNT}),
            node.send({second: AMOUNT}, None, "unset", None)["txid"],
        ]

        self.generatetoaddress(node, 1, dilithium)
        for txid in sent:
            assert_equal(node.gettransaction(txid)["confirmations"], 1)

        # And the wallet's own change is a Dilithium destination, so nothing in
        # the guard can make an ordinary payment unfundable.
        assert_equal(node.getaddressinfo(node.getrawchangeaddress("dilithium"))["ispostquantum"], True)

    def run_test(self):
        node = self.nodes[0]

        dilithium = node.getnewaddress("", "dilithium")
        self.generatetoaddress(node, 101, dilithium)
        assert_greater_than(node.getbalance(), 0)

        dead = self.unspendable_addresses()
        assert_equal(len(dead), 5)

        self.test_validateaddress(dilithium, dead)
        self.test_sends_are_refused(dilithium, dead)
        self.test_change_address_is_refused(dilithium, dead)
        self.test_script_derived_addresses_match_getnewaddress(dilithium)
        self.test_dilithium_sends_still_work(dilithium)


if __name__ == "__main__":
    WalletDilithiumAddressSafetyTest(__file__).main()

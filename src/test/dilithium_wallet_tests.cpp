// Copyright (c) 2026 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <coins.h>
#include <consensus/amount.h>
#include <dilithiumkey.h>
#include <dilithiumpubkey.h>
#include <key_io.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <util/translation.h>

#include <string>
#include <variant>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(dilithium_wallet_tests, BasicTestingSetup)

// A Dilithium public key can be turned into an address and decoded back to the
// same post-quantum destination type.
BOOST_AUTO_TEST_CASE(dilithium_address_roundtrip)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    CDilithiumPubKey pubkey = key.GetPubKey();

    const CTxDestination dest = DilithiumPKHash(pubkey);
    const std::string address = EncodeDestination(dest);
    BOOST_CHECK(!address.empty());

    const CTxDestination decoded = DecodeDestination(address);
    BOOST_CHECK(std::holds_alternative<DilithiumPKHash>(decoded));
    BOOST_CHECK(decoded == dest);
    BOOST_CHECK(IsValidDestination(decoded));
}

// A Dilithium address must be distinct from a legacy P2PKH address built from
// the same 20-byte hash, and must decode to a distinct destination type.
BOOST_AUTO_TEST_CASE(dilithium_address_distinct_from_legacy)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    const CKeyID id = key.GetPubKey().GetID();

    const std::string dilithium_addr = EncodeDestination(DilithiumPKHash(id));
    const std::string legacy_addr = EncodeDestination(PKHash(id));

    BOOST_CHECK(dilithium_addr != legacy_addr);
    BOOST_CHECK(std::holds_alternative<DilithiumPKHash>(DecodeDestination(dilithium_addr)));
    BOOST_CHECK(std::holds_alternative<PKHash>(DecodeDestination(legacy_addr)));

    // Both destinations produce the same on-chain P2PKH script (the distinction
    // is only at the address/wallet layer).
    BOOST_CHECK(GetScriptForDestination(DilithiumPKHash(id)) == GetScriptForDestination(PKHash(id)));
}

// End-to-end: fund a Dilithium P2PKH output and spend it, producing the
// signature through the standard SigningProvider / ProduceSignature pipeline
// (the same path the wallet's SignTransaction uses).
BOOST_AUTO_TEST_CASE(dilithium_sign_p2pkh_via_provider)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    CDilithiumPubKey pubkey = key.GetPubKey();

    FillableSigningProvider keystore;
    BOOST_REQUIRE(keystore.AddDilithiumKey(key));
    BOOST_CHECK(keystore.HaveDilithiumKey(pubkey.GetID()));

    // Receive to the Dilithium P2PKH script.
    const CScript scriptPubKey = GetScriptForDestination(DilithiumPKHash(pubkey));
    BOOST_CHECK_EQUAL(scriptPubKey.size(), 25U); // standard P2PKH template

    // BASE-sigversion (legacy) sighash does not commit to the amount, so any
    // value works here; keep it small to fit BuildCreditingTransaction's int.
    const CAmount amount = 0;
    const CTransaction txCredit{BuildCreditingTransaction(scriptPubKey, amount)};
    CMutableTransaction txSpend = BuildSpendingTransaction(CScript(), CScriptWitness(), txCredit);

    SignatureData sigdata;
    BOOST_REQUIRE(SignSignature(keystore, scriptPubKey, txSpend, 0, amount, SIGHASH_ALL, sigdata));
    BOOST_CHECK(sigdata.complete);
    BOOST_CHECK(!txSpend.vin[0].scriptSig.empty());

    // Independently verify the produced scriptSig against the output script.
    ScriptError serr = SCRIPT_ERR_OK;
    const MutableTransactionSignatureChecker checker(&txSpend, 0, amount, MissingDataBehavior::ASSERT_FAIL);
    BOOST_CHECK_MESSAGE(
        VerifyScript(txSpend.vin[0].scriptSig, scriptPubKey, nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serr),
        "VerifyScript failed: " << ScriptErrorString(serr));
}

// Signing must fail cleanly when the keystore does not hold the Dilithium key.
BOOST_AUTO_TEST_CASE(dilithium_sign_missing_key)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    const CScript scriptPubKey = GetScriptForDestination(DilithiumPKHash(key.GetPubKey()));

    FillableSigningProvider empty_keystore; // does not know the key
    const CAmount amount = 0;
    const CTransaction txCredit{BuildCreditingTransaction(scriptPubKey, amount)};
    CMutableTransaction txSpend = BuildSpendingTransaction(CScript(), CScriptWitness(), txCredit);

    SignatureData sigdata;
    BOOST_CHECK(!SignSignature(empty_keystore, scriptPubKey, txSpend, 0, amount, SIGHASH_ALL, sigdata));
    BOOST_CHECK(!sigdata.complete);
}

// End-to-end through SignTransaction() (the entry point used by the wallet),
// which resolves the input's previous output from a coins map.
BOOST_AUTO_TEST_CASE(dilithium_signtransaction_end_to_end)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    FillableSigningProvider keystore;
    BOOST_REQUIRE(keystore.AddDilithiumKey(key));

    const CScript scriptPubKey = GetScriptForDestination(DilithiumPKHash(key.GetPubKey()));
    const CAmount amount = 0;
    const CTransaction txCredit{BuildCreditingTransaction(scriptPubKey, amount)};
    CMutableTransaction txSpend = BuildSpendingTransaction(CScript(), CScriptWitness(), txCredit);

    std::map<COutPoint, Coin> coins;
    coins[txSpend.vin[0].prevout].out = txCredit.vout[0];
    coins[txSpend.vin[0].prevout].nHeight = 1;

    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(SignTransaction(txSpend, &keystore, coins, SIGHASH_ALL, input_errors));
    BOOST_CHECK(input_errors.empty());
}

BOOST_AUTO_TEST_SUITE_END()

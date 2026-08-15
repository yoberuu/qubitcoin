// Copyright (c) 2026 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dilithiumkey.h>
#include <dilithiumpubkey.h>

#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <hash.h>
#include <key.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sigcache.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <uint256.h>

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(dilithiumkey_tests, BasicTestingSetup)

namespace {
std::vector<unsigned char> PubKeyBytes(const CDilithiumPubKey& pk)
{
    return std::vector<unsigned char>(pk.begin(), pk.end());
}
} // namespace

// Basic key generation, size and public key derivation.
BOOST_AUTO_TEST_CASE(dilithiumkey_generation)
{
    CDilithiumKey key;
    BOOST_CHECK(!key.IsValid());

    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    BOOST_CHECK_EQUAL(key.size(), CDilithiumKey::SIZE);

    CDilithiumPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());
    BOOST_CHECK_EQUAL(pubkey.size(), CDilithiumPubKey::SIZE);

    // Two keys should differ.
    CDilithiumKey key2 = GenerateRandomDilithiumKey();
    BOOST_REQUIRE(key2.IsValid());
    BOOST_CHECK(pubkey != key2.GetPubKey());
}

// Phase 7 (Critical: key backup/recovery): CDilithiumKey::MakeNewKeyFromSeed is
// deterministic, and DeriveDilithiumChildSeed gives a stable per-index child seed.
// Together these let a wallet recover every key from a single master seed.
BOOST_AUTO_TEST_CASE(dilithiumkey_from_seed_recoverable)
{
    const uint256 master = uint256::ONE;

    // Deriving the same index from the same master seed reproduces the same key.
    const uint256 child0 = DeriveDilithiumChildSeed(master, 0);
    CDilithiumKey a, b;
    a.MakeNewKeyFromSeed(child0);
    b.MakeNewKeyFromSeed(child0);
    BOOST_REQUIRE(a.IsValid());
    BOOST_CHECK(a.GetPubKey() == b.GetPubKey());

    // Different indices give different keys.
    const uint256 child1 = DeriveDilithiumChildSeed(master, 1);
    CDilithiumKey c;
    c.MakeNewKeyFromSeed(child1);
    BOOST_REQUIRE(c.IsValid());
    BOOST_CHECK(a.GetPubKey() != c.GetPubKey());

    // Different master seeds give different keys at the same index.
    const uint256 child0_other = DeriveDilithiumChildSeed(uint256::ZERO, 0);
    BOOST_CHECK(child0 != child0_other);
    CDilithiumKey d;
    d.MakeNewKeyFromSeed(child0_other);
    BOOST_REQUIRE(d.IsValid());
    BOOST_CHECK(a.GetPubKey() != d.GetPubKey());

    // Simulate recovery: rebuild the first few keys of a wallet from just the
    // master seed and confirm they match the original derivation.
    std::vector<CDilithiumPubKey> original;
    for (uint32_t i = 0; i < 4; ++i) {
        CDilithiumKey k;
        k.MakeNewKeyFromSeed(DeriveDilithiumChildSeed(master, i));
        original.push_back(k.GetPubKey());
    }
    for (uint32_t i = 0; i < 4; ++i) {
        CDilithiumKey k;
        k.MakeNewKeyFromSeed(DeriveDilithiumChildSeed(master, i));
        BOOST_CHECK(k.GetPubKey() == original[i]);
    }
}

// Round-trip loading of raw key material.
BOOST_AUTO_TEST_CASE(dilithiumkey_load_roundtrip)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    BOOST_REQUIRE(key.IsValid());
    CDilithiumPubKey pubkey = key.GetPubKey();

    std::vector<unsigned char> secret(key.begin(), key.end());
    std::vector<unsigned char> pub = PubKeyBytes(pubkey);

    CDilithiumKey loaded;
    BOOST_REQUIRE(loaded.Set(secret, pub));
    BOOST_CHECK(loaded.GetPubKey() == pubkey);

    // Bad sizes are rejected.
    CDilithiumKey bad;
    BOOST_CHECK(!bad.Set(Span<const unsigned char>(secret.data(), secret.size() - 1), pub));
    BOOST_CHECK(!bad.IsValid());
}

// VerifyPubKey() answers whether a secret and a public key belong together.
// Set() cannot tell (both fields are merely the right length) and GetPubKey()
// only replays what Set() stored, so this is the only check that binds them.
BOOST_AUTO_TEST_CASE(dilithiumkey_verify_pubkey)
{
    CDilithiumKey key1 = GenerateRandomDilithiumKey();
    CDilithiumKey key2 = GenerateRandomDilithiumKey();
    BOOST_REQUIRE(key1.IsValid() && key2.IsValid());
    const CDilithiumPubKey pub1 = key1.GetPubKey();
    const CDilithiumPubKey pub2 = key2.GetPubKey();

    BOOST_CHECK(key1.VerifyPubKey(pub1));
    BOOST_CHECK(key2.VerifyPubKey(pub2));
    BOOST_CHECK(!key1.VerifyPubKey(pub2));
    BOOST_CHECK(!key2.VerifyPubKey(pub1));

    // Swapping the cached public key does not change the answer: the check
    // depends on the secret and the argument, never on what Set() cached.
    const std::vector<unsigned char> secret1(key1.begin(), key1.end());
    CDilithiumKey mislabelled;
    BOOST_REQUIRE(mislabelled.Set(secret1, PubKeyBytes(pub2)));
    BOOST_CHECK(mislabelled.GetPubKey() == pub2);
    BOOST_CHECK(!mislabelled.VerifyPubKey(pub2));
    BOOST_CHECK(mislabelled.VerifyPubKey(pub1));

    // Neither an invalid key nor an invalid public key can pass.
    BOOST_CHECK(!CDilithiumKey().VerifyPubKey(pub1));
    BOOST_CHECK(!key1.VerifyPubKey(CDilithiumPubKey()));
}

// Sign a raw hash and verify directly through the public key.
BOOST_AUTO_TEST_CASE(dilithiumkey_sign_verify_hash)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    CDilithiumPubKey pubkey = key.GetPubKey();

    const uint256 hash = uint256::ONE;
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(hash, sig));
    BOOST_CHECK(!sig.empty());

    BOOST_CHECK(pubkey.Verify(hash, sig));

    // A different message hash must not verify.
    BOOST_CHECK(!pubkey.Verify(uint256::ZERO, sig));

    // A different key must not verify.
    CDilithiumPubKey other = GenerateRandomDilithiumKey().GetPubKey();
    BOOST_CHECK(!other.Verify(hash, sig));
}

// End-to-end: build a P2PK-style script secured by a Dilithium key and verify
// that a Dilithium-signed spending transaction passes the script interpreter.
BOOST_AUTO_TEST_CASE(dilithiumkey_script_checksig)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    CDilithiumPubKey pubkey = key.GetPubKey();

    // scriptPubKey: <dilithium pubkey> OP_CHECKSIG  (P2PK analogue)
    CScript scriptPubKey;
    scriptPubKey << PubKeyBytes(pubkey) << OP_CHECKSIG;

    const CAmount amount = 0;
    const CTransaction txCredit{BuildCreditingTransaction(scriptPubKey, amount)};
    CMutableTransaction txSpend = BuildSpendingTransaction(CScript(), CScriptWitness(), txCredit);

    // Sign what the interpreter will check: the tagged BIP143 message.
    const uint256 msg = DilithiumSignatureMessage(scriptPubKey, txSpend, 0, SIGHASH_ALL, amount);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(msg, sig));
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));

    // scriptSig: <signature>
    CScript scriptSig;
    scriptSig << sig;
    txSpend.vin[0].scriptSig = scriptSig;

    const uint32_t flags = SCRIPT_VERIFY_NONE;
    ScriptError err = SCRIPT_ERR_OK;
    const MutableTransactionSignatureChecker checker(&txSpend, 0, amount, MissingDataBehavior::ASSERT_FAIL);
    BOOST_CHECK_MESSAGE(
        VerifyScript(txSpend.vin[0].scriptSig, scriptPubKey, nullptr, flags, checker, &err),
        "VerifyScript failed: " << ScriptErrorString(err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

// A signature over the wrong sighash (tampered transaction) must fail.
BOOST_AUTO_TEST_CASE(dilithiumkey_script_checksig_tampered)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    CDilithiumPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << PubKeyBytes(pubkey) << OP_CHECKSIG;

    const CAmount amount = 0;
    const CTransaction txCredit{BuildCreditingTransaction(scriptPubKey, amount)};
    CMutableTransaction txSpend = BuildSpendingTransaction(CScript(), CScriptWitness(), txCredit);

    const uint256 msg = DilithiumSignatureMessage(scriptPubKey, txSpend, 0, SIGHASH_ALL, amount);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(msg, sig));
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));

    CScript scriptSig;
    scriptSig << sig;
    txSpend.vin[0].scriptSig = scriptSig;

    // Tamper with the transaction after signing (change the output value), which
    // changes the sighash and must invalidate the signature.
    txSpend.vout[0].nValue += 1;

    const uint32_t flags = SCRIPT_VERIFY_NONE;
    ScriptError err = SCRIPT_ERR_OK;
    const MutableTransactionSignatureChecker checker(&txSpend, 0, amount, MissingDataBehavior::ASSERT_FAIL);
    BOOST_CHECK(!VerifyScript(txSpend.vin[0].scriptSig, scriptPubKey, nullptr, flags, checker, &err));
}

// A valid Dilithium signature from the wrong key must fail the script check.
BOOST_AUTO_TEST_CASE(dilithiumkey_script_checksig_wrong_key)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    CDilithiumKey wrong_key = GenerateRandomDilithiumKey();

    CScript scriptPubKey;
    scriptPubKey << PubKeyBytes(key.GetPubKey()) << OP_CHECKSIG;

    const CAmount amount = 0;
    const CTransaction txCredit{BuildCreditingTransaction(scriptPubKey, amount)};
    CMutableTransaction txSpend = BuildSpendingTransaction(CScript(), CScriptWitness(), txCredit);

    const uint256 msg = DilithiumSignatureMessage(scriptPubKey, txSpend, 0, SIGHASH_ALL, amount);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(wrong_key.Sign(msg, sig)); // signed by the wrong key
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));

    CScript scriptSig;
    scriptSig << sig;
    txSpend.vin[0].scriptSig = scriptSig;

    ScriptError err = SCRIPT_ERR_OK;
    const MutableTransactionSignatureChecker checker(&txSpend, 0, amount, MissingDataBehavior::ASSERT_FAIL);
    BOOST_CHECK(!VerifyScript(txSpend.vin[0].scriptSig, scriptPubKey, nullptr, SCRIPT_VERIFY_NONE, checker, &err));
}

// QubitCoin is a pure post-quantum chain: a classic secp256k1 (ECDSA) P2PK
// spend, even with a perfectly valid ECDSA signature, must be rejected outright
// by OP_CHECKSIG because only Dilithium public keys (1952 bytes) are accepted.
BOOST_AUTO_TEST_CASE(ecdsa_checksig_rejected)
{
    CKey ckey = GenerateRandomKey();
    BOOST_REQUIRE(ckey.IsValid());
    CPubKey cpubkey = ckey.GetPubKey();

    // scriptPubKey: <secp256k1 pubkey> OP_CHECKSIG
    CScript scriptPubKey;
    scriptPubKey << std::vector<unsigned char>(cpubkey.begin(), cpubkey.end()) << OP_CHECKSIG;

    const CAmount amount = 0;
    const CTransaction txCredit{BuildCreditingTransaction(scriptPubKey, amount)};
    CMutableTransaction txSpend = BuildSpendingTransaction(CScript(), CScriptWitness(), txCredit);

    const uint256 sighash = SignatureHash(scriptPubKey, txSpend, 0, SIGHASH_ALL, amount, SigVersion::BASE);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(ckey.Sign(sighash, sig)); // a perfectly valid ECDSA signature
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));

    CScript scriptSig;
    scriptSig << sig;
    txSpend.vin[0].scriptSig = scriptSig;

    ScriptError err = SCRIPT_ERR_OK;
    const MutableTransactionSignatureChecker checker(&txSpend, 0, amount, MissingDataBehavior::ASSERT_FAIL);
    BOOST_CHECK(!VerifyScript(txSpend.vin[0].scriptSig, scriptPubKey, nullptr, SCRIPT_VERIFY_NONE, checker, &err));
    // The ECDSA public key is rejected before any signature check runs.
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUBKEYTYPE);
}

// Phase 6 (Critical DoS fix): Dilithium spends use the BIP143-style (WITNESS_V0)
// sighash, not the legacy quadratic (BASE) sighash. A signature made over the
// legacy sighash must therefore be rejected, and one made over the BIP143 sighash
// must be accepted.
BOOST_AUTO_TEST_CASE(dilithium_sighash_is_bip143)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    CDilithiumPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << PubKeyBytes(pubkey) << OP_CHECKSIG;

    const CAmount amount = 1000;
    const CTransaction txCredit{BuildCreditingTransaction(scriptPubKey, amount)};
    CMutableTransaction txSpend = BuildSpendingTransaction(CScript(), CScriptWitness(), txCredit);

    // A signature over the legacy BASE sighash (pre-fix behaviour) must NOT verify.
    const uint256 legacy_hash = SignatureHash(scriptPubKey, txSpend, 0, SIGHASH_ALL, amount, SigVersion::BASE);
    const uint256 msg = DilithiumSignatureMessage(scriptPubKey, txSpend, 0, SIGHASH_ALL, amount);
    BOOST_CHECK(legacy_hash != msg);

    std::vector<unsigned char> legacy_sig;
    BOOST_REQUIRE(key.Sign(legacy_hash, legacy_sig));
    legacy_sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));
    txSpend.vin[0].scriptSig = CScript() << legacy_sig;

    ScriptError err = SCRIPT_ERR_OK;
    const MutableTransactionSignatureChecker checker(&txSpend, 0, amount, MissingDataBehavior::ASSERT_FAIL);
    BOOST_CHECK(!VerifyScript(txSpend.vin[0].scriptSig, scriptPubKey, nullptr, SCRIPT_VERIFY_NONE, checker, &err));

    // A signature over the message built on the BIP143 sighash verifies.
    std::vector<unsigned char> good_sig;
    BOOST_REQUIRE(key.Sign(msg, good_sig));
    good_sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));
    txSpend.vin[0].scriptSig = CScript() << good_sig;

    err = SCRIPT_ERR_OK;
    const MutableTransactionSignatureChecker checker2(&txSpend, 0, amount, MissingDataBehavior::ASSERT_FAIL);
    BOOST_CHECK_MESSAGE(
        VerifyScript(txSpend.vin[0].scriptSig, scriptPubKey, nullptr, SCRIPT_VERIFY_NONE, checker2, &err),
        "BIP143 Dilithium spend should verify: " << ScriptErrorString(err));
}

/**
 * The message a Dilithium key signs is domain-separated: it is the BIP143 sighash
 * under the BIP340-style tag DILITHIUM_SIGHASH_TAG, not the sighash itself.
 *
 * Two things are pinned here. First the construction, recomputed from the literal
 * tag string rather than by calling the same helper, so the exact tag is fixed by
 * a test and cannot drift silently — it is consensus critical, and changing it
 * invalidates every signature on the chain. Second the consequence: a signature
 * over the untagged sighash, or over the same sighash under any other tag, does
 * not verify. The untagged case is the one that matters, because that digest is
 * byte-identical to what an ECDSA or Schnorr signer over this transaction would
 * be asked to produce.
 */
BOOST_AUTO_TEST_CASE(dilithium_sighash_is_domain_separated)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    const CDilithiumPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << PubKeyBytes(pubkey) << OP_CHECKSIG;

    const CAmount amount = 7777;
    const CTransaction txCredit{BuildCreditingTransaction(scriptPubKey, amount)};
    CMutableTransaction txSpend = BuildSpendingTransaction(CScript(), CScriptWitness(), txCredit);

    const uint256 sighash = SignatureHash(scriptPubKey, txSpend, 0, SIGHASH_ALL, amount, SigVersion::WITNESS_V0);
    const uint256 msg = DilithiumSignatureMessage(scriptPubKey, txSpend, 0, SIGHASH_ALL, amount);

    // The documented tag, and the documented construction.
    BOOST_CHECK_EQUAL(std::string{DILITHIUM_SIGHASH_TAG}, "QBTC-ML-DSA-65-SIGHASH");
    const uint256 expected = (HashWriter{TaggedHash("QBTC-ML-DSA-65-SIGHASH")} << sighash).GetSHA256();
    BOOST_CHECK_EQUAL(msg.ToString(), expected.ToString());

    // Tagging is not the identity: what is signed is not the bare sighash.
    BOOST_CHECK(msg != sighash);

    // A near-miss tag gives a different message, so no other domain can produce a
    // signature this chain accepts.
    for (const std::string& other : {std::string{"QBTC-ML-DSA-65-SIGHASH "},
                                     std::string{"qbtc-ml-dsa-65-sighash"},
                                     std::string{"TapSighash"},
                                     std::string{""}}) {
        BOOST_CHECK((HashWriter{TaggedHash(other)} << sighash).GetSHA256() != msg);
    }

    // End to end: only the tagged message is accepted by the interpreter.
    const auto spend_with = [&](const uint256& signed_over) {
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(key.Sign(signed_over, sig));
        sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));
        txSpend.vin[0].scriptSig = CScript() << sig;
        ScriptError err = SCRIPT_ERR_OK;
        const MutableTransactionSignatureChecker checker(&txSpend, 0, amount, MissingDataBehavior::ASSERT_FAIL);
        return VerifyScript(txSpend.vin[0].scriptSig, scriptPubKey, nullptr, SCRIPT_VERIFY_NONE, checker, &err);
    };

    BOOST_CHECK_MESSAGE(!spend_with(sighash),
                        "a signature over the untagged BIP143 sighash must not verify");
    BOOST_CHECK_MESSAGE(!spend_with((HashWriter{TaggedHash("QBTC-ML-DSA-65-SIGHASH-v2")} << sighash).GetSHA256()),
                        "a signature under a different tag must not verify");
    BOOST_CHECK_MESSAGE(spend_with(msg), "the tagged message must verify");
}

// Phase 6 (Critical DoS fix): a successful Dilithium verification through a
// CachingTransactionSignatureChecker is stored in the SignatureCache, so the same
// signature is not re-verified when the transaction is later reprocessed.
BOOST_AUTO_TEST_CASE(dilithium_signature_cache)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    CDilithiumPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << PubKeyBytes(pubkey) << OP_CHECKSIG;

    const CAmount amount = 5000;
    const CTransaction txCredit{BuildCreditingTransaction(scriptPubKey, amount)};
    CMutableTransaction txSpendMut = BuildSpendingTransaction(CScript(), CScriptWitness(), txCredit);

    const uint256 msg = DilithiumSignatureMessage(scriptPubKey, txSpendMut, 0, SIGHASH_ALL, amount);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(msg, sig)); // note: without the hashtype byte
    std::vector<unsigned char> sig_with_hashtype = sig;
    sig_with_hashtype.push_back(static_cast<unsigned char>(SIGHASH_ALL));
    txSpendMut.vin[0].scriptSig = CScript() << sig_with_hashtype;

    const CTransaction txSpend{txSpendMut};

    SignatureCache sigcache(DEFAULT_SIGNATURE_CACHE_BYTES);

    // The entry (computed over the hashtype-stripped signature, and over the same
    // tagged message the checker verifies) is absent initially.
    uint256 entry;
    sigcache.ComputeEntryDilithium(entry, msg, sig, pubkey);
    BOOST_CHECK(!sigcache.Get(entry, /*erase=*/false));

    PrecomputedTransactionData txdata;
    txdata.Init(txSpend, {});
    CachingTransactionSignatureChecker checker(&txSpend, 0, amount, /*store=*/true, sigcache, txdata);
    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK_MESSAGE(
        VerifyScript(txSpend.vin[0].scriptSig, scriptPubKey, nullptr, SCRIPT_VERIFY_NONE, checker, &err),
        "cached Dilithium verify failed: " << ScriptErrorString(err));

    // After a successful verification the entry is cached.
    BOOST_CHECK(sigcache.Get(entry, /*erase=*/false));
}

// Phase 6 (Critical DoS fix): spending a Dilithium P2PKH output is charged the
// post-quantum verification cost, counted from the prevout being spent, so that
// MAX_BLOCK_SIGOPS_COST bounds the number of verifications per block.
BOOST_AUTO_TEST_CASE(dilithium_verify_sigop_cost)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    const CKeyID keyid = key.GetPubKey().GetID();

    // A Dilithium P2PKH prevout: OP_DUP OP_HASH160 <keyid> OP_EQUALVERIFY OP_CHECKSIG
    CScript prevScript = CScript() << OP_DUP << OP_HASH160 << ToByteVector(keyid) << OP_EQUALVERIFY << OP_CHECKSIG;

    CMutableTransaction fund;
    fund.vin.resize(1);
    fund.vout.resize(1);
    fund.vout[0].nValue = 10000;
    fund.vout[0].scriptPubKey = prevScript;
    const CTransaction fundTx{fund};

    CCoinsView dummy;
    CCoinsViewCache coins(&dummy);
    AddCoins(coins, fundTx, /*nHeight=*/1);

    CMutableTransaction spend;
    spend.vin.resize(1);
    spend.vin[0].prevout = COutPoint(fundTx.GetHash(), 0);
    spend.vout.resize(1);
    spend.vout[0].nValue = 9000;
    spend.vout[0].scriptPubKey = CScript() << OP_TRUE;
    const CTransaction spendTx{spend};

    const int64_t cost = GetTransactionSigOpCost(spendTx, coins, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS);
    // The single executed Dilithium verification is charged at least this much.
    BOOST_CHECK(cost >= int64_t{WITNESS_SCALE_FACTOR} * DILITHIUM_VERIFY_SIGOP_COST);
}

BOOST_AUTO_TEST_SUITE_END()

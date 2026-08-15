// Copyright (c) 2026 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * QubitCoin post-quantum spend size, dust and relay-policy tests.
 *
 * The economics of this chain rest on what a Dilithium spend actually costs in
 * weight, in each of the two forms that relay, and on the dust threshold and
 * relay bounds that follow from it. These tests derive those numbers by
 * measuring real transactions rather than restating the constants, so a change
 * to the signature scheme, the script encoding or the segwit discount surfaces
 * here rather than in the fee market.
 *
 *   ./src/test/test_bitcoin --run_test=dilithium_size_tests
 */

#include <addresstype.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <crypto/dilithium.h>
#include <dilithiumkey.h>
#include <dilithiumpubkey.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <serialize.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <uint256.h>
#include <util/transaction_identifier.h>

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

constexpr CAmount SPEND_AMOUNT{100000};

//! Signature blob as it appears on the stack: raw ML-DSA sig + 1 sighash byte.
//! `msg` is the tagged message from DilithiumSignatureMessage(), not a bare sighash.
std::vector<unsigned char> SignWithHashType(const CDilithiumKey& key, const uint256& msg, int hashtype)
{
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(msg, sig));
    sig.push_back(static_cast<unsigned char>(hashtype));
    return sig;
}

//! A real, fully signed bare (non-witness) Dilithium P2PKH spend.
CMutableTransaction SignedBareSpend(const CDilithiumKey& key, CScript& script_pubkey_out)
{
    FillableSigningProvider keystore;
    BOOST_REQUIRE(keystore.AddDilithiumKey(key));
    script_pubkey_out = GetScriptForDestination(DilithiumPKHash(key.GetPubKey()));

    const CTransaction credit{BuildCreditingTransaction(script_pubkey_out, static_cast<int>(SPEND_AMOUNT))};
    CMutableTransaction spend = BuildSpendingTransaction(CScript(), CScriptWitness(), credit);
    SignatureData sigdata;
    BOOST_REQUIRE(SignSignature(keystore, script_pubkey_out, spend, 0, SPEND_AMOUNT, SIGHASH_ALL, sigdata));
    return spend;
}

//! A real, fully signed witness Dilithium spend (segwit v0 keyhash over the
//! ML-DSA key hash), built the way the interpreter satisfies one: an empty
//! scriptSig and a [signature, public key] witness stack.
CMutableTransaction SignedWitnessSpend(const CDilithiumKey& key, CScript& script_pubkey_out)
{
    const CDilithiumPubKey pub = key.GetPubKey();
    const CKeyID keyid = pub.GetID();
    script_pubkey_out = GetScriptForDestination(WitnessV0KeyHash(uint160{keyid}));

    const CTransaction credit{BuildCreditingTransaction(script_pubkey_out, static_cast<int>(SPEND_AMOUNT))};
    CMutableTransaction spend = BuildSpendingTransaction(CScript(), CScriptWitness(), credit);

    // Implied P2PKH scriptCode, exactly as VerifyWitnessProgram builds it.
    const CScript exec_script = CScript()
        << OP_DUP << OP_HASH160 << ToByteVector(keyid) << OP_EQUALVERIFY << OP_CHECKSIG;
    const uint256 msg = DilithiumSignatureMessage(exec_script, spend, 0, SIGHASH_ALL, SPEND_AMOUNT, nullptr);
    spend.vin[0].scriptSig = CScript();
    spend.vin[0].scriptWitness.stack = {SignWithHashType(key, msg, SIGHASH_ALL),
                                        std::vector<unsigned char>(pub.begin(), pub.end())};
    return spend;
}

enum class Shape {
    Bare,       //!< key pushed directly in the scriptSig
    P2sh,       //!< key nested inside a redeemScript push
    Witness,    //!< key on the witness stack, scriptSig empty
    P2wsh,      //!< key nested inside a witnessScript on the witness stack
    KeyOnly,    //!< key on the witness stack with no signature: not a real spend
                //!< shape, but the cheapest way to carry a key past the counter
    NoKey,      //!< no ML-DSA key anywhere
};

//! Dummy-sized transaction of `n_in` inputs of the given shape. Sizes, not
//! signatures, are what the policy rules being tested here look at.
CMutableTransaction MakeShapedTx(Shape shape, unsigned n_in)
{
    const std::vector<unsigned char> sig(DILITHIUM_SIG_ELEMENT_SIZE, 0x01);
    const std::vector<unsigned char> key(DILITHIUM_PUBKEY_ELEMENT_SIZE, 0x02);
    const CScript inner_script = CScript() << key << OP_CHECKSIG;
    const std::vector<unsigned char> inner(inner_script.begin(), inner_script.end());

    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.resize(n_in);
    for (unsigned i = 0; i < n_in; ++i) {
        tx.vin[i].prevout = COutPoint(Txid::FromUint256(uint256::ONE), i);
        tx.vin[i].nSequence = CTxIn::SEQUENCE_FINAL;
        switch (shape) {
        case Shape::Bare: tx.vin[i].scriptSig = CScript() << sig << key; break;
        case Shape::P2sh: tx.vin[i].scriptSig = CScript() << sig << inner; break;
        case Shape::Witness: tx.vin[i].scriptWitness.stack = {sig, key}; break;
        case Shape::P2wsh: tx.vin[i].scriptWitness.stack = {sig, inner}; break;
        case Shape::KeyOnly: tx.vin[i].scriptWitness.stack = {key}; break;
        case Shape::NoKey: tx.vin[i].scriptSig = CScript() << sig; break;
        }
    }
    tx.vout.resize(1);
    tx.vout[0].nValue = 1 * COIN;
    tx.vout[0].scriptPubKey = GetScriptForDestination(
        DilithiumPKHash(GenerateRandomDilithiumKey().GetPubKey()));
    return tx;
}

std::string StandardnessReason(const CMutableTransaction& tx)
{
    std::string reason;
    if (IsStandardTx(CTransaction{tx}, MAX_OP_RETURN_RELAY, /*permit_bare_multisig=*/true,
                     CFeeRate{DUST_RELAY_TX_FEE}, reason)) {
        return "";
    }
    return reason;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(dilithium_size_tests, BasicTestingSetup)

/**
 * The bare-form constants must match a real signed spend exactly. ML-DSA-65
 * signatures and public keys are fixed length, so "worst case" and "typical"
 * are the same number here; any drift means the constants are wrong, not
 * merely conservative.
 */
BOOST_AUTO_TEST_CASE(bare_dilithium_input_size_is_exact)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    CScript spk;
    const CMutableTransaction spend = SignedBareSpend(key, spk);
    const CTxIn& txin = spend.vin[0];

    BOOST_CHECK_EQUAL(txin.scriptSig.size(), DILITHIUM_P2PKH_SCRIPTSIG_SIZE);
    BOOST_CHECK_EQUAL(::GetSerializeSize(txin), DILITHIUM_P2PKH_INPUT_SIZE);
    BOOST_CHECK_EQUAL(::GetSerializeSize(txin) * WITNESS_SCALE_FACTOR, DILITHIUM_P2PKH_INPUT_WEIGHT);
    // No witness, so the virtual size is the byte size. GetTransactionInputWeight()
    // reads one weight unit higher because it always counts the empty witness stack
    // count byte, which a bare input only really pays if some other input in the
    // transaction is a witness spend.
    BOOST_CHECK_EQUAL(::GetSerializeSize(txin), DILITHIUM_P2PKH_INPUT_VSIZE);
    BOOST_CHECK_EQUAL(GetTransactionInputWeight(txin), DILITHIUM_P2PKH_INPUT_WEIGHT + 1);

    // The input dominates: a whole 1-in-1-out spend is the input plus 76 WU of
    // version / counts / output / locktime overhead.
    BOOST_CHECK_EQUAL(GetTransactionWeight(CTransaction{spend}), DILITHIUM_P2PKH_INPUT_WEIGHT + 76);

    ScriptError serr = SCRIPT_ERR_OK;
    const MutableTransactionSignatureChecker checker(&spend, 0, SPEND_AMOUNT, MissingDataBehavior::ASSERT_FAIL);
    BOOST_CHECK_MESSAGE(VerifyScript(txin.scriptSig, spk, nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serr),
                        "bare Dilithium spend must be valid: " << ScriptErrorString(serr));
}

/**
 * Same for the witness form, plus the claim that makes it worth having: moving
 * the signature and key into the witness makes an input ~3.9x lighter, because
 * the two ~5 kB elements are discounted 4:1 instead of counted at full weight.
 */
BOOST_AUTO_TEST_CASE(witness_dilithium_input_size_is_exact)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    CScript spk;
    const CMutableTransaction spend = SignedWitnessSpend(key, spk);
    const CTxIn& txin = spend.vin[0];

    BOOST_CHECK(txin.scriptSig.empty());
    BOOST_CHECK_EQUAL(::GetSerializeSize(txin), DILITHIUM_P2WPKH_INPUT_NONWITNESS_SIZE);
    BOOST_CHECK_EQUAL(::GetSerializeSize(txin.scriptWitness.stack), DILITHIUM_P2WPKH_WITNESS_SIZE);
    BOOST_CHECK_EQUAL(GetTransactionInputWeight(txin), DILITHIUM_P2WPKH_INPUT_WEIGHT);
    BOOST_CHECK_EQUAL(GetVirtualTransactionInputSize(txin), DILITHIUM_P2WPKH_INPUT_VSIZE);

    // Same overhead as the bare case plus the 2 WU segwit marker and flag.
    BOOST_CHECK_EQUAL(GetTransactionWeight(CTransaction{spend}), DILITHIUM_P2WPKH_INPUT_WEIGHT + 78);

    // The witness form is the efficient one, by close to the full 4x discount.
    BOOST_CHECK_GT(DILITHIUM_P2PKH_INPUT_WEIGHT, DILITHIUM_P2WPKH_INPUT_WEIGHT * 3);
    BOOST_CHECK_LT(DILITHIUM_P2PKH_INPUT_WEIGHT, DILITHIUM_P2WPKH_INPUT_WEIGHT * 4);

    ScriptError serr = SCRIPT_ERR_OK;
    const MutableTransactionSignatureChecker checker(&spend, 0, SPEND_AMOUNT, MissingDataBehavior::ASSERT_FAIL);
    BOOST_CHECK_MESSAGE(VerifyScript(txin.scriptSig, spk, &txin.scriptWitness,
                                     STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serr),
                        "witness Dilithium spend must be valid: " << ScriptErrorString(serr));
}

/**
 * Dust is "worth less than it costs to spend", so the threshold has to be built
 * from the measured spend cost of the form the output commits to. Both forms are
 * checked against a real signed input, not against the constants.
 */
BOOST_AUTO_TEST_CASE(dust_thresholds_follow_real_spend_cost)
{
    const CFeeRate rate{DUST_RELAY_TX_FEE};
    CDilithiumKey key = GenerateRandomDilithiumKey();

    CScript bare_spk;
    const CMutableTransaction bare = SignedBareSpend(key, bare_spk);
    CScript witness_spk;
    const CMutableTransaction witness = SignedWitnessSpend(key, witness_spk);

    const CTxOut bare_out{0, bare_spk};
    const CTxOut witness_out{0, witness_spk};
    const CAmount bare_dust = GetDustThreshold(bare_out, rate);
    const CAmount witness_dust = GetDustThreshold(witness_out, rate);

    // Threshold == feerate applied to (output + its real spending input).
    BOOST_CHECK_EQUAL(bare_dust,
                      rate.GetFee(::GetSerializeSize(bare_out) + ::GetSerializeSize(bare.vin[0])));
    BOOST_CHECK_EQUAL(witness_dust,
                      rate.GetFee(::GetSerializeSize(witness_out) + GetVirtualTransactionInputSize(witness.vin[0])));

    // 34 + 5311 = 5345 vB and 31 + 1359 = 1390 vB at 3000 sat/kvB.
    BOOST_CHECK_EQUAL(bare_dust, 16035);
    BOOST_CHECK_EQUAL(witness_dust, 4170);

    // An output at the threshold must be worth at least what spending it costs,
    // which is the whole point and what the inherited ECDSA estimates broke: they
    // would have put these at 546 and 294 sat.
    BOOST_CHECK_GE(bare_dust, rate.GetFee(GetVirtualTransactionInputSize(bare.vin[0])));
    BOOST_CHECK_GE(witness_dust, rate.GetFee(GetVirtualTransactionInputSize(witness.vin[0])));
    BOOST_CHECK_GT(witness_dust, 294);

    // The cheaper form has the lower threshold, and neither is dust-free.
    BOOST_CHECK_LT(witness_dust, bare_dust);
    BOOST_CHECK_GT(witness_dust, 0);

    // Output types whose satisfaction the output does not determine (P2SH here)
    // keep Bitcoin's lower-bound estimate.
    const CTxOut p2sh_out{0, CScript() << OP_HASH160 << std::vector<unsigned char>(20, 0) << OP_EQUAL};
    BOOST_CHECK_EQUAL(GetDustThreshold(p2sh_out, rate), 540);
}

/** Every shape that can carry an ML-DSA key past relay must be counted. */
BOOST_AUTO_TEST_CASE(dilithium_input_counting_covers_every_shape)
{
    for (const auto& [shape, name] : {std::pair{Shape::Bare, "bare"},
                                      std::pair{Shape::P2sh, "P2SH-nested"},
                                      std::pair{Shape::Witness, "witness"},
                                      std::pair{Shape::P2wsh, "P2WSH-nested"},
                                      std::pair{Shape::KeyOnly, "witness key only"}}) {
        BOOST_CHECK_MESSAGE(CountDilithiumSpendInputs(CTransaction{MakeShapedTx(shape, 3)}) == 3,
                            name << " inputs were not all counted");
    }
    BOOST_CHECK_EQUAL(CountDilithiumSpendInputs(CTransaction{MakeShapedTx(Shape::NoKey, 3)}), 0u);
}

/**
 * The relay cap is derived, not chosen: it is exactly the number of
 * verifications MAX_STANDARD_TX_WEIGHT can pay for at the cheapest standard
 * spend form. Both halves of that matter — one lower and consolidations of the
 * efficient form get rejected for no reason, one higher and the backstop stops
 * bounding anything.
 */
BOOST_AUTO_TEST_CASE(dilithium_input_cap_is_derived_from_weight)
{
    // The witness form is the cheapest way to demand a verification.
    BOOST_CHECK_EQUAL(MIN_STANDARD_DILITHIUM_VERIFY_WEIGHT, DILITHIUM_P2WPKH_INPUT_WEIGHT);
    BOOST_CHECK_LE(MIN_STANDARD_DILITHIUM_VERIFY_WEIGHT, DILITHIUM_P2PKH_INPUT_WEIGHT);

    const int64_t cap = MAX_STANDARD_DILITHIUM_INPUTS;
    BOOST_CHECK_LE(cap * MIN_STANDARD_DILITHIUM_VERIFY_WEIGHT, MAX_STANDARD_TX_WEIGHT);
    BOOST_CHECK_GT((cap + 1) * MIN_STANDARD_DILITHIUM_VERIFY_WEIGHT, MAX_STANDARD_TX_WEIGHT);
}

/**
 * For both real spend forms, weight is what binds, and the cap does not get in
 * the way of either. A witness consolidation is allowed all the way up to the
 * cap — the point of replacing the old fixed count of 15, which would have
 * thrown away most of the witness form's weight advantage.
 */
BOOST_AUTO_TEST_CASE(weight_binds_before_the_dilithium_input_cap)
{
    // Witness form: the cap is reachable, and one input past it exceeds the
    // weight limit rather than the cap.
    CMutableTransaction at_cap = MakeShapedTx(Shape::Witness, MAX_STANDARD_DILITHIUM_INPUTS);
    BOOST_CHECK_LE(GetTransactionWeight(CTransaction{at_cap}), MAX_STANDARD_TX_WEIGHT);
    BOOST_CHECK_EQUAL(StandardnessReason(at_cap), "");
    BOOST_CHECK_GT(MAX_STANDARD_DILITHIUM_INPUTS, 15u);

    CMutableTransaction over_cap = MakeShapedTx(Shape::Witness, MAX_STANDARD_DILITHIUM_INPUTS + 1);
    BOOST_CHECK_GT(GetTransactionWeight(CTransaction{over_cap}), MAX_STANDARD_TX_WEIGHT);
    BOOST_CHECK_EQUAL(StandardnessReason(over_cap), "tx-size");

    // Bare form: ~4x heavier, so weight binds far below the cap.
    const unsigned max_bare = MAX_STANDARD_TX_WEIGHT / DILITHIUM_P2PKH_INPUT_WEIGHT;
    BOOST_CHECK_LT(max_bare, MAX_STANDARD_DILITHIUM_INPUTS);
    BOOST_CHECK_EQUAL(StandardnessReason(MakeShapedTx(Shape::Bare, max_bare)), "");
    BOOST_CHECK_EQUAL(StandardnessReason(MakeShapedTx(Shape::Bare, max_bare + 1)), "tx-size");
}

/**
 * What the cap is actually for: a shape that carries an ML-DSA key for less
 * weight than a real witness spend does. Weight alone would let ~188 of these
 * into one standard transaction; the cap holds the line at the derived number.
 */
BOOST_AUTO_TEST_CASE(dilithium_input_cap_backstops_cheaper_shapes)
{
    CMutableTransaction cheap = MakeShapedTx(Shape::KeyOnly, MAX_STANDARD_DILITHIUM_INPUTS + 1);
    // The weight check cannot be what rejects this, or the test proves nothing.
    BOOST_CHECK_LT(GetTransactionWeight(CTransaction{cheap}), MAX_STANDARD_TX_WEIGHT / 2);
    BOOST_CHECK_EQUAL(StandardnessReason(cheap), "too-many-dilithium-inputs");

    BOOST_CHECK_EQUAL(StandardnessReason(MakeShapedTx(Shape::KeyOnly, MAX_STANDARD_DILITHIUM_INPUTS)), "");
}

BOOST_AUTO_TEST_SUITE_END()

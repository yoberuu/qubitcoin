// Copyright (c) 2026 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Dilithium × ECDSA Audit & Mainnet Readiness Suite
 * ==================================================
 *
 * This is an auditing program, not a routine unit test. It exercises the
 * consensus, cryptographic, size/economic, and mining surfaces that decide
 * whether QubitCoin is ready for any serious mainnet consideration.
 *
 * Run (from the build tree after compiling tests):
 *
 *   ./src/test/test_bitcoin --run_test=dilithium_ecdsa_audit_suite --log_level=all
 *
 * Or via make:
 *
 *   make -C src check-bitcoin TESTS=dilithium_ecdsa_audit_suite
 *
 * Console output is the audit report. Each check prints PASS/FAIL with a
 * one-line rationale. The final section is a structured readiness summary.
 *
 * Why this exists:
 *   - Dilithium-only claims are only as strong as the remaining ECDSA/Schnorr
 *     code paths. This suite proves those paths are dead at consensus.
 *   - ML-DSA-65 inputs are ~35× larger than ECDSA P2PKH. Economics must be
 *     measured, not assumed, before anyone talks about mainnet fees or capacity.
 */

#include <addresstype.h>
#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <crypto/dilithium.h>
#include <dilithiumkey.h>
#include <dilithiumpubkey.h>
#include <hash.h>
#include <key.h>
#include <key_io.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/transaction_identifier.h>
#include <validation.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

//! Minimal reporter that accumulates PASS/FAIL and prints a readable report.
class AuditReporter
{
    int m_pass{0};
    int m_fail{0};
    int m_notes{0};
    std::vector<std::string> m_failures;
    std::vector<std::string> m_risks;

public:
    void Section(const std::string& title) const
    {
        std::cout << "\n";
        std::cout << "════════════════════════════════════════════════════════════\n";
        std::cout << "  " << title << "\n";
        std::cout << "════════════════════════════════════════════════════════════\n";
    }

    void Check(bool ok, const std::string& name, const std::string& why)
    {
        if (ok) {
            ++m_pass;
            std::cout << "  [PASS] " << name << "\n";
            std::cout << "         " << why << "\n";
        } else {
            ++m_fail;
            m_failures.push_back(name);
            std::cout << "  [FAIL] " << name << "\n";
            std::cout << "         " << why << "\n";
        }
        BOOST_CHECK_MESSAGE(ok, name + ": " + why);
    }

    void Note(const std::string& text)
    {
        ++m_notes;
        std::cout << "  [NOTE] " << text << "\n";
    }

    void Risk(const std::string& text)
    {
        m_risks.push_back(text);
        std::cout << "  [RISK] " << text << "\n";
    }

    void Metric(const std::string& label, const std::string& value) const
    {
        std::cout << "  • " << label << ": " << value << "\n";
    }

    int PassCount() const { return m_pass; }
    int FailCount() const { return m_fail; }
    const std::vector<std::string>& Failures() const { return m_failures; }
    const std::vector<std::string>& Risks() const { return m_risks; }
};

//! Build a classic P2PKH scriptPubKey from a 20-byte hash (on-chain template).
CScript P2PKH(const uint160& hash)
{
    return CScript() << OP_DUP << OP_HASH160 << ToByteVector(hash) << OP_EQUALVERIFY << OP_CHECKSIG;
}

//! Attempt to verify a spend of `scriptPubKey` with the given scriptSig.
bool TryVerify(const CScript& scriptSig, const CScript& scriptPubKey, const CAmount amount, ScriptError& err)
{
    const CTransaction txCredit{BuildCreditingTransaction(scriptPubKey, amount)};
    CMutableTransaction txSpend = BuildSpendingTransaction(scriptSig, CScriptWitness(), txCredit);
    const MutableTransactionSignatureChecker checker(&txSpend, 0, amount, MissingDataBehavior::ASSERT_FAIL);
    err = SCRIPT_ERR_OK;
    return VerifyScript(scriptSig, scriptPubKey, nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, checker, &err);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(dilithium_ecdsa_audit_suite, RegTestingSetup)

BOOST_AUTO_TEST_CASE(run_full_audit)
{
    AuditReporter audit;

    std::cout << "\n";
    std::cout << "################################################################\n";
    std::cout << "#  QubitCoin Dilithium × ECDSA Audit & Mainnet Readiness Suite #\n";
    std::cout << "#  Algorithm: " << dilithium::ALGORITHM_NAME
              << "  |  Pubkey: " << dilithium::PUBLIC_KEY_SIZE << " B"
              << "  |  Sig max: " << dilithium::SIGNATURE_MAX_SIZE << " B\n";
    std::cout << "################################################################\n";

    BOOST_REQUIRE_MESSAGE(dilithium::IsAvailable(),
                          "liboqs/Dilithium support is not compiled in; audit cannot proceed");

    // ─────────────────────────────────────────────────────────────────────
    // 1. Consensus Enforcement — ECDSA / Schnorr must be dead
    // ─────────────────────────────────────────────────────────────────────
    audit.Section("1. Consensus Enforcement Audit");
    audit.Note("Why: a Dilithium-only claim is worthless if any ECDSA/Schnorr "
               "validation path still returns true under consensus rules.");

    {
        // Direct API: CheckECDSASignature must always return false.
        CMutableTransaction dummy_tx;
        dummy_tx.vin.resize(1);
        dummy_tx.vout.resize(1);
        dummy_tx.vout[0].nValue = 1 * COIN;
        MutableTransactionSignatureChecker checker(&dummy_tx, 0, 1 * COIN, MissingDataBehavior::FAIL);

        CKey ecdsa_key;
        ecdsa_key.MakeNewKey(/*fCompressed=*/true);
        const CPubKey ecdsa_pub = ecdsa_key.GetPubKey();
        std::vector<unsigned char> ecdsa_sig;
        const uint256 sighash = Hash(std::vector<unsigned char>{'a', 'u', 'd', 'i', 't'});
        BOOST_REQUIRE(ecdsa_key.Sign(sighash, ecdsa_sig));
        ecdsa_sig.push_back(SIGHASH_ALL);

        const bool ecdsa_ok = checker.CheckECDSASignature(
            ecdsa_sig, std::vector<unsigned char>(ecdsa_pub.begin(), ecdsa_pub.end()),
            CScript() << OP_TRUE, SigVersion::BASE);
        audit.Check(!ecdsa_ok,
                    "CheckECDSASignature always fails",
                    "Even a cryptographically valid secp256k1 signature must never "
                    "validate; this covers OP_CHECKMULTISIG's funnel as well.");

        // Direct API: CheckSchnorrSignature must always fail (SCRIPT_ERR_SCHNORR_SIG).
        std::vector<unsigned char> xonly(32, 0x11);
        std::vector<unsigned char> schnorr_sig(64, 0x22);
        ScriptExecutionData execdata;
        ScriptError serr = SCRIPT_ERR_OK;
        const bool schnorr_ok = checker.CheckSchnorrSignature(
            schnorr_sig, xonly, SigVersion::TAPSCRIPT, execdata, &serr);
        audit.Check(!schnorr_ok && serr == SCRIPT_ERR_SCHNORR_SIG,
                    "CheckSchnorrSignature always fails",
                    "BIP340 Taproot key-path / tapscript Schnorr verification is "
                    "hard-disabled (returns SCRIPT_ERR_SCHNORR_SIG).");
    }

    {
        // OP_CHECKSIG / OP_CHECKSIGVERIFY must reject every non-1952-byte pubkey.
        // Why: EvalChecksigPreTapscript gates on CDilithiumPubKey::SIZE before
        // calling CheckDilithiumSignature. secp256k1 keys are 33/65 bytes.
        CKey ecdsa_key;
        ecdsa_key.MakeNewKey(/*fCompressed=*/true);
        const CPubKey ecdsa_pub = ecdsa_key.GetPubKey();
        const CScript p2pkh = P2PKH(ecdsa_pub.GetID());

        // Fake scriptSig: push a dummy "sig" and the ECDSA pubkey.
        std::vector<unsigned char> fake_sig(72, 0x30);
        fake_sig.push_back(SIGHASH_ALL);
        const CScript scriptSig = CScript() << fake_sig
                                            << std::vector<unsigned char>(ecdsa_pub.begin(), ecdsa_pub.end());

        ScriptError err = SCRIPT_ERR_OK;
        const bool verified = TryVerify(scriptSig, p2pkh, /*amount=*/0, err);
        audit.Check(!verified && err == SCRIPT_ERR_PUBKEYTYPE,
                    "OP_CHECKSIG rejects ECDSA (33-byte) pubkey",
                    "Consensus returns SCRIPT_ERR_PUBKEYTYPE for any pubkey whose "
                    "length is not exactly 1952 (Dilithium).");

        // Uncompressed 65-byte ECDSA pubkey.
        CKey ecdsa_u;
        ecdsa_u.MakeNewKey(/*fCompressed=*/false);
        const CPubKey ecdsa_pub_u = ecdsa_u.GetPubKey();
        BOOST_REQUIRE_EQUAL(ecdsa_pub_u.size(), 65U);
        const CScript scriptSig65 = CScript() << fake_sig
                                              << std::vector<unsigned char>(ecdsa_pub_u.begin(), ecdsa_pub_u.end());
        err = SCRIPT_ERR_OK;
        const bool verified65 = TryVerify(scriptSig65, P2PKH(ecdsa_pub_u.GetID()), 0, err);
        audit.Check(!verified65 && err == SCRIPT_ERR_PUBKEYTYPE,
                    "OP_CHECKSIG rejects uncompressed ECDSA (65-byte) pubkey",
                    "Uncompressed secp256k1 keys are also rejected by the size gate.");

        // Empty / truncated / wrong-size Dilithium-looking keys.
        for (const size_t bad_len : {0U, 1U, 32U, 520U, 1951U, 1953U, 4096U}) {
            std::vector<unsigned char> bad_pub(bad_len, 0xab);
            const CScript bad_sig = CScript() << fake_sig << bad_pub;
            const CScript bad_spk = P2PKH(Hash160(bad_pub));
            err = SCRIPT_ERR_OK;
            const bool bad_ok = TryVerify(bad_sig, bad_spk, 0, err);
            audit.Check(!bad_ok && err == SCRIPT_ERR_PUBKEYTYPE,
                        "OP_CHECKSIG rejects pubkey length " + std::to_string(bad_len),
                        "Only length 1952 may proceed to Dilithium verification.");
        }
    }

    {
        // OP_CHECKSIGVERIFY with ECDSA material must also fail (same EvalChecksig path).
        CKey ecdsa_key;
        ecdsa_key.MakeNewKey(/*fCompressed=*/true);
        const CPubKey ecdsa_pub = ecdsa_key.GetPubKey();
        const CScript spk = CScript() << OP_DUP << OP_HASH160 << ToByteVector(ecdsa_pub.GetID())
                                      << OP_EQUALVERIFY << OP_CHECKSIGVERIFY << OP_TRUE;
        std::vector<unsigned char> fake_sig(72, 0x30);
        fake_sig.push_back(SIGHASH_ALL);
        const CScript scriptSig = CScript() << fake_sig
                                            << std::vector<unsigned char>(ecdsa_pub.begin(), ecdsa_pub.end());
        ScriptError err = SCRIPT_ERR_OK;
        const bool ok = TryVerify(scriptSig, spk, 0, err);
        audit.Check(!ok,
                    "OP_CHECKSIGVERIFY rejects ECDSA pubkey",
                    "CHECKSIGVERIFY shares EvalChecksigPreTapscript; ECDSA cannot pass.");
    }

    // ─────────────────────────────────────────────────────────────────────
    // 2. Dilithium Correctness
    // ─────────────────────────────────────────────────────────────────────
    audit.Section("2. Dilithium Correctness Audit");
    audit.Note("Why: consensus rejection of ECDSA is useless if Dilithium itself "
               "is broken, non-deterministic, or size-inconsistent with FIPS 204.");

    CDilithiumKey random_key = GenerateRandomDilithiumKey();
    audit.Check(random_key.IsValid(),
                "Random Dilithium key generation",
                "CSPRNG-backed MakeNewKey must produce a valid ML-DSA-65 keypair.");

    const CDilithiumPubKey random_pub = random_key.GetPubKey();
    audit.Check(random_pub.IsValid() && random_pub.size() == CDilithiumPubKey::SIZE,
                "Public key size is exactly 1952 bytes",
                "Consensus pubkey gate and address Hash160 both assume SIZE==1952.");

    // Deterministic seed keygen.
    const uint256 seed = uint256S("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CDilithiumKey seed_key_a, seed_key_b;
    seed_key_a.MakeNewKeyFromSeed(seed);
    seed_key_b.MakeNewKeyFromSeed(seed);
    audit.Check(seed_key_a.IsValid() && seed_key_b.IsValid() &&
                    seed_key_a.GetPubKey() == seed_key_b.GetPubKey(),
                "Deterministic seed keygen is stable",
                "Same 32-byte seed must always yield the same keypair (wallet recovery).");

    uint256 seed2 = seed;
    *seed2.begin() ^= 0x01;
    CDilithiumKey seed_key_c;
    seed_key_c.MakeNewKeyFromSeed(seed2);
    audit.Check(seed_key_c.IsValid() && seed_key_c.GetPubKey() != seed_key_a.GetPubKey(),
                "Different seeds yield different keys",
                "HD child isolation depends on seed uniqueness.");

    // HD derivation consistency.
    const uint256 master = seed;
    const uint256 child0 = DeriveDilithiumChildSeed(master, 0);
    const uint256 child1 = DeriveDilithiumChildSeed(master, 1);
    const uint256 child0_again = DeriveDilithiumChildSeed(master, 0);
    audit.Check(child0 == child0_again && child0 != child1,
                "Dilithium HD child derivation is consistent",
                "HMAC-SHA256(master, \"QBTC-ML-DSA-65-HD\"||LE32(i)) must be stable "
                "and index-dependent.");

    CDilithiumKey hd0, hd0b;
    hd0.MakeNewKeyFromSeed(child0);
    hd0b.MakeNewKeyFromSeed(child0_again);
    audit.Check(hd0.GetPubKey() == hd0b.GetPubKey(),
                "HD child keys round-trip through derivation",
                "Wallet re-derivation from backup seed must reproduce addresses.");

    // Sign / verify.
    const uint256 msg = Hash(std::vector<unsigned char>{'Q', 'B', 'T', 'C'});
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(random_key.Sign(msg, sig));
    audit.Check(!sig.empty() && sig.size() <= dilithium::SIGNATURE_MAX_SIZE,
                "Signature size within ML-DSA-65 bound",
                "Observed " + std::to_string(sig.size()) + " B; max is " +
                    std::to_string(dilithium::SIGNATURE_MAX_SIZE) + " B.");

    audit.Check(random_pub.Verify(msg, sig),
                "Sign → Verify success",
                "A freshly signed 32-byte sighash must verify under the matching pubkey.");

    // Negative verifications.
    uint256 msg_bad = msg;
    *msg_bad.begin() ^= 0xff;
    audit.Check(!random_pub.Verify(msg_bad, sig),
                "Verify fails on modified message",
                "Integrity: flipping one message byte must invalidate the signature.");

    std::vector<unsigned char> sig_bad = sig;
    if (!sig_bad.empty()) sig_bad[sig_bad.size() / 2] ^= 0x01;
    audit.Check(!random_pub.Verify(msg, sig_bad),
                "Verify fails on modified signature",
                "Integrity: flipping one signature byte must invalidate verification.");

    CDilithiumKey other = GenerateRandomDilithiumKey();
    audit.Check(!other.GetPubKey().Verify(msg, sig),
                "Verify fails with wrong public key",
                "A signature must not verify under an unrelated Dilithium pubkey.");

    std::vector<unsigned char> sig_trunc(sig.begin(), sig.begin() + std::min<size_t>(sig.size(), 16));
    audit.Check(!random_pub.Verify(msg, sig_trunc),
                "Verify fails on truncated signature",
                "Partial signatures must never verify.");

    // Serialization round-trip for pubkey.
    {
        DataStream ss;
        ss << random_pub;
        CDilithiumPubKey pub_rt;
        ss >> pub_rt;
        audit.Check(pub_rt == random_pub && pub_rt.IsValid(),
                    "CDilithiumPubKey serialization round-trip",
                    "Wallet DB / network encoding must not corrupt the 1952-byte key.");
    }

    // End-to-end script spend (the real consensus path).
    {
        FillableSigningProvider keystore;
        BOOST_REQUIRE(keystore.AddDilithiumKey(random_key));
        const CScript spk = GetScriptForDestination(DilithiumPKHash(random_pub));
        BOOST_REQUIRE_EQUAL(spk.size(), 25U);

        // BuildCreditingTransaction takes int; keep value inside int range.
        const CAmount amount = 1 * COIN;
        const CTransaction txCredit{BuildCreditingTransaction(spk, static_cast<int>(amount))};
        CMutableTransaction txSpend = BuildSpendingTransaction(CScript(), CScriptWitness(), txCredit);
        SignatureData sigdata;
        const bool signed_ok = SignSignature(keystore, spk, txSpend, 0, amount, SIGHASH_ALL, sigdata);
        ScriptError serr = SCRIPT_ERR_OK;
        const MutableTransactionSignatureChecker checker(&txSpend, 0, amount, MissingDataBehavior::ASSERT_FAIL);
        const bool verified = signed_ok &&
                              VerifyScript(txSpend.vin[0].scriptSig, spk, nullptr,
                                           STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serr);
        audit.Check(verified,
                    "End-to-end Dilithium P2PKH SignSignature + VerifyScript",
                    "This is the wallet→mempool→consensus spend path. Failure here "
                    "blocks every on-chain payment.");
        if (!verified) {
            audit.Note(std::string("VerifyScript error: ") + ScriptErrorString(serr));
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // 3. Size & Economic Calculations
    // ─────────────────────────────────────────────────────────────────────
    audit.Section("3. Size & Economic Calculations");
    audit.Note("Why: Dilithium inputs dominate transaction weight. Mainnet fee "
               "markets, dust policy, and block capacity all hinge on these numbers.");

    // Measure a real signed Dilithium P2PKH input.
    size_t measured_scriptsig = 0;
    size_t measured_input = 0;
    size_t measured_tx_vsize = 0;
    size_t measured_tx_weight = 0;
    size_t measured_sig = 0;
    {
        FillableSigningProvider keystore;
        BOOST_REQUIRE(keystore.AddDilithiumKey(random_key));
        const CScript spk = GetScriptForDestination(DilithiumPKHash(random_pub));
        const CAmount amount = 1 * COIN;
        const CTransaction txCredit{BuildCreditingTransaction(spk, static_cast<int>(amount))};
        CMutableTransaction txSpend = BuildSpendingTransaction(CScript(), CScriptWitness(), txCredit);
        // Pay to a second Dilithium address so the tx is a realistic 1-in-1-out.
        CDilithiumKey dest_key = GenerateRandomDilithiumKey();
        txSpend.vout[0].scriptPubKey = GetScriptForDestination(DilithiumPKHash(dest_key.GetPubKey()));
        txSpend.vout[0].nValue = amount - 10000; // leave room for a fee

        SignatureData sigdata;
        BOOST_REQUIRE(SignSignature(keystore, spk, txSpend, 0, amount, SIGHASH_ALL, sigdata));
        measured_scriptsig = txSpend.vin[0].scriptSig.size();
        measured_input = ::GetSerializeSize(TX_NO_WITNESS(txSpend.vin[0]));
        const CTransaction signed_tx{txSpend};
        measured_tx_weight = GetTransactionWeight(signed_tx);
        measured_tx_vsize = (measured_tx_weight + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;

        // Extract raw sig length (push prefix + sighash byte).
        measured_sig = 0;
        if (!txSpend.vin[0].scriptSig.empty()) {
            // scriptSig = <sig+sighash> <pubkey>; first push is the signature blob.
            CScript::const_iterator pc = txSpend.vin[0].scriptSig.begin();
            opcodetype opcode;
            std::vector<unsigned char> vch;
            if (txSpend.vin[0].scriptSig.GetOp(pc, opcode, vch) && !vch.empty()) {
                measured_sig = vch.size() - 1; // strip sighash type byte
            }
        }
    }

    constexpr size_t LEGACY_ECDSA_P2PKH_INPUT = 148;      // Bitcoin textbook figure
    constexpr size_t LEGACY_ECDSA_1IN1OUT_VSIZE = 192;    // rough 1-in-1-out reference

    // Policy's canonical Dilithium spend sizes (used for dust and estimation).
    constexpr size_t POLICY_DILITHIUM_SCRIPTSIG = DILITHIUM_P2PKH_SCRIPTSIG_SIZE;
    constexpr size_t POLICY_DILITHIUM_INPUT = DILITHIUM_P2PKH_INPUT_SIZE; // 5311

    audit.Metric("Dilithium pubkey size", std::to_string(CDilithiumPubKey::SIZE) + " B");
    audit.Metric("Measured Dilithium signature size", std::to_string(measured_sig) + " B");
    audit.Metric("ML-DSA-65 signature max", std::to_string(dilithium::SIGNATURE_MAX_SIZE) + " B");
    audit.Metric("Measured Dilithium P2PKH scriptSig", std::to_string(measured_scriptsig) + " B");
    audit.Metric("Policy worst-case Dilithium scriptSig", std::to_string(POLICY_DILITHIUM_SCRIPTSIG) + " B");
    audit.Metric("Measured Dilithium P2PKH input (serialized)", std::to_string(measured_input) + " B");
    audit.Metric("Policy worst-case Dilithium P2PKH input", std::to_string(POLICY_DILITHIUM_INPUT) + " B");
    audit.Metric("Legacy ECDSA P2PKH input (Bitcoin ref.)", std::to_string(LEGACY_ECDSA_P2PKH_INPUT) + " B");

    const double input_ratio = static_cast<double>(measured_input) / LEGACY_ECDSA_P2PKH_INPUT;
    {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(1) << input_ratio << "×";
        audit.Metric("Dilithium / ECDSA input size ratio", oss.str());
    }

    // Weight / vsize: legacy inputs have no witness, so weight = 4 * bytes.
    const size_t dil_input_weight = measured_input * WITNESS_SCALE_FACTOR;
    const size_t ecdsa_input_weight = LEGACY_ECDSA_P2PKH_INPUT * WITNESS_SCALE_FACTOR;
    audit.Metric("Dilithium input weight (no witness discount)",
                 std::to_string(dil_input_weight) + " WU");
    audit.Metric("ECDSA input weight (reference)",
                 std::to_string(ecdsa_input_weight) + " WU");
    audit.Metric("Measured 1-in-1-out Dilithium tx weight",
                 std::to_string(measured_tx_weight) + " WU");
    audit.Metric("Measured 1-in-1-out Dilithium tx vsize",
                 std::to_string(measured_tx_vsize) + " vB");

    // Max Dilithium inputs per block under weight limit.
    // Conservative: use policy worst-case input weight; leave headroom for a
    // coinbase (~1 kWU) and minimal outputs.
    const int64_t coinbase_headroom = 4000;
    const int64_t budget = MAX_BLOCK_WEIGHT - coinbase_headroom;
    const int64_t max_inputs_measured = budget / static_cast<int64_t>(dil_input_weight);
    const int64_t max_inputs_policy = budget / static_cast<int64_t>(POLICY_DILITHIUM_INPUT * WITNESS_SCALE_FACTOR);
    audit.Metric("MAX_BLOCK_WEIGHT", std::to_string(MAX_BLOCK_WEIGHT) + " WU");
    audit.Metric("Theoretical max Dilithium inputs / block (measured)",
                 std::to_string(max_inputs_measured));
    audit.Metric("Theoretical max Dilithium inputs / block (policy worst-case)",
                 std::to_string(max_inputs_policy));
    audit.Metric("DILITHIUM_VERIFY_SIGOP_COST (per verify)",
                 std::to_string(DILITHIUM_VERIFY_SIGOP_COST));
    audit.Metric("MAX_STANDARD_DILITHIUM_INPUTS (policy)",
                 std::to_string(MAX_STANDARD_DILITHIUM_INPUTS));
    audit.Metric("MAX_BLOCK_SIGOPS_COST", std::to_string(MAX_BLOCK_SIGOPS_COST));

    // The witness spend form moves the same signature and key into the witness,
    // where they are discounted 4:1.
    audit.Metric("Witness Dilithium input weight", std::to_string(DILITHIUM_P2WPKH_INPUT_WEIGHT) + " WU");
    audit.Metric("Witness Dilithium input vsize", std::to_string(DILITHIUM_P2WPKH_INPUT_VSIZE) + " vB");
    {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2)
            << static_cast<double>(DILITHIUM_P2PKH_INPUT_WEIGHT) / DILITHIUM_P2WPKH_INPUT_WEIGHT << "×";
        audit.Metric("Bare / witness Dilithium input weight ratio", oss.str());
    }
    audit.Metric("Max witness Dilithium inputs / block",
                 std::to_string((MAX_BLOCK_WEIGHT - coinbase_headroom) / DILITHIUM_P2WPKH_INPUT_WEIGHT));
    audit.Check(DILITHIUM_P2WPKH_INPUT_WEIGHT * 3 < DILITHIUM_P2PKH_INPUT_WEIGHT,
                "Witness Dilithium spends are the efficient form by ~4x weight",
                "Fee and dust math must reward the witness form, not price both "
                "shapes as if they were bare P2PKH.");
    {
        // Sigops also constrain: each Dilithium verify costs
        // DILITHIUM_VERIFY_SIGOP_COST * WITNESS_SCALE_FACTOR in GetTransactionSigOpCost units.
        const int64_t cost_per = DILITHIUM_VERIFY_SIGOP_COST * WITNESS_SCALE_FACTOR;
        const int64_t max_by_sigops = MAX_BLOCK_SIGOPS_COST / cost_per;
        const int64_t max_std_by_sigops = MAX_STANDARD_TX_SIGOPS_COST / cost_per;
        audit.Metric("Max Dilithium verifies / block by sigops budget",
                     std::to_string(max_by_sigops));
        audit.Metric("Max Dilithium verifies / standard tx by sigops",
                     std::to_string(max_std_by_sigops));
        audit.Check(max_by_sigops >= max_inputs_policy,
                    "Sigops budget does not undercut weight capacity",
                    "If sigops bind first, fee markets and DoS surface change; "
                    "operators must know which constraint wins.");
        audit.Check(MAX_STANDARD_DILITHIUM_INPUTS * MIN_STANDARD_DILITHIUM_VERIFY_WEIGHT
                        <= MAX_STANDARD_TX_WEIGHT &&
                    (MAX_STANDARD_DILITHIUM_INPUTS + 1) * MIN_STANDARD_DILITHIUM_VERIFY_WEIGHT
                        > MAX_STANDARD_TX_WEIGHT,
                    "Policy Dilithium input limit equals what MAX_STANDARD_TX_WEIGHT pays for",
                    "Derived rather than hand-tuned, so it never penalises the cheaper "
                    "witness form and never stops bounding the cheapest one.");
        audit.Check(static_cast<int64_t>(MAX_STANDARD_DILITHIUM_INPUTS) < max_inputs_policy,
                    "Policy Dilithium input limit binds before full-block weight packing",
                    "Relay should reject pathological consolidations before they approach "
                    "the ~188-input block weight ceiling.");
    }

    // Verify-cost microbenchmark (same path as consensus: CDilithiumPubKey::Verify).
    {
        constexpr int iters = 200;
        const uint256 msg = Hash(std::vector<unsigned char>{9, 8, 7, 6, 5, 4, 3, 2});
        std::vector<unsigned char> dil_sig;
        BOOST_REQUIRE(random_key.Sign(msg, dil_sig));

        const auto t0 = std::chrono::steady_clock::now();
        for (int i = 0; i < iters; ++i) {
            BOOST_REQUIRE(random_pub.Verify(msg, dil_sig));
        }
        const auto t1 = std::chrono::steady_clock::now();
        const double dil_us =
            std::chrono::duration<double, std::micro>(t1 - t0).count() / iters;

        // ECDSA reference (libsecp256k1 via CKey) — consensus-disabled on spend,
        // but still a valid CPU baseline for DILITHIUM_VERIFY_SIGOP_COST.
        CKey ecdsa_key = GenerateRandomKey();
        const CPubKey ecdsa_pub = ecdsa_key.GetPubKey();
        std::vector<unsigned char> ecdsa_sig;
        BOOST_REQUIRE(ecdsa_key.Sign(msg, ecdsa_sig));
        const auto t2 = std::chrono::steady_clock::now();
        for (int i = 0; i < iters * 5; ++i) {
            BOOST_REQUIRE(ecdsa_pub.Verify(msg, ecdsa_sig));
        }
        const auto t3 = std::chrono::steady_clock::now();
        const double ecdsa_us =
            std::chrono::duration<double, std::micro>(t3 - t2).count() / (iters * 5);
        const double ratio = dil_us / std::max(ecdsa_us, 1e-9);

        {
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(1) << dil_us << " µs";
            audit.Metric("ML-DSA-65 Verify (CDilithiumPubKey)", oss.str());
        }
        {
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(1) << ecdsa_us << " µs";
            audit.Metric("ECDSA Verify (CPubKey, reference)", oss.str());
        }
        {
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(2) << ratio << "×";
            audit.Metric("Dilithium/ECDSA verify latency ratio", oss.str());
        }
        {
            std::ostringstream why;
            why << std::fixed << std::setprecision(2)
                << "Sigop cost should not under-price real CPU relative to ECDSA; "
                << "current cost=" << DILITHIUM_VERIFY_SIGOP_COST
                << " covers measured ~" << ratio << "× with margin.";
            audit.Check(ratio < static_cast<double>(DILITHIUM_VERIFY_SIGOP_COST),
                        "DILITHIUM_VERIFY_SIGOP_COST >= measured Dilithium/ECDSA verify ratio",
                        why.str());
        }
        // Sanity: verification should be well under a millisecond on CI/dev hosts.
        audit.Check(dil_us < 1000.0,
                    "Dilithium verify completes in under 1 ms on this host",
                    "Multi-millisecond verifies would make full-block validation painful.");
    }

    // Policy: Dilithium input cap rejects oversized consolidations as non-standard.
    // Uses the cheapest key-carrying shape (a bare key on the witness stack) so the
    // count bound is what is being exercised rather than the weight limit.
    {
        auto make_tx = [&](unsigned n_in) {
            CMutableTransaction tx;
            tx.version = 2;
            tx.vin.resize(n_in);
            for (auto& in : tx.vin) {
                in.prevout.hash = Txid::FromUint256(uint256::ONE);
                in.scriptWitness.stack = {std::vector<unsigned char>(dilithium::PUBLIC_KEY_SIZE, 0x02)};
            }
            tx.vout.resize(1);
            tx.vout[0].nValue = 1 * COIN;
            tx.vout[0].scriptPubKey = GetScriptForDestination(DilithiumPKHash(random_pub));
            return tx;
        };
        std::string reason;
        const bool ok_at_limit = IsStandardTx(CTransaction{make_tx(MAX_STANDARD_DILITHIUM_INPUTS)},
                                              MAX_OP_RETURN_RELAY, /*permit_bare_multisig=*/true,
                                              CFeeRate{DUST_RELAY_TX_FEE}, reason);
        reason.clear();
        const bool bad_over = !IsStandardTx(CTransaction{make_tx(MAX_STANDARD_DILITHIUM_INPUTS + 1)},
                                            MAX_OP_RETURN_RELAY, /*permit_bare_multisig=*/true,
                                            CFeeRate{DUST_RELAY_TX_FEE}, reason);
        audit.Check(ok_at_limit,
                    "Tx with MAX_STANDARD_DILITHIUM_INPUTS Dilithium inputs is standard",
                    "Ordinary consolidations up to the policy cap must still relay.");
        audit.Check(bad_over && reason == "too-many-dilithium-inputs",
                    "Tx above MAX_STANDARD_DILITHIUM_INPUTS is non-standard",
                    "Relay peers must refuse oversized Dilithium consolidations "
                    "(reason=too-many-dilithium-inputs).");
    }

    // Dust threshold for Dilithium P2PKH.
    {
        const CScript dil_spk = GetScriptForDestination(DilithiumPKHash(random_pub));
        const CTxOut dil_out{0, dil_spk};
        const CFeeRate dust_rate{DUST_RELAY_TX_FEE};
        const CAmount dil_dust = GetDustThreshold(dil_out, dust_rate);

        // Legacy ECDSA estimate for comparison (34-byte output + 148-byte input).
        const size_t legacy_nsize = ::GetSerializeSize(CTxOut{0, dil_spk}) + LEGACY_ECDSA_P2PKH_INPUT;
        const CAmount legacy_dust = dust_rate.GetFee(legacy_nsize);

        // Witness form: same key, spent through a segwit v0 keyhash output.
        const CScript wit_spk = GetScriptForDestination(WitnessV0KeyHash(uint160{random_pub.GetID()}));
        const CAmount wit_dust = GetDustThreshold(CTxOut{0, wit_spk}, dust_rate);
        const CAmount wit_legacy_dust = dust_rate.GetFee(::GetSerializeSize(CTxOut{0, wit_spk}) + 67);

        audit.Metric("Dust relay fee", std::to_string(DUST_RELAY_TX_FEE) + " sat/kvB");
        audit.Metric("Dilithium P2PKH (bare) dust threshold", std::to_string(dil_dust) + " sat");
        audit.Metric("Dilithium P2WPKH (witness) dust threshold", std::to_string(wit_dust) + " sat");
        audit.Metric("ECDSA-style dust (if mis-estimated at 148 B input)",
                     std::to_string(legacy_dust) + " sat");
        audit.Metric("ECDSA-style witness dust (if mis-estimated at 67 B input)",
                     std::to_string(wit_legacy_dust) + " sat");
        audit.Check(dil_dust > legacy_dust * 10,
                    "Bare dust threshold uses Dilithium input size (not ECDSA 148 B)",
                    "Without this, wallets would create uneconomical outputs that "
                    "cost more in fees to spend than they are worth.");
        audit.Check(wit_dust > wit_legacy_dust * 10,
                    "Witness dust threshold uses Dilithium witness size (not ECDSA 67 B)",
                    "A witness Dilithium output still costs ~1359 vB to spend; the "
                    "inherited estimate priced it at 67.");
        audit.Check(wit_dust < dil_dust,
                    "Witness dust threshold is below the bare one",
                    "The cheaper spend form should carry the lower threshold, or the "
                    "dust rule stops tracking real spend cost.");
        audit.Check(dil_dust > 0,
                    "Dilithium dust threshold is positive",
                    "Zero dust would allow free relay of dust spam.");
    }

    // Fee impact at a reference feerate.
    {
        const CFeeRate ref{1000}; // 1 sat/vB — common Bitcoin reference
        const CAmount dil_fee = ref.GetFee(measured_tx_vsize);
        const CAmount ecdsa_fee = ref.GetFee(LEGACY_ECDSA_1IN1OUT_VSIZE);
        audit.Metric("Fee for 1-in-1-out Dilithium @ 1 sat/vB",
                     std::to_string(dil_fee) + " sat");
        audit.Metric("Fee for 1-in-1-out ECDSA @ 1 sat/vB (ref.)",
                     std::to_string(ecdsa_fee) + " sat");
        {
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(1)
                << (static_cast<double>(dil_fee) / std::max<CAmount>(ecdsa_fee, 1)) << "×";
            audit.Metric("Fee multiplier vs Bitcoin ECDSA P2PKH", oss.str());
        }
        audit.Check(measured_tx_vsize < MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR,
                    "Typical Dilithium 1-in-1-out is under MAX_STANDARD_TX_WEIGHT",
                    "If a single-input payment exceeded the standardness limit, "
                    "the chain would be unusable for ordinary transfers.");
    }

    audit.Note("Signature cache: Dilithium scriptSigs are large (~5 KB/entry). "
               "Caching verified (sighash, pubkey, sig) tuples remains important "
               "under block/relay load; size -maxsigcachesize for Dilithium entries.");
    audit.Note("Mitigations in place: DILITHIUM_VERIFY_SIGOP_COST=" +
               std::to_string(DILITHIUM_VERIFY_SIGOP_COST) +
               " (measured verify ~1–3× ECDSA with platform margin) and "
               "MAX_STANDARD_DILITHIUM_INPUTS=" +
               std::to_string(MAX_STANDARD_DILITHIUM_INPUTS) +
               " (policy-only relay cap). Weight remains the binding block limit.");
    audit.Risk("Cold-sigcache full blocks still cost O(inputs) lattice verifies; "
               "publish hardware validation numbers before mainnet.");
    audit.Risk("Block capacity collapses to a few hundred Dilithium inputs "
               "(vs ~20k ECDSA). Throughput and fee-market dynamics will not "
               "resemble Bitcoin's.");

    // ─────────────────────────────────────────────────────────────────────
    // 4. Mining & Coinbase Sanity
    // ─────────────────────────────────────────────────────────────────────
    audit.Section("4. Mining & Coinbase Sanity");
    audit.Note("Why: if Dilithium coinbases cannot be mined or spent after "
               "maturity, the chain cannot distribute coins.");

    SetMockTime(Params().GenesisBlock().nTime + 600);

    CDilithiumKey miner_key = GenerateRandomDilithiumKey();
    const CTxDestination miner_dest = DilithiumPKHash(miner_key.GetPubKey());
    const std::string miner_addr = EncodeDestination(miner_dest);
    audit.Check(std::holds_alternative<DilithiumPKHash>(DecodeDestination(miner_addr)),
                "Miner address encodes/decodes as DilithiumPKHash",
                "generatetoaddress must accept the same address type wallets produce.");

    const CScript coinbase_spk = GetScriptForDestination(miner_dest);
    const int height0 = WITH_LOCK(m_node.chainman->GetMutex(), return m_node.chainman->ActiveHeight());

    // Mine maturity+1 blocks to the Dilithium address (coinbase matures at 100).
    std::vector<COutPoint> coinbases;
    for (int i = 0; i < COINBASE_MATURITY + 1; ++i) {
        SetMockTime(GetTime() + 1);
        const COutPoint out = MineBlock(m_node, coinbase_spk);
        if (out.hash.IsNull()) break;
        coinbases.push_back(out);
    }
    const int height1 = WITH_LOCK(m_node.chainman->GetMutex(), return m_node.chainman->ActiveHeight());
    audit.Check(height1 == height0 + COINBASE_MATURITY + 1 && coinbases.size() == static_cast<size_t>(COINBASE_MATURITY + 1),
                "Mine COINBASE_MATURITY+1 blocks to Dilithium address",
                "generatetoaddress / MineBlock path must advance the chain and "
                "pay the Dilithium P2PKH scriptPubKey.");

    // Confirm tip coinbase scriptPubKey.
    {
        CBlockIndex* tip = WITH_LOCK(m_node.chainman->GetMutex(), return m_node.chainman->ActiveChain().Tip());
        BOOST_REQUIRE(tip);
        CBlock block;
        BOOST_REQUIRE(m_node.chainman->m_blockman.ReadBlockFromDisk(block, *tip));
        audit.Check(!block.vtx.empty() && block.vtx[0]->IsCoinBase() &&
                        block.vtx[0]->vout[0].scriptPubKey == coinbase_spk,
                    "Coinbase output scriptPubKey matches Dilithium destination",
                    "Miner reward must be locked to the Dilithium Hash160, not an ECDSA path.");
    }

    // Spend the first (now mature) coinbase.
    {
        FillableSigningProvider keystore;
        BOOST_REQUIRE(keystore.AddDilithiumKey(miner_key));
        BOOST_REQUIRE(!coinbases.empty());

        CBlockIndex* genesis_plus_1 = WITH_LOCK(m_node.chainman->GetMutex(),
                                                return m_node.chainman->ActiveChain()[height0 + 1]);
        BOOST_REQUIRE(genesis_plus_1);
        CBlock mature_block;
        BOOST_REQUIRE(m_node.chainman->m_blockman.ReadBlockFromDisk(mature_block, *genesis_plus_1));
        BOOST_REQUIRE(mature_block.vtx[0]->IsCoinBase());

        const CAmount coinbase_value = mature_block.vtx[0]->vout[0].nValue;
        CMutableTransaction spend;
        spend.vin.resize(1);
        spend.vin[0].prevout = COutPoint(mature_block.vtx[0]->GetHash(), 0);
        spend.vout.resize(1);
        CDilithiumKey recv = GenerateRandomDilithiumKey();
        spend.vout[0].scriptPubKey = GetScriptForDestination(DilithiumPKHash(recv.GetPubKey()));
        spend.vout[0].nValue = coinbase_value - 50000; // fee

        SignatureData sigdata;
        const bool signed_ok = SignSignature(keystore, coinbase_spk, spend, 0, coinbase_value, SIGHASH_ALL, sigdata);
        ScriptError serr = SCRIPT_ERR_OK;
        const MutableTransactionSignatureChecker checker(&spend, 0, coinbase_value, MissingDataBehavior::ASSERT_FAIL);
        const bool verified = signed_ok &&
                              VerifyScript(spend.vin[0].scriptSig, coinbase_spk, nullptr,
                                           STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serr);
        audit.Check(verified,
                    "Mature Dilithium coinbase is spendable",
                    "After " + std::to_string(COINBASE_MATURITY) +
                        " confirmations the miner must be able to SignSignature + "
                        "VerifyScript the coinbase P2PKH output.");
    }

    SetMockTime(0);

    // ─────────────────────────────────────────────────────────────────────
    // 5. Mainnet Readiness Report
    // ─────────────────────────────────────────────────────────────────────
    audit.Section("5. Mainnet Readiness Report");

    std::cout << "\n  WHAT IS SOLID\n";
    std::cout << "  ─────────────\n";
    std::cout << "  • ECDSA CheckECDSASignature is hard-disabled (always false).\n";
    std::cout << "  • Schnorr CheckSchnorrSignature is hard-disabled (SCRIPT_ERR_SCHNORR_SIG).\n";
    std::cout << "  • OP_CHECKSIG/VERIFY reject every non-1952-byte pubkey at consensus.\n";
    std::cout << "  • Dilithium ML-DSA-65 keygen / sign / verify / HD derivation work.\n";
    std::cout << "  • Dilithium P2PKH spends verify end-to-end through SignSignature.\n";
    std::cout << "  • Dust policy accounts for ~5.3 KB Dilithium scriptSigs.\n";
    std::cout << "  • DILITHIUM_VERIFY_SIGOP_COST tuned from measured verify latency.\n";
    std::cout << "  • MAX_STANDARD_DILITHIUM_INPUTS=" << MAX_STANDARD_DILITHIUM_INPUTS
              << " soft policy limit (too-many-dilithium-inputs).\n";
    std::cout << "  • Mining to Dilithium addresses and spending mature coinbases works.\n";

    std::cout << "\n  WHAT STILL CARRIES RISK\n";
    std::cout << "  ───────────────────────\n";
    for (const auto& r : audit.Risks()) {
        std::cout << "  • " << r << "\n";
    }
    std::cout << "  • MAX_SCRIPT_ELEMENT_SIZE=4096 is a consensus constant; any future\n";
    std::cout << "    change is a hard fork. Treat it as frozen for mainnet.\n";
    std::cout << "  • Genesis / network params (powLimit, ports, seeds, assumevalid) must\n";
    std::cout << "    be finalized and reviewed before any mainnet tag.\n";
    std::cout << "  • Descriptor wallets cannot hold spendable Dilithium keys today;\n";
    std::cout << "    legacy SPKM + Dilithium HD is the only production wallet path.\n";
    std::cout << "  • No long-running adversarial fuzz of Dilithium script paths is\n";
    std::cout << "    asserted here — add continuous fuzz before mainnet.\n";
    std::cout << "  • Peer diversity, DNS seeds, and checkpoint/assumeutxo strategy are\n";
    std::cout << "    operational — outside this crypto audit but launch-blocking.\n";

    std::cout << "\n  CONCRETE RECOMMENDATIONS\n";
    std::cout << "  ────────────────────────\n";
    std::cout << "  1. Freeze consensus constants (pubkey size gate, MAX_SCRIPT_ELEMENT_SIZE,\n";
    std::cout << "     DILITHIUM_VERIFY_SIGOP_COST=" << DILITHIUM_VERIFY_SIGOP_COST
              << ", dust Dilithium input size) behind review.\n";
    std::cout << "  2. Keep MAX_STANDARD_DILITHIUM_INPUTS as policy-only; re-tune after\n";
    std::cout << "     measuring mempool DoS under adversarial consolidations.\n";
    std::cout << "  3. Benchmark full-block Dilithium validation on target hardware; publish\n";
    std::cout << "     numbers (also: ./src/bench/bench_bitcoin -filter='Dilithium.*|ECDSA.*').\n";
    std::cout << "  4. Run extended functional tests: multi-input Dilithium spends, reorgs,\n";
    std::cout << "     wallet encrypt/backup/restore, fee estimation with large vsize.\n";
    std::cout << "  5. Decide and document mainnet powLimit / retarget / subsidy before\n";
    std::cout << "     genesis mining; Testnet4 soft min-diff is not a mainnet template.\n";
    std::cout << "  6. Do not advertise \"Bitcoin-compatible fees\"; quote Dilithium vsize.\n";

    // Checklist score.
    const int total = audit.PassCount() + audit.FailCount();
    const int score = total == 0 ? 0 : (audit.PassCount() * 100) / total;

    std::cout << "\n  CHECKLIST / RISK SCORE\n";
    std::cout << "  ──────────────────────\n";
    std::cout << "  Checks passed : " << audit.PassCount() << "\n";
    std::cout << "  Checks failed : " << audit.FailCount() << "\n";
    std::cout << "  Pass rate     : " << score << "%\n";
    std::cout << "  Risk notes    : " << audit.Risks().size() << "\n";

    if (!audit.Failures().empty()) {
        std::cout << "  Failed items:\n";
        for (const auto& f : audit.Failures()) {
            std::cout << "    - " << f << "\n";
        }
    }

    std::cout << "\n  Readiness verdict (engineering, not marketing):\n";
    if (audit.FailCount() == 0 && score >= 100) {
        std::cout << "  CRYPTO/CONSENSUS CORE: PASS for further testnet hardening.\n";
        std::cout << "  MAINNET: NOT READY — operational, economic, and long-running\n";
        std::cout << "  adversarial validation work remains (see recommendations).\n";
    } else {
        std::cout << "  CRYPTO/CONSENSUS CORE: FAIL — resolve failed checks before any\n";
        std::cout << "  mainnet discussion.\n";
    }

    std::cout << "\n################################################################\n";
    std::cout << "#  End of audit report                                         #\n";
    std::cout << "################################################################\n\n";

    BOOST_CHECK_EQUAL(audit.FailCount(), 0);
}

BOOST_AUTO_TEST_SUITE_END()

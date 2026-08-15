// Copyright (c) 2026 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Dilithium cryptographic / consensus-safety audit tests.
 *
 * These tests deliberately re-derive the load-bearing claims from first
 * principles instead of trusting the higher-level suites. Several of them
 * assert *current* behaviour that the audit flags as a defect; those are
 * marked BUG-WITNESS and must be updated (not deleted) when the defect is
 * fixed, so the fix is provably effective.
 *
 *   ./src/test/test_bitcoin --run_test=dilithium_crypto_audit_tests
 */

#include <addresstype.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <crypto/dilithium.h>
#include <crypto/sha256.h>
#include <dilithiumkey.h>
#include <dilithiumpubkey.h>
#include <hash.h>
#include <key.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <consensus/validation.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/transaction_identifier.h>

#include <cstring>
#include <set>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

//! Fixed 32-byte seed used by the known-answer tests.
uint256 KatSeed(unsigned char fill)
{
    uint256 s;
    std::memset(s.data(), fill, 32);
    return s;
}

std::string Sha256Hex(Span<const unsigned char> data)
{
    unsigned char out[32];
    CSHA256().Write(data.data(), data.size()).Finalize(out);
    return HexStr(Span<const unsigned char>(out, 32));
}

//! Signature blob as it appears on the stack: raw ML-DSA sig + 1 sighash byte.
//! `msg` is the tagged message from DilithiumSignatureMessage(), not a bare sighash.
std::vector<unsigned char> SignWithHashType(const CDilithiumKey& key, const uint256& msg, int hashtype)
{
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(msg, sig));
    sig.push_back(static_cast<unsigned char>(hashtype));
    return sig;
}

//! The hashtype byte a signer actually emitted: the last byte of the signature push,
//! which in a P2PKH scriptSig is the first of the two.
unsigned char EmittedHashtype(const CScript& script_sig)
{
    CScript::const_iterator pc = script_sig.begin();
    opcodetype op;
    std::vector<unsigned char> push;
    BOOST_REQUIRE(script_sig.GetOp(pc, op, push));
    BOOST_REQUIRE(!push.empty());
    return push.back();
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(dilithium_crypto_audit_tests, BasicTestingSetup)

// ─────────────────────────────────────────────────────────────────────────
// 1. Key generation & determinism
// ─────────────────────────────────────────────────────────────────────────

/**
 * The startup self-test must pass on this build, and it must be the thing that
 * enforces the pinned seed -> key mapping (S1) and the exact signature length
 * (S2). If it ever fails, seeded key derivation is refused outright rather than
 * silently producing different keys.
 */
BOOST_AUTO_TEST_CASE(runtime_self_test_gates_keygen_and_sizes)
{
    BOOST_REQUIRE(dilithium::IsAvailable());
    BOOST_CHECK(dilithium::SelfTest());

    // Because the self-test passes, seeded derivation is permitted...
    CDilithiumKey k;
    k.MakeNewKeyFromSeed(KatSeed(0x5A));
    BOOST_CHECK(k.IsValid());

    // ...and signatures are exactly the FIPS 204 ML-DSA-65 length.
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(k.Sign(Hash(std::vector<unsigned char>{'s'}), sig));
    BOOST_CHECK_EQUAL(sig.size(), dilithium::SIGNATURE_MAX_SIZE);
}

/**
 * S2 regression: signature length canonicality is now a QubitCoin rule, checked
 * in dilithium::Verify, not merely an internal liboqs invariant. Verify must
 * reject any length other than exactly SIGNATURE_MAX_SIZE before it ever reaches
 * the library.
 */
BOOST_AUTO_TEST_CASE(verify_enforces_exact_signature_length)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    const CDilithiumPubKey pub = key.GetPubKey();
    const uint256 msg = Hash(std::vector<unsigned char>{'l', 'e', 'n'});
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(msg, sig));
    BOOST_REQUIRE_EQUAL(sig.size(), dilithium::SIGNATURE_MAX_SIZE);
    BOOST_CHECK(pub.Verify(msg, sig));

    // Every other length is rejected, including lengths within the old
    // "non-empty and <= max" window that used to be forwarded to liboqs.
    for (size_t len : {size_t{0}, size_t{1}, size_t{32}, size_t{1952},
                       dilithium::SIGNATURE_MAX_SIZE - 1}) {
        std::vector<unsigned char> t(sig.begin(), sig.begin() + len);
        BOOST_CHECK_MESSAGE(!pub.Verify(msg, t), "length " << len << " accepted");
    }
    std::vector<unsigned char> longer(sig);
    longer.push_back(0x00);
    BOOST_CHECK(!pub.Verify(msg, longer));
}

/**
 * Known-answer test pinning seed -> public key.
 *
 * MakeNewKeyFromSeed does NOT feed the seed to a FIPS 204 derandomised
 * keygen (liboqs 0.14 exposes no such entry point). It installs a custom
 * global RNG emitting SHA256(seed || LE64(ctr)) and lets liboqs draw its own
 * xi. The resulting key therefore depends on *how many bytes* and *in what
 * order* liboqs' ML-DSA-65 keypair draws from randombytes. That is an
 * internal implementation detail, not a standardised mapping.
 *
 * This KAT freezes the mapping so any liboqs upgrade that changes its
 * randomness consumption fails loudly here instead of silently making every
 * existing HD wallet unrecoverable.
 */
BOOST_AUTO_TEST_CASE(kat_seed_to_pubkey_is_pinned)
{
    BOOST_REQUIRE(dilithium::IsAvailable());

    CDilithiumKey k0;
    k0.MakeNewKeyFromSeed(KatSeed(0x00));
    BOOST_REQUIRE(k0.IsValid());
    const CDilithiumPubKey p0 = k0.GetPubKey();
    BOOST_CHECK_EQUAL(p0.size(), dilithium::PUBLIC_KEY_SIZE);

    CDilithiumKey k1;
    k1.MakeNewKeyFromSeed(KatSeed(0xAB));
    BOOST_REQUIRE(k1.IsValid());
    const CDilithiumPubKey p1 = k1.GetPubKey();

    const std::string h0 = Sha256Hex(Span<const unsigned char>(p0.data(), p0.size()));
    const std::string h1 = Sha256Hex(Span<const unsigned char>(p1.data(), p1.size()));
    BOOST_TEST_MESSAGE("KAT seed(0x00..) -> SHA256(pubkey) = " << h0);
    BOOST_TEST_MESSAGE("KAT seed(0xAB..) -> SHA256(pubkey) = " << h1);

    // Pinned expectations, measured against liboqs 0.14.1 (ML-DSA-65 keygen
    // draws exactly 32 bytes from randombytes and uses them as xi). If a liboqs
    // upgrade changes that consumption pattern these break loudly — which is the
    // point: silently changing the mapping would make every existing HD wallet
    // unrecoverable.
    BOOST_CHECK_EQUAL(h0, "22320b719b796da8822243444a954cb54fe8924e4ba64cdf43a861cb8c25a764");
    BOOST_CHECK_EQUAL(h1, "c563c1a31ff6b15e214d0b9212985c9cd2aa4390c54087cfc36c12772c5184fb");

    // Determinism must hold within a run regardless of the pinned digests.
    CDilithiumKey again;
    again.MakeNewKeyFromSeed(KatSeed(0x00));
    BOOST_CHECK(again.GetPubKey() == p0);
    BOOST_CHECK(!(p0 == p1));
}

/**
 * HD child-seed PRF: child(i) = HMAC-SHA256(master, "QBTC-ML-DSA-65-HD" || LE32(i)).
 *
 * Injectivity argument: the label is a fixed 17-byte constant and the index is
 * a fixed-width 4-byte little-endian integer, so the message encoding
 * label||LE32(i) is prefix-free in i. Distinct i therefore give distinct HMAC
 * messages, and a collision would require a SHA-256 collision. HMAC (rather
 * than a bare hash) also removes any length-extension concern and keeps the
 * master seed in the key position, so child seeds leak nothing about it under
 * the standard PRF assumption.
 */
BOOST_AUTO_TEST_CASE(hd_prf_domain_separation_and_injectivity)
{
    const uint256 master = KatSeed(0x11);
    const uint256 other_master = KatSeed(0x12);

    // No collisions across a wide index range.
    std::set<uint256> seen;
    for (uint32_t i = 0; i < 4096; ++i) {
        BOOST_REQUIRE(seen.insert(DeriveDilithiumChildSeed(master, i)).second);
    }
    // Boundary indices above the dense range, including the LE32 sign/wrap points.
    for (uint32_t i : {uint32_t{65535}, uint32_t{65536}, uint32_t{0x00ffffff},
                       uint32_t{0x01000000}, uint32_t{0x7fffffff},
                       uint32_t{0x80000000}, uint32_t{0xffffffff}}) {
        BOOST_CHECK_MESSAGE(seen.insert(DeriveDilithiumChildSeed(master, i)).second,
                            "child seed collision at index " << i);
    }
    BOOST_CHECK_EQUAL(seen.size(), 4096U + 7U);

    // Different masters never share a child seed at the same index.
    for (uint32_t i = 0; i < 64; ++i) {
        BOOST_CHECK(DeriveDilithiumChildSeed(master, i) != DeriveDilithiumChildSeed(other_master, i));
    }

    // A child seed must not equal the master (no identity leak).
    BOOST_CHECK(DeriveDilithiumChildSeed(master, 0) != master);

    // Distinct child seeds must yield distinct keys.
    CDilithiumKey a, b;
    a.MakeNewKeyFromSeed(DeriveDilithiumChildSeed(master, 0));
    b.MakeNewKeyFromSeed(DeriveDilithiumChildSeed(master, 1));
    BOOST_REQUIRE(a.IsValid() && b.IsValid());
    BOOST_CHECK(!(a.GetPubKey() == b.GetPubKey()));
}

/**
 * A CDilithiumKey must be able to prove its secret matches its public key.
 *
 * Set() stores the supplied public key verbatim and GetPubKey() echoes that
 * cached copy, so the guard the wallet used to apply,
 *     key.Set(secret, pubkey); return key.GetPubKey() == pubkey;
 * compared the stored public key with itself and could never fail. A "dckey"
 * record pairing secret A with public key B loaded without complaint and then
 * produced signatures nothing could verify. VerifyPubKey() closes that by
 * signing a challenge and checking it against the *claimed* public key, the way
 * CKey::VerifyPubKey() does for ECDSA.
 */
BOOST_AUTO_TEST_CASE(dilithium_key_binds_secret_to_pubkey)
{
    CDilithiumKey good = GenerateRandomDilithiumKey();
    CDilithiumKey other = GenerateRandomDilithiumKey();
    BOOST_REQUIRE(good.IsValid() && other.IsValid());
    const CDilithiumPubKey right_pub = good.GetPubKey();
    const CDilithiumPubKey wrong_pub = other.GetPubKey();

    // Pair good's SECRET with other's PUBLIC key. Still structurally valid:
    // both fields are the right length, so nothing cheap can tell them apart.
    CDilithiumKey frankenkey;
    BOOST_REQUIRE(frankenkey.Set(Span<const unsigned char>(good.data(), good.size()),
                                 Span<const unsigned char>(wrong_pub.data(), wrong_pub.size())));
    BOOST_CHECK(frankenkey.IsValid());

    // The old check: vacuously true, which is why it caught nothing.
    BOOST_CHECK(frankenkey.GetPubKey() == wrong_pub);

    // The real one: rejects the mismatch, and accepts the honest pairing.
    BOOST_CHECK_MESSAGE(!frankenkey.VerifyPubKey(wrong_pub),
                        "mismatched secret/pubkey pair must be rejected");
    BOOST_CHECK(good.VerifyPubKey(right_pub));
    BOOST_CHECK(other.VerifyPubKey(wrong_pub));
    BOOST_CHECK(!good.VerifyPubKey(wrong_pub));
    BOOST_CHECK(!other.VerifyPubKey(right_pub));

    // What the mismatch would have cost: the key signs under a different
    // keypair, so every signature it produces is worthless.
    const uint256 msg = Hash(std::vector<unsigned char>{'b', 'i', 'n', 'd'});
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(frankenkey.Sign(msg, sig));
    BOOST_CHECK_MESSAGE(!wrong_pub.Verify(msg, sig),
                        "signature must not verify under the mismatched public key");
    BOOST_CHECK_MESSAGE(right_pub.Verify(msg, sig),
                        "signature verifies under the real key of the secret used");

    // A garbage secret of the right length cannot masquerade either.
    const std::vector<unsigned char> zeros(CDilithiumKey::SIZE, 0x00);
    CDilithiumKey junk;
    BOOST_REQUIRE(junk.Set(Span<const unsigned char>(zeros.data(), zeros.size()),
                           Span<const unsigned char>(right_pub.data(), right_pub.size())));
    BOOST_CHECK(!junk.VerifyPubKey(right_pub));
}

// ─────────────────────────────────────────────────────────────────────────
// 2. Signature scheme correctness
// ─────────────────────────────────────────────────────────────────────────

/**
 * ML-DSA-65 signatures are fixed length (3309 bytes). Neither truncated nor
 * padded signatures may verify: otherwise a third party could reshape a
 * signature, changing the txid of a non-witness spend.
 *
 * NOTE: this canonicality is currently enforced *inside liboqs*
 * (siglen != CRYPTO_BYTES -> reject), not by QubitCoin consensus code. The
 * audit recommends an explicit length check in dilithium::Verify so that
 * consensus does not depend on a third-party library's internal invariant.
 */
BOOST_AUTO_TEST_CASE(signature_length_is_canonical)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    BOOST_REQUIRE(key.IsValid());
    const CDilithiumPubKey pub = key.GetPubKey();
    const uint256 msg = Hash(std::vector<unsigned char>{'q', 'b', 't', 'c'});

    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(msg, sig));
    BOOST_CHECK_EQUAL(sig.size(), dilithium::SIGNATURE_MAX_SIZE);
    BOOST_CHECK(pub.Verify(msg, sig));

    // Truncation
    for (size_t drop : {size_t{1}, size_t{2}, size_t{100}, sig.size()}) {
        std::vector<unsigned char> t(sig.begin(), sig.end() - drop);
        BOOST_CHECK_MESSAGE(!pub.Verify(msg, t), "truncated by " << drop << " verified");
    }
    // Padding
    for (size_t add : {size_t{1}, size_t{8}}) {
        std::vector<unsigned char> p(sig);
        p.insert(p.end(), add, 0x00);
        BOOST_CHECK_MESSAGE(!pub.Verify(msg, p), "padded by " << add << " verified");
    }
    // Single-bit mutations must all fail (strong unforgeability spot-check).
    for (size_t i = 0; i < 96; ++i) {
        std::vector<unsigned char> m(sig);
        m[(i * 37) % m.size()] ^= static_cast<unsigned char>(1u << (i % 8));
        BOOST_CHECK(!pub.Verify(msg, m));
    }
    // Wrong key must fail.
    BOOST_CHECK(!GenerateRandomDilithiumKey().GetPubKey().Verify(msg, sig));
}

/**
 * The signed message must commit to the hashtype byte and to the input amount.
 *
 * Dilithium always uses the BIP143 (WITNESS_V0) algorithm, which serialises
 * nHashType as a 4-byte little-endian int and the amount as an 8-byte int.
 * Distinct hashtype bytes therefore give distinct preimages, so a third party
 * cannot rewrite the trailing sighash byte of a signature blob. The assertions
 * are made on DilithiumSignatureMessage() rather than on the inner sighash,
 * because that is what a key actually signs — which also shows the tag layer
 * preserves the distinctions the sighash draws.
 */
BOOST_AUTO_TEST_CASE(sighash_commits_hashtype_and_amount)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    const CDilithiumPubKey pub = key.GetPubKey();
    const CScript spk = GetScriptForDestination(DilithiumPKHash(pub));
    const CAmount amount = 1234567;
    const CTransaction credit{BuildCreditingTransaction(spk, static_cast<int>(amount))};
    CMutableTransaction spend = BuildSpendingTransaction(CScript(), CScriptWitness(), credit);

    // Distinct hashtypes -> distinct messages (injective commitment).
    std::set<uint256> hashes;
    for (int ht = 0; ht < 256; ++ht) {
        hashes.insert(DilithiumSignatureMessage(spk, spend, 0, ht, amount, nullptr));
    }
    BOOST_CHECK_EQUAL(hashes.size(), 256U);

    // Amount is committed: changing it changes the message.
    const uint256 h_a = DilithiumSignatureMessage(spk, spend, 0, SIGHASH_ALL, amount, nullptr);
    const uint256 h_b = DilithiumSignatureMessage(spk, spend, 0, SIGHASH_ALL, amount + 1, nullptr);
    BOOST_CHECK(h_a != h_b);

    // End-to-end: rewriting the trailing hashtype byte invalidates the spend.
    spend.vin[0].scriptSig = CScript()
        << SignWithHashType(key, h_a, SIGHASH_ALL)
        << ToByteVector(pub);
    ScriptError serr = SCRIPT_ERR_OK;
    {
        const MutableTransactionSignatureChecker checker(&spend, 0, amount, MissingDataBehavior::ASSERT_FAIL);
        BOOST_CHECK(VerifyScript(spend.vin[0].scriptSig, spk, nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serr));
    }
    std::vector<unsigned char> tampered = SignWithHashType(key, h_a, SIGHASH_ALL);
    tampered.back() = SIGHASH_NONE; // flip only the hashtype byte
    spend.vin[0].scriptSig = CScript() << tampered << ToByteVector(pub);
    {
        const MutableTransactionSignatureChecker checker(&spend, 0, amount, MissingDataBehavior::ASSERT_FAIL);
        BOOST_CHECK(!VerifyScript(spend.vin[0].scriptSig, spk, nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serr));
    }
}

/**
 * Only the six defined hashtype bytes are accepted, and the rule is consensus, not
 * policy.
 *
 * All 256 values were previously accepted. None of them was third-party malleable —
 * the byte is committed inside the sighash — but SignatureHash() only reads the low
 * five bits and the ANYONECANPAY bit, so 0x21 meant exactly what SIGHASH_ALL means,
 * and a signer could pick any of 250 spare encodings of the same intent. Every value
 * here is signed correctly for its own byte, so the only thing under test is whether
 * the byte itself is allowed: a rejection can only come from the new rule, not from a
 * message mismatch.
 */
BOOST_AUTO_TEST_CASE(only_defined_hashtypes_are_accepted)
{
    const std::set<int> defined{SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE,
                                SIGHASH_ALL | SIGHASH_ANYONECANPAY,
                                SIGHASH_NONE | SIGHASH_ANYONECANPAY,
                                SIGHASH_SINGLE | SIGHASH_ANYONECANPAY};
    BOOST_CHECK_EQUAL(defined.size(), 6U);

    // The predicate itself, over the whole byte range.
    for (int ht = 0; ht < 256; ++ht) {
        BOOST_CHECK_MESSAGE(IsDefinedDilithiumHashtype(static_cast<unsigned char>(ht)) == (defined.count(ht) == 1),
                            "IsDefinedDilithiumHashtype disagrees at " << ht);
    }

    CDilithiumKey key = GenerateRandomDilithiumKey();
    const CDilithiumPubKey pub = key.GetPubKey();
    const CScript spk = GetScriptForDestination(DilithiumPKHash(pub));
    const CAmount amount = 100000;
    const CTransaction credit{BuildCreditingTransaction(spk, static_cast<int>(amount))};
    CMutableTransaction spend = BuildSpendingTransaction(CScript(), CScriptWitness(), credit);

    for (int ht = 0; ht < 256; ++ht) {
        const uint256 msg = DilithiumSignatureMessage(spk, spend, 0, ht, amount, nullptr);
        spend.vin[0].scriptSig = CScript() << SignWithHashType(key, msg, ht) << ToByteVector(pub);
        const MutableTransactionSignatureChecker checker(&spend, 0, amount, MissingDataBehavior::ASSERT_FAIL);

        // Consensus flags, so this cannot be mistaken for a standardness rule the
        // way ECDSA's identical check is (it hangs off SCRIPT_VERIFY_STRICTENC).
        ScriptError err = SCRIPT_ERR_OK;
        const bool ok = VerifyScript(spend.vin[0].scriptSig, spk, nullptr,
                                     MANDATORY_SCRIPT_VERIFY_FLAGS, checker, &err);
        if (defined.count(ht)) {
            BOOST_CHECK_MESSAGE(ok, "hashtype " << ht << " must verify: " << ScriptErrorString(err));
        } else {
            BOOST_CHECK_MESSAGE(!ok, "undefined hashtype " << ht << " must be refused");
            BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_SIG_HASHTYPE,
                                "hashtype " << ht << " refused for the wrong reason: " << ScriptErrorString(err));
        }
    }

    // An empty signature is still the compact way to fail a CHECKSIG: it has no
    // hashtype byte to judge, so it must not be diagnosed as a bad one.
    spend.vin[0].scriptSig = CScript() << std::vector<unsigned char>{} << ToByteVector(pub);
    {
        const MutableTransactionSignatureChecker checker(&spend, 0, amount, MissingDataBehavior::ASSERT_FAIL);
        ScriptError err = SCRIPT_ERR_OK;
        BOOST_CHECK(!VerifyScript(spend.vin[0].scriptSig, spk, nullptr,
                                  MANDATORY_SCRIPT_VERIFY_FLAGS, checker, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);
    }
}

/**
 * The signer will not produce what the interpreter will not accept: the wallet
 * signing path refuses an undefined hashtype outright, and each of the six defined
 * ones round-trips to a spend that verifies.
 */
BOOST_AUTO_TEST_CASE(signing_path_only_produces_defined_hashtypes)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    FillableSigningProvider keystore;
    BOOST_REQUIRE(keystore.AddDilithiumKey(key));
    const CScript spk = GetScriptForDestination(DilithiumPKHash(key.GetPubKey()));
    const CAmount amount = 100000;
    const CTransaction credit{BuildCreditingTransaction(spk, static_cast<int>(amount))};

    for (const int ht : {int{SIGHASH_ALL}, int{SIGHASH_NONE}, int{SIGHASH_SINGLE},
                         SIGHASH_ALL | SIGHASH_ANYONECANPAY,
                         SIGHASH_NONE | SIGHASH_ANYONECANPAY,
                         SIGHASH_SINGLE | SIGHASH_ANYONECANPAY}) {
        CMutableTransaction spend = BuildSpendingTransaction(CScript(), CScriptWitness(), credit);
        SignatureData sigdata;
        BOOST_CHECK_MESSAGE(SignSignature(keystore, spk, spend, 0, amount, ht, sigdata),
                            "signing must support hashtype " << ht);

        ScriptError err = SCRIPT_ERR_OK;
        const MutableTransactionSignatureChecker checker(&spend, 0, amount, MissingDataBehavior::ASSERT_FAIL);
        BOOST_CHECK_MESSAGE(VerifyScript(spend.vin[0].scriptSig, spk, nullptr,
                                         STANDARD_SCRIPT_VERIFY_FLAGS, checker, &err),
                            "hashtype " << ht << " spend must verify: " << ScriptErrorString(err));
        BOOST_CHECK_EQUAL(EmittedHashtype(spend.vin[0].scriptSig), static_cast<unsigned char>(ht));
    }

    // Undefined values, and a value that does not fit in the trailing byte, are
    // refused before any signature is produced.
    for (const int ht : {0x04, 0x05, 0x21, 0x7f, 0x80, 0x84, 0xff, 0x101}) {
        CMutableTransaction spend = BuildSpendingTransaction(CScript(), CScriptWitness(), credit);
        SignatureData sigdata;
        BOOST_CHECK_MESSAGE(!SignSignature(keystore, spk, spend, 0, amount, ht, sigdata),
                            "signing must refuse hashtype " << ht);
    }

    // The one value that is translated rather than refused: SIGHASH_DEFAULT has no
    // encoding of its own outside Taproot, so it signs, and emits, SIGHASH_ALL.
    CMutableTransaction spend = BuildSpendingTransaction(CScript(), CScriptWitness(), credit);
    SignatureData sigdata;
    BOOST_CHECK(SignSignature(keystore, spk, spend, 0, amount, SIGHASH_DEFAULT, sigdata));
    BOOST_CHECK_EQUAL(EmittedHashtype(spend.vin[0].scriptSig), static_cast<unsigned char>(SIGHASH_ALL));
}

// ─────────────────────────────────────────────────────────────────────────
// 3. Verification path
// ─────────────────────────────────────────────────────────────────────────

//! ECDSA and Schnorr must be dead for *every* input, including well-formed ones.
BOOST_AUTO_TEST_CASE(ecdsa_and_schnorr_are_unconditionally_false)
{
    CKey eckey = GenerateRandomKey();
    const CPubKey ecpub = eckey.GetPubKey();
    const CScript spk = GetScriptForDestination(PKHash(ecpub));
    const CTransaction credit{BuildCreditingTransaction(spk, 1000)};
    CMutableTransaction spend = BuildSpendingTransaction(CScript(), CScriptWitness(), credit);

    const uint256 sighash = SignatureHash(spk, spend, 0, SIGHASH_ALL, 1000, SigVersion::BASE, nullptr);
    std::vector<unsigned char> ecsig;
    BOOST_REQUIRE(eckey.Sign(sighash, ecsig));
    ecsig.push_back(SIGHASH_ALL);

    const MutableTransactionSignatureChecker checker(&spend, 0, 1000, MissingDataBehavior::ASSERT_FAIL);

    // The raw secp256k1 signature is genuinely valid...
    BOOST_CHECK(ecpub.Verify(sighash, {ecsig.begin(), ecsig.end() - 1}));
    // ...yet the consensus checker refuses it unconditionally.
    BOOST_CHECK(!checker.CheckECDSASignature(ecsig, ToByteVector(ecpub), spk, SigVersion::BASE));

    // A full P2PKH ECDSA spend must fail with SCRIPT_ERR_PUBKEYTYPE (size gate).
    spend.vin[0].scriptSig = CScript() << ecsig << ToByteVector(ecpub);
    ScriptError serr = SCRIPT_ERR_OK;
    BOOST_CHECK(!VerifyScript(spend.vin[0].scriptSig, spk, nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serr));
    BOOST_CHECK_EQUAL(serr, SCRIPT_ERR_PUBKEYTYPE);

    // Every non-1952 pubkey length is rejected by the size gate.
    for (size_t len : {size_t{0}, size_t{1}, size_t{32}, size_t{33}, size_t{65},
                       size_t{520}, size_t{1951}, size_t{1953}, size_t{4096}}) {
        const std::vector<unsigned char> fake(len, 0x02);
        ScriptError e = SCRIPT_ERR_OK;
        CScript ss = CScript() << std::vector<unsigned char>(64, 0x01) << fake;
        CScript pkh = CScript() << OP_DUP << OP_HASH160 << ToByteVector(uint160()) << OP_EQUALVERIFY << OP_CHECKSIG;
        BOOST_CHECK(!VerifyScript(ss, pkh, nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, checker, &e));
    }

    // Schnorr: the checker always sets SCRIPT_ERR_SCHNORR_SIG.
    ScriptExecutionData execdata;
    ScriptError schnorr_err = SCRIPT_ERR_OK;
    const std::vector<unsigned char> xonly(32, 0x07), sig64(64, 0x09);
    BOOST_CHECK(!checker.CheckSchnorrSignature(sig64, xonly, SigVersion::TAPROOT, execdata, &schnorr_err));
    BOOST_CHECK_EQUAL(schnorr_err, SCRIPT_ERR_SCHNORR_SIG);
}

/**
 * Signature-cache entries must be domain separated.
 *
 * Within the Dilithium domain the preimage is salt || hash(32) || pubkey(1952)
 * || sig, and both hash and pubkey are fixed width, so the concatenation is
 * unambiguously parseable and cannot be re-split into a different (hash,
 * pubkey, sig) triple. Across domains the 'E'/'S'/'D' padding produces three
 * different SHA-256 midstates.
 */
BOOST_AUTO_TEST_CASE(sigcache_domain_separation)
{
    SignatureCache cache{DEFAULT_SIGNATURE_CACHE_BYTES};

    CDilithiumKey dkey = GenerateRandomDilithiumKey();
    const CDilithiumPubKey dpub = dkey.GetPubKey();
    const uint256 h = Hash(std::vector<unsigned char>{1, 2, 3});
    std::vector<unsigned char> dsig;
    BOOST_REQUIRE(dkey.Sign(h, dsig));

    CKey eckey = GenerateRandomKey();
    const CPubKey ecpub = eckey.GetPubKey();
    std::vector<unsigned char> ecsig;
    BOOST_REQUIRE(eckey.Sign(h, ecsig));

    uint256 e_dil, e_ecdsa, e_schnorr;
    cache.ComputeEntryDilithium(e_dil, h, dsig, dpub);
    cache.ComputeEntryECDSA(e_ecdsa, h, ecsig, ecpub);
    cache.ComputeEntrySchnorr(e_schnorr, h, ecsig, XOnlyPubKey(ecpub));
    BOOST_CHECK(e_dil != e_ecdsa);
    BOOST_CHECK(e_dil != e_schnorr);
    BOOST_CHECK(e_ecdsa != e_schnorr);

    // Same scheme, different inputs -> different entries.
    uint256 e2;
    cache.ComputeEntryDilithium(e2, Hash(std::vector<unsigned char>{9}), dsig, dpub);
    BOOST_CHECK(e_dil != e2);
    cache.ComputeEntryDilithium(e2, h, dsig, GenerateRandomDilithiumKey().GetPubKey());
    BOOST_CHECK(e_dil != e2);

    // A cached Dilithium entry must not be readable through another domain.
    cache.Set(e_dil);
    BOOST_CHECK(cache.Get(e_dil, /*erase=*/false));
    BOOST_CHECK(!cache.Get(e_ecdsa, /*erase=*/false));
}

// ─────────────────────────────────────────────────────────────────────────
// 4. DoS accounting: alternative Dilithium spend shapes
// ─────────────────────────────────────────────────────────────────────────

namespace {
//! P2WPKH-style Dilithium spend: 20-byte witness program over Hash160(mldsa pubkey).
struct WitnessSpend {
    CScript scriptPubKey;
    CMutableTransaction spend;
    CAmount amount{100000};
};

WitnessSpend BuildDilithiumP2WPKH(const CDilithiumKey& key)
{
    WitnessSpend w;
    const CDilithiumPubKey pub = key.GetPubKey();
    const CKeyID keyid = pub.GetID();
    w.scriptPubKey = GetScriptForDestination(WitnessV0KeyHash(uint160{keyid}));

    const CTransaction credit{BuildCreditingTransaction(w.scriptPubKey, static_cast<int>(w.amount))};
    w.spend = BuildSpendingTransaction(CScript(), CScriptWitness(), credit);

    // Implied P2PKH scriptCode, exactly as VerifyWitnessProgram builds it.
    const CScript exec_script = CScript()
        << OP_DUP << OP_HASH160 << ToByteVector(keyid) << OP_EQUALVERIFY << OP_CHECKSIG;
    const uint256 msg = DilithiumSignatureMessage(exec_script, w.spend, 0, SIGHASH_ALL, w.amount, nullptr);
    w.spend.vin[0].scriptSig = CScript(); // must be empty for native segwit
    w.spend.vin[0].scriptWitness.stack.clear();
    w.spend.vin[0].scriptWitness.stack.push_back(SignWithHashType(key, msg, SIGHASH_ALL));
    w.spend.vin[0].scriptWitness.stack.emplace_back(pub.begin(), pub.end());
    return w;
}

//! P2SH-wrapped bare-pubkey Dilithium spend: redeemScript = <pubkey> OP_CHECKSIG.
struct P2shSpend {
    CScript scriptPubKey;
    CScript redeemScript;
    CMutableTransaction spend;
    CAmount amount{100000};
};

P2shSpend BuildDilithiumP2SH(const CDilithiumKey& key)
{
    P2shSpend p;
    const CDilithiumPubKey pub = key.GetPubKey();
    p.redeemScript = CScript() << ToByteVector(pub) << OP_CHECKSIG;
    p.scriptPubKey = GetScriptForDestination(ScriptHash(p.redeemScript));

    const CTransaction credit{BuildCreditingTransaction(p.scriptPubKey, static_cast<int>(p.amount))};
    p.spend = BuildSpendingTransaction(CScript(), CScriptWitness(), credit);

    const uint256 msg = DilithiumSignatureMessage(p.redeemScript, p.spend, 0, SIGHASH_ALL, p.amount, nullptr);
    p.spend.vin[0].scriptSig = CScript()
        << SignWithHashType(key, msg, SIGHASH_ALL)
        << std::vector<unsigned char>(p.redeemScript.begin(), p.redeemScript.end());
    return p;
}
} // namespace

/**
 * BUG-WITNESS: a Dilithium key can be spent through a native P2WPKH output.
 *
 * EvalChecksigPreTapscript no longer calls CheckPubKeyEncoding, so
 * SCRIPT_VERIFY_WITNESS_PUBKEYTYPE (which would reject a non-33-byte key in
 * segwit) never runs. VerifyWitnessProgram builds the implied P2PKH script and
 * executes it with SigVersion::WITNESS_V0, which the Dilithium checker accepts.
 *
 * Consequences: the ~5.3 kB signature+pubkey move into the witness and receive
 * the 75% weight discount, so roughly 4x more Dilithium verifications fit in a
 * block than the bare-P2PKH capacity model assumes.
 */
BOOST_AUTO_TEST_CASE(dilithium_p2wpkh_is_consensus_valid)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    WitnessSpend w = BuildDilithiumP2WPKH(key);

    ScriptError serr = SCRIPT_ERR_OK;
    const MutableTransactionSignatureChecker checker(&w.spend, 0, w.amount, MissingDataBehavior::ASSERT_FAIL);
    const bool ok = VerifyScript(w.spend.vin[0].scriptSig, w.scriptPubKey,
                                 &w.spend.vin[0].scriptWitness,
                                 STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serr);
    BOOST_TEST_MESSAGE("Dilithium P2WPKH VerifyScript -> " << ok << " (" << ScriptErrorString(serr) << ")");
    BOOST_CHECK_MESSAGE(ok, "expected current (defective) behaviour: witness Dilithium spends validate");

    // Weight comparison against the bare-P2PKH model.
    const int64_t witness_weight = GetTransactionWeight(CTransaction(w.spend));
    CDilithiumKey k2 = GenerateRandomDilithiumKey();
    const CScript legacy_spk = GetScriptForDestination(DilithiumPKHash(k2.GetPubKey()));
    const CTransaction legacy_credit{BuildCreditingTransaction(legacy_spk, 100000)};
    CMutableTransaction legacy = BuildSpendingTransaction(CScript(), CScriptWitness(), legacy_credit);
    const uint256 lh = DilithiumSignatureMessage(legacy_spk, legacy, 0, SIGHASH_ALL, 100000, nullptr);
    legacy.vin[0].scriptSig = CScript() << SignWithHashType(k2, lh, SIGHASH_ALL) << ToByteVector(k2.GetPubKey());
    const int64_t legacy_weight = GetTransactionWeight(CTransaction(legacy));

    BOOST_TEST_MESSAGE("weight: P2WPKH-Dilithium=" << witness_weight
                       << " WU vs bare-P2PKH-Dilithium=" << legacy_weight << " WU");
    BOOST_CHECK_MESSAGE(witness_weight * 3 < legacy_weight,
                        "witness discount should make the witness form far cheaper");
}

/**
 * BUG-WITNESS: P2SH-wrapped bare-pubkey Dilithium also validates. Because
 * MAX_SCRIPT_ELEMENT_SIZE is 4096, a 1952-byte key fits inside a redeemScript
 * push, so the 1952-byte-push heuristic used by policy never sees it.
 */
BOOST_AUTO_TEST_CASE(dilithium_p2sh_bare_pubkey_is_consensus_valid)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    P2shSpend p = BuildDilithiumP2SH(key);

    ScriptError serr = SCRIPT_ERR_OK;
    const MutableTransactionSignatureChecker checker(&p.spend, 0, p.amount, MissingDataBehavior::ASSERT_FAIL);
    const bool ok = VerifyScript(p.spend.vin[0].scriptSig, p.scriptPubKey, nullptr,
                                 STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serr);
    BOOST_TEST_MESSAGE("Dilithium P2SH(bare pubkey) VerifyScript -> " << ok
                       << " (" << ScriptErrorString(serr) << ")");
    BOOST_CHECK_MESSAGE(ok, "expected current (defective) behaviour: P2SH Dilithium spends validate");
}

/**
 * Regression test for the hardened relay bound (audit item 4.3).
 *
 * The invariant is that no standard transaction can demand more than
 * MAX_STANDARD_DILITHIUM_INPUTS ML-DSA verifications, whatever shape carries the
 * key:
 *   - bare P2PKH: key pushed directly in the scriptSig,
 *   - P2SH:       key nested inside the redeemScript push,
 *   - segwit:     key in the witness stack, scriptSig empty,
 *   - key only:   a witness item that is just the key, which is cheaper than any
 *                 real spend shape and so is what the count bound exists for.
 *
 * Two rules combine to give that: MAX_STANDARD_TX_WEIGHT bounds any shape that
 * pays at least MIN_STANDARD_DILITHIUM_VERIFY_WEIGHT per verification, and the
 * count bounds anything cheaper. For each shape this walks up to the largest
 * standard input count and checks which rule stopped it.
 */
BOOST_AUTO_TEST_CASE(policy_dilithium_input_limit_covers_all_spend_shapes)
{
    const CScript payout = GetScriptForDestination(
        DilithiumPKHash(GenerateRandomDilithiumKey().GetPubKey()));

    const std::vector<unsigned char> dummy_sig(dilithium::SIGNATURE_MAX_SIZE + 1, 0x01);
    const std::vector<unsigned char> dummy_key(dilithium::PUBLIC_KEY_SIZE, 0x02);

    const CScript bare_scriptsig = CScript() << dummy_sig << dummy_key;
    const CScript redeem = CScript() << dummy_key << OP_CHECKSIG;
    const CScript p2sh_scriptsig = CScript()
        << dummy_sig << std::vector<unsigned char>(redeem.begin(), redeem.end());

    enum class Shape { Bare, P2sh, Witness, KeyOnly };
    auto make = [&](Shape shape, unsigned n_in) {
        CMutableTransaction tx;
        tx.version = 2;
        tx.vin.resize(n_in);
        for (unsigned i = 0; i < n_in; ++i) {
            tx.vin[i].prevout = COutPoint(Txid::FromUint256(uint256::ONE), i);
            switch (shape) {
            case Shape::Bare: tx.vin[i].scriptSig = bare_scriptsig; break;
            case Shape::P2sh: tx.vin[i].scriptSig = p2sh_scriptsig; break;
            case Shape::Witness: tx.vin[i].scriptWitness.stack.assign({dummy_sig, dummy_key}); break;
            case Shape::KeyOnly: tx.vin[i].scriptWitness.stack.assign({dummy_key}); break;
            }
        }
        tx.vout.resize(1);
        tx.vout[0].nValue = 5 * COIN;
        tx.vout[0].scriptPubKey = payout;
        return tx;
    };

    auto reason_for = [](const CMutableTransaction& tx) {
        std::string reason;
        if (IsStandardTx(CTransaction{tx}, MAX_OP_RETURN_RELAY, /*permit_bare_multisig=*/true,
                         CFeeRate{DUST_RELAY_TX_FEE}, reason)) {
            return std::string{};
        }
        return reason;
    };

    for (const auto& [shape, name, expected_reason] :
         {std::tuple{Shape::Bare, "bare-P2PKH", "tx-size"},
          std::tuple{Shape::P2sh, "P2SH-nested", "tx-size"},
          std::tuple{Shape::Witness, "witness", "tx-size"},
          std::tuple{Shape::KeyOnly, "witness key only", "too-many-dilithium-inputs"}}) {
        unsigned n = 0;
        while (n < MAX_STANDARD_DILITHIUM_INPUTS + 1 && reason_for(make(shape, n + 1)).empty()) ++n;

        BOOST_CHECK_MESSAGE(n > 0, name << ": even a single input is non-standard");
        BOOST_CHECK_MESSAGE(CountDilithiumSpendInputs(CTransaction{make(shape, n)}) == n,
                            name << ": only some inputs were recognised as Dilithium spends");
        BOOST_CHECK_MESSAGE(n <= MAX_STANDARD_DILITHIUM_INPUTS,
                            name << ": " << n << " verifications relay, above the bound of "
                                 << MAX_STANDARD_DILITHIUM_INPUTS);
        BOOST_CHECK_MESSAGE(reason_for(make(shape, n + 1)) == expected_reason,
                            name << ": input " << (n + 1) << " rejected by '"
                                 << reason_for(make(shape, n + 1)) << "', expected '"
                                 << expected_reason << "'");
    }
}

/**
 * BUG-WITNESS (third-party malleability).
 *
 * Dilithium spends are non-witness, and the BIP143 sighash does not commit to
 * the scriptSig. Push encoding is only constrained by SCRIPT_VERIFY_MINIMALDATA,
 * which is a *standardness* flag, not a mandatory one. A third party can
 * therefore re-encode the two pushes with OP_PUSHDATA4, changing the txid while
 * keeping the spend valid under consensus rules.
 */
BOOST_AUTO_TEST_CASE(non_minimal_push_encoding_is_third_party_malleable)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    const CDilithiumPubKey pub = key.GetPubKey();
    const CScript spk = GetScriptForDestination(DilithiumPKHash(pub));
    const CAmount amount = 100000;
    const CTransaction credit{BuildCreditingTransaction(spk, static_cast<int>(amount))};
    CMutableTransaction spend = BuildSpendingTransaction(CScript(), CScriptWitness(), credit);

    const uint256 msg = DilithiumSignatureMessage(spk, spend, 0, SIGHASH_ALL, amount, nullptr);
    const std::vector<unsigned char> sig = SignWithHashType(key, msg, SIGHASH_ALL);
    const std::vector<unsigned char> keybytes(pub.begin(), pub.end());

    // Honest, minimally-encoded spend.
    spend.vin[0].scriptSig = CScript() << sig << keybytes;
    const Txid honest_txid = CTransaction(spend).GetHash();
    {
        ScriptError e = SCRIPT_ERR_OK;
        const MutableTransactionSignatureChecker checker(&spend, 0, amount, MissingDataBehavior::ASSERT_FAIL);
        BOOST_CHECK(VerifyScript(spend.vin[0].scriptSig, spk, nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, checker, &e));
    }

    // Same stack, re-encoded with OP_PUSHDATA4 by a third party (no key needed).
    CScript mutated;
    auto push4 = [&mutated](const std::vector<unsigned char>& v) {
        mutated.push_back(OP_PUSHDATA4);
        const uint32_t n = static_cast<uint32_t>(v.size());
        mutated.push_back(static_cast<unsigned char>(n & 0xff));
        mutated.push_back(static_cast<unsigned char>((n >> 8) & 0xff));
        mutated.push_back(static_cast<unsigned char>((n >> 16) & 0xff));
        mutated.push_back(static_cast<unsigned char>((n >> 24) & 0xff));
        mutated.insert(mutated.end(), v.begin(), v.end());
    };
    push4(sig);
    push4(keybytes);
    spend.vin[0].scriptSig = mutated;
    const Txid mutated_txid = CTransaction(spend).GetHash();

    const MutableTransactionSignatureChecker checker(&spend, 0, amount, MissingDataBehavior::ASSERT_FAIL);
    ScriptError mandatory_err = SCRIPT_ERR_OK;
    const bool valid_at_consensus = VerifyScript(spend.vin[0].scriptSig, spk, nullptr,
                                                 MANDATORY_SCRIPT_VERIFY_FLAGS, checker, &mandatory_err);
    ScriptError standard_err = SCRIPT_ERR_OK;
    const bool valid_at_policy = VerifyScript(spend.vin[0].scriptSig, spk, nullptr,
                                              STANDARD_SCRIPT_VERIFY_FLAGS, checker, &standard_err);

    BOOST_TEST_MESSAGE("re-encoded spend: consensus=" << valid_at_consensus
                       << " policy=" << valid_at_policy
                       << " (" << ScriptErrorString(standard_err) << ")");
    BOOST_CHECK_MESSAGE(valid_at_consensus,
                        "BUG-WITNESS: non-minimal push encoding still validates at consensus");
    BOOST_CHECK_MESSAGE(!valid_at_policy, "MINIMALDATA should reject it at relay");
    BOOST_CHECK_MESSAGE(honest_txid != mutated_txid,
                        "BUG-WITNESS: txid changed without access to the private key");
}

/**
 * BUG-WITNESS: GetTransactionSigOpCost charges the Dilithium surcharge only for
 * CHECKSIGs found in the *prevout scriptPubKey*. A P2WPKH or P2SH prevout has
 * none at the top level, so an equally expensive ML-DSA verification is billed
 * at the plain Bitcoin rate and the surcharge never applies.
 */
BOOST_AUTO_TEST_CASE(sigop_cost_undercharges_witness_and_p2sh_dilithium)
{
    const uint32_t flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS};
    CDilithiumKey key = GenerateRandomDilithiumKey();
    const CDilithiumPubKey pub = key.GetPubKey();

    auto cost_for = [&](const CScript& prev_spk, const CMutableTransaction& spend) {
        CCoinsView dummy;
        CCoinsViewCache coins(&dummy);
        const CTransaction credit{BuildCreditingTransaction(prev_spk, 100000)};
        AddCoins(coins, credit, 0);
        CMutableTransaction fixed{spend};
        fixed.vin[0].prevout = COutPoint(credit.GetHash(), 0);
        return GetTransactionSigOpCost(CTransaction(fixed), coins, flags);
    };

    // Baseline: bare Dilithium P2PKH pays the surcharge.
    const CScript bare_spk = GetScriptForDestination(DilithiumPKHash(pub));
    const CTransaction bare_credit{BuildCreditingTransaction(bare_spk, 100000)};
    CMutableTransaction bare_spend = BuildSpendingTransaction(CScript(), CScriptWitness(), bare_credit);
    const int64_t bare_cost = cost_for(bare_spk, bare_spend);
    const int64_t expected_bare = int64_t{WITNESS_SCALE_FACTOR} * DILITHIUM_VERIFY_SIGOP_COST;
    BOOST_TEST_MESSAGE("sigop cost, bare P2PKH Dilithium = " << bare_cost
                       << " (surcharge component " << expected_bare << ")");
    BOOST_CHECK_GE(bare_cost, expected_bare);

    // P2WPKH: same single ML-DSA verify, but no surcharge.
    WitnessSpend w = BuildDilithiumP2WPKH(key);
    const int64_t witness_cost = cost_for(w.scriptPubKey, w.spend);
    BOOST_TEST_MESSAGE("sigop cost, P2WPKH Dilithium    = " << witness_cost);
    BOOST_CHECK_MESSAGE(witness_cost < expected_bare,
                        "BUG-WITNESS: witness Dilithium verify is billed below the surcharge");

    // P2SH bare pubkey: the redeemScript CHECKSIG is counted, but unscaled.
    P2shSpend p = BuildDilithiumP2SH(key);
    const int64_t p2sh_cost = cost_for(p.scriptPubKey, p.spend);
    BOOST_TEST_MESSAGE("sigop cost, P2SH Dilithium      = " << p2sh_cost);
    BOOST_CHECK_MESSAGE(p2sh_cost < expected_bare,
                        "BUG-WITNESS: P2SH Dilithium verify is billed below the surcharge");
}

BOOST_AUTO_TEST_SUITE_END()

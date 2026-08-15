// Copyright (c) 2026 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/dilithium.h>

#include <test/util/setup_common.h>

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(dilithium_tests, BasicTestingSetup)

namespace {
Span<const unsigned char> StrSpan(const std::string& s)
{
    return Span<const unsigned char>(reinterpret_cast<const unsigned char*>(s.data()), s.size());
}
} // namespace

BOOST_AUTO_TEST_CASE(dilithium_available)
{
    // This build must have liboqs support enabled for the remaining tests to
    // be meaningful.
    BOOST_CHECK(dilithium::IsAvailable());
}

BOOST_AUTO_TEST_CASE(dilithium_keygen_sizes)
{
    dilithium::KeyPair kp;
    BOOST_REQUIRE(dilithium::GenerateKeyPair(kp));
    BOOST_CHECK_EQUAL(kp.public_key.size(), dilithium::PUBLIC_KEY_SIZE);
    BOOST_CHECK_EQUAL(kp.secret_key.size(), dilithium::SECRET_KEY_SIZE);

    // Two independently generated key pairs must differ.
    dilithium::KeyPair kp2;
    BOOST_REQUIRE(dilithium::GenerateKeyPair(kp2));
    BOOST_CHECK(kp.public_key != kp2.public_key);
}

BOOST_AUTO_TEST_CASE(dilithium_sign_and_verify)
{
    dilithium::KeyPair kp;
    BOOST_REQUIRE(dilithium::GenerateKeyPair(kp));

    const std::string message{"QubitCoin ($QBTC) quantum-resistant signature test"};

    dilithium::Signature sig;
    BOOST_REQUIRE(dilithium::Sign(StrSpan(message), kp.secret_key, sig));
    BOOST_CHECK(!sig.empty());
    BOOST_CHECK(sig.size() <= dilithium::SIGNATURE_MAX_SIZE);

    // A valid signature verifies against the original message and public key.
    BOOST_CHECK(dilithium::Verify(StrSpan(message), sig, kp.public_key));
}

BOOST_AUTO_TEST_CASE(dilithium_verify_fails_on_modified_message)
{
    dilithium::KeyPair kp;
    BOOST_REQUIRE(dilithium::GenerateKeyPair(kp));

    const std::string message{"the quick brown fox jumps over the lazy dog"};
    dilithium::Signature sig;
    BOOST_REQUIRE(dilithium::Sign(StrSpan(message), kp.secret_key, sig));

    // Flipping a byte of the message must break verification.
    const std::string tampered{"the quick brown fox jumps over the lazy d0g"};
    BOOST_CHECK(!dilithium::Verify(StrSpan(tampered), sig, kp.public_key));
}

BOOST_AUTO_TEST_CASE(dilithium_verify_fails_on_modified_signature)
{
    dilithium::KeyPair kp;
    BOOST_REQUIRE(dilithium::GenerateKeyPair(kp));

    const std::string message{"do not tamper with me"};
    dilithium::Signature sig;
    BOOST_REQUIRE(dilithium::Sign(StrSpan(message), kp.secret_key, sig));

    // Flip a bit in the signature.
    dilithium::Signature bad_sig = sig;
    bad_sig[bad_sig.size() / 2] ^= 0x01;
    BOOST_CHECK(!dilithium::Verify(StrSpan(message), bad_sig, kp.public_key));
}

BOOST_AUTO_TEST_CASE(dilithium_verify_fails_on_wrong_key)
{
    dilithium::KeyPair signer;
    dilithium::KeyPair other;
    BOOST_REQUIRE(dilithium::GenerateKeyPair(signer));
    BOOST_REQUIRE(dilithium::GenerateKeyPair(other));

    const std::string message{"signed by signer, verified against other"};
    dilithium::Signature sig;
    BOOST_REQUIRE(dilithium::Sign(StrSpan(message), signer.secret_key, sig));

    BOOST_CHECK(dilithium::Verify(StrSpan(message), sig, signer.public_key));
    BOOST_CHECK(!dilithium::Verify(StrSpan(message), sig, other.public_key));
}

// Phase 7 (Critical: key backup/recovery): deterministic key generation from a
// seed. The same seed must always reproduce the exact same key pair (this is what
// makes wallet funds recoverable from a single backed-up seed), while different
// seeds must produce different keys.
BOOST_AUTO_TEST_CASE(dilithium_keygen_from_seed_is_deterministic)
{
    std::vector<unsigned char> seed(dilithium::KEYGEN_SEED_SIZE, 0);
    for (size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<unsigned char>(i + 1);

    dilithium::KeyPair a, b;
    BOOST_REQUIRE(dilithium::GenerateKeyPairFromSeed(seed, a));
    BOOST_REQUIRE(dilithium::GenerateKeyPairFromSeed(seed, b));

    // Same seed -> identical public AND secret key.
    BOOST_CHECK(a.public_key == b.public_key);
    BOOST_CHECK(a.secret_key == b.secret_key);

    // The derived key is usable: sign with it and verify.
    const std::string message{"recoverable QBTC key"};
    dilithium::Signature sig;
    BOOST_REQUIRE(dilithium::Sign(StrSpan(message), a.secret_key, sig));
    BOOST_CHECK(dilithium::Verify(StrSpan(message), sig, a.public_key));

    // A different seed yields a different key.
    std::vector<unsigned char> seed2 = seed;
    seed2[0] ^= 0xff;
    dilithium::KeyPair c;
    BOOST_REQUIRE(dilithium::GenerateKeyPairFromSeed(seed2, c));
    BOOST_CHECK(a.public_key != c.public_key);

    // Wrong seed size is rejected.
    std::vector<unsigned char> short_seed(dilithium::KEYGEN_SEED_SIZE - 1, 0x42);
    dilithium::KeyPair d;
    BOOST_CHECK(!dilithium::GenerateKeyPairFromSeed(short_seed, d));
}

// Deterministic keygen must be safe interleaved with the randomized keygen path;
// the randomized path must remain random after a deterministic call.
BOOST_AUTO_TEST_CASE(dilithium_keygen_from_seed_restores_random_rng)
{
    std::vector<unsigned char> seed(dilithium::KEYGEN_SEED_SIZE, 0x07);
    dilithium::KeyPair det;
    BOOST_REQUIRE(dilithium::GenerateKeyPairFromSeed(seed, det));

    dilithium::KeyPair r1, r2;
    BOOST_REQUIRE(dilithium::GenerateKeyPair(r1));
    BOOST_REQUIRE(dilithium::GenerateKeyPair(r2));
    // Randomized keygen still produces independent keys (RNG was restored).
    BOOST_CHECK(r1.public_key != r2.public_key);
    BOOST_CHECK(r1.public_key != det.public_key);
}

BOOST_AUTO_TEST_CASE(dilithium_rejects_bad_input_sizes)
{
    dilithium::KeyPair kp;
    BOOST_REQUIRE(dilithium::GenerateKeyPair(kp));

    const std::string message{"size validation"};
    dilithium::Signature sig;
    BOOST_REQUIRE(dilithium::Sign(StrSpan(message), kp.secret_key, sig));

    // Wrong secret key size must be rejected by Sign().
    dilithium::SecretKey short_sk(kp.secret_key.begin(), kp.secret_key.end() - 1);
    dilithium::Signature sig2;
    BOOST_CHECK(!dilithium::Sign(StrSpan(message), short_sk, sig2));

    // Wrong public key size must be rejected by Verify().
    dilithium::PublicKey short_pk(kp.public_key.begin(), kp.public_key.end() - 1);
    BOOST_CHECK(!dilithium::Verify(StrSpan(message), sig, short_pk));

    // Empty signature must be rejected by Verify().
    dilithium::Signature empty_sig;
    BOOST_CHECK(!dilithium::Verify(StrSpan(message), empty_sig, kp.public_key));
}

BOOST_AUTO_TEST_SUITE_END()

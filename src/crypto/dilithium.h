// Copyright (c) 2026 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_DILITHIUM_H
#define BITCOIN_CRYPTO_DILITHIUM_H

#include <span.h>
#include <support/allocators/secure.h>

#include <cstddef>
#include <cstdint>
#include <vector>

/**
 * Thin C++ wrapper around the Open Quantum Safe (liboqs) implementation of the
 * ML-DSA (Dilithium) post-quantum signature scheme.
 *
 * QubitCoin uses ML-DSA-65 (a.k.a. Dilithium3, NIST security category 3) as its
 * default parameter set. This module only provides the raw cryptographic
 * primitives; it does NOT touch any of the existing ECDSA/Schnorr code paths.
 *
 * All functions are thread-safe. They return `false` on any failure (bad input
 * size, liboqs error, or liboqs support compiled out) rather than throwing.
 */
namespace dilithium {

//! Human readable liboqs algorithm identifier for the default parameter set.
inline constexpr const char* ALGORITHM_NAME = "ML-DSA-65";

//! Serialized size of an ML-DSA-65 public key, in bytes.
inline constexpr size_t PUBLIC_KEY_SIZE = 1952;

//! Serialized size of an ML-DSA-65 secret key, in bytes.
inline constexpr size_t SECRET_KEY_SIZE = 4032;

//! Serialized size of an ML-DSA-65 signature, in bytes.
//!
//! FIPS 204 ML-DSA signatures are fixed length: 3309 bytes for ML-DSA-65. liboqs
//! nominally reports this as an upper bound, but Sign() always emits exactly this
//! many bytes and Verify() requires exactly this many. The exact-length rule is
//! consensus critical (it is what makes a signature non-malleable in length), so
//! it is asserted here rather than inherited from liboqs' internals.
inline constexpr size_t SIGNATURE_MAX_SIZE = 3309;

using PublicKey = std::vector<unsigned char>;

//! Secret key bytes are held in cleansing (secure) storage so key material is
//! wiped from memory when the container is destroyed.
using SecretKey = std::vector<unsigned char, secure_allocator<unsigned char>>;

using Signature = std::vector<unsigned char>;

//! Size, in bytes, of the deterministic seed consumed by GenerateKeyPairFromSeed.
//! FIPS 204 ML-DSA key generation is fully determined by a 32-byte seed (xi).
inline constexpr size_t KEYGEN_SEED_SIZE = 32;

//! A freshly generated ML-DSA-65 key pair.
struct KeyPair {
    PublicKey public_key;
    SecretKey secret_key;
};

//! Returns true if this build was compiled with liboqs / Dilithium support.
bool IsAvailable() noexcept;

/**
 * Generate a fresh ML-DSA-65 key pair.
 *
 * @param[out] out  On success, populated with a new public/secret key pair.
 * @return true on success, false if key generation failed.
 */
bool GenerateKeyPair(KeyPair& out);

/**
 * Deterministically generate an ML-DSA-65 key pair from a fixed seed.
 *
 * QubitCoin uses this to make wallet keys recoverable from a single backed-up
 * secret (see CDilithiumKey and the wallet's Dilithium HD seed).
 *
 * DERIVATION, NORMATIVELY (this is wallet-recovery critical — an independent
 * implementation must reproduce it exactly or funds are unrecoverable):
 *
 *   1. A deterministic byte stream is defined as the concatenation of
 *          SHA256(seed || LE64(0)) || SHA256(seed || LE64(1)) || ...
 *   2. liboqs' ML-DSA-65 key generation is invoked with that stream as its
 *      randomness source. It draws exactly KEYGEN_SEED_SIZE bytes, so
 *      effectively
 *          xi = SHA256(seed || 0x0000000000000000)
 *   3. The key pair is FIPS 204 s5.1 ML-DSA.KeyGen_internal(xi).
 *
 * Step 3 is standard, but step 2 is NOT: liboqs (as of 0.14) exposes no
 * derandomised keygen, so xi is produced by the library drawing from the stream
 * rather than being handed to it. The mapping therefore depends on liboqs
 * consuming exactly 32 bytes, once, and using them directly as xi. That is
 * verified at runtime by SelfTest() against a pinned known-answer vector, and
 * this function refuses to derive anything if the vector does not match — a
 * silent change would otherwise make every existing wallet unrecoverable.
 *
 * This routine temporarily installs a process-global deterministic RNG in
 * liboqs, so it is serialized (together with GenerateKeyPair and Sign) behind an
 * internal mutex and is safe to call from multiple threads. Verification does
 * not consume randomness and is unaffected.
 *
 * @param[in]  seed  Exactly KEYGEN_SEED_SIZE bytes of key-derivation material.
 * @param[out] out   On success, the deterministically derived key pair.
 * @return true on success, false on error (wrong seed size, or KAT mismatch).
 */
bool GenerateKeyPairFromSeed(Span<const unsigned char> seed, KeyPair& out);

/**
 * Verify that the linked ML-DSA-65 implementation behaves as consensus and
 * wallet recovery assume. Intended to be called once during startup; a false
 * return should abort the node.
 *
 * Checks, in order:
 *   - liboqs support is compiled in and the algorithm is available,
 *   - the advertised key/signature sizes match our compile-time constants,
 *   - seeded key generation reproduces a pinned known-answer vector (this is
 *     what guards wallet recoverability across liboqs upgrades),
 *   - a fresh key signs and verifies, the signature is exactly
 *     SIGNATURE_MAX_SIZE bytes, and a single-bit mutation of it fails.
 */
bool SelfTest();

/**
 * Sign a message with an ML-DSA-65 secret key.
 *
 * @param[in]  message     The message bytes to sign.
 * @param[in]  secret_key  A secret key of exactly SECRET_KEY_SIZE bytes.
 * @param[out] sig_out     On success, the resulting signature.
 * @return true on success, false on error (e.g. wrong secret key size).
 */
bool Sign(Span<const unsigned char> message, Span<const unsigned char> secret_key, Signature& sig_out);

/**
 * Verify an ML-DSA-65 signature over a message.
 *
 * @param[in] message     The message bytes that were signed.
 * @param[in] signature   The candidate signature.
 * @param[in] public_key  A public key of exactly PUBLIC_KEY_SIZE bytes.
 * @return true if the signature is valid for (message, public_key), else false.
 */
bool Verify(Span<const unsigned char> message, Span<const unsigned char> signature, Span<const unsigned char> public_key);

} // namespace dilithium

#endif // BITCOIN_CRYPTO_DILITHIUM_H

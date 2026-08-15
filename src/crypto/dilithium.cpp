// Copyright (c) 2026 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <config/bitcoin-config.h> // IWYU pragma: keep

#include <crypto/dilithium.h>

#include <crypto/common.h>
#include <crypto/sha256.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <mutex>

#ifdef ENABLE_DILITHIUM
#include <oqs/oqs.h>
#endif

namespace dilithium {

#ifdef ENABLE_DILITHIUM

namespace {
//! Serializes all liboqs operations that consume randomness (key generation and
//! signing). GenerateKeyPairFromSeed temporarily swaps liboqs' process-global RNG
//! for a deterministic one; holding this mutex around every randomness-consuming
//! call guarantees no other thread observes that temporary RNG. Verification does
//! not draw randomness and therefore does not take this lock.
std::mutex g_rng_mutex;

//! Deterministic RNG state for the current GenerateKeyPairFromSeed call. Guarded
//! by g_rng_mutex (only ever set/read while the lock is held). The stream is
//! SHA256(seed || LE64(counter)) blocks concatenated, which fully determines the
//! ML-DSA key from the 32-byte seed.
struct DetRngState {
    std::array<uint8_t, KEYGEN_SEED_SIZE> seed{};
    uint64_t counter{0};
    std::array<uint8_t, 32> block{};
    size_t block_off{sizeof(block)}; // start exhausted so the first byte draws a block
    bool active{false};
} g_det_rng;

void DeterministicRandomBytes(uint8_t* out, size_t bytes_to_read)
{
    // Only reached while g_rng_mutex is held and g_det_rng.active is true.
    for (size_t i = 0; i < bytes_to_read; ++i) {
        if (g_det_rng.block_off >= g_det_rng.block.size()) {
            CSHA256 hasher;
            hasher.Write(g_det_rng.seed.data(), g_det_rng.seed.size());
            unsigned char ctr[8];
            WriteLE64(ctr, g_det_rng.counter++);
            hasher.Write(ctr, sizeof(ctr));
            hasher.Finalize(g_det_rng.block.data());
            g_det_rng.block_off = 0;
        }
        out[i] = g_det_rng.block[g_det_rng.block_off++];
    }
}

//! Process-wide, lazily initialized ML-DSA-65 handle.
//!
//! An OQS_SIG object is immutable after construction and every liboqs signature
//! entry point takes it as a `const` pointer, so a single shared instance is
//! safe to use concurrently from multiple threads. The function-local static
//! gives us thread-safe initialization; the handle is released at program exit.
const OQS_SIG* GetSig() noexcept
{
    static const struct SigHolder {
        OQS_SIG* sig{nullptr};
        SigHolder()
        {
            OQS_init();
            sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
        }
        ~SigHolder()
        {
            OQS_SIG_free(sig);
        }
    } holder;
    return holder.sig;
}
} // namespace

bool IsAvailable() noexcept
{
    return GetSig() != nullptr;
}

bool GenerateKeyPair(KeyPair& out)
{
    const OQS_SIG* sig = GetSig();
    if (sig == nullptr) return false;

    // Sanity check that the compile-time constants match the runtime library.
    if (sig->length_public_key != PUBLIC_KEY_SIZE || sig->length_secret_key != SECRET_KEY_SIZE) {
        return false;
    }

    PublicKey public_key(sig->length_public_key);
    SecretKey secret_key(sig->length_secret_key);

    {
        // Serialize with the deterministic-keygen path so the process-global RNG
        // is always the default "system" RNG while this (randomized) keygen runs.
        std::lock_guard<std::mutex> lock(g_rng_mutex);
        if (OQS_SIG_keypair(sig, public_key.data(), secret_key.data()) != OQS_SUCCESS) {
            return false;
        }
    }

    out.public_key = std::move(public_key);
    out.secret_key = std::move(secret_key);
    return true;
}

namespace {
//! Unchecked seeded keygen. Callers must go through GenerateKeyPairFromSeed(),
//! which additionally gates on the known-answer vector below.
bool GenerateKeyPairFromSeedUnchecked(Span<const unsigned char> seed, KeyPair& out)
{
    if (seed.size() != KEYGEN_SEED_SIZE) return false;

    const OQS_SIG* sig = GetSig();
    if (sig == nullptr) return false;
    if (sig->length_public_key != PUBLIC_KEY_SIZE || sig->length_secret_key != SECRET_KEY_SIZE) {
        return false;
    }

    PublicKey public_key(sig->length_public_key);
    SecretKey secret_key(sig->length_secret_key);

    OQS_STATUS rc;
    {
        std::lock_guard<std::mutex> lock(g_rng_mutex);
        // Install a deterministic RNG seeded from `seed`, generate, then restore
        // the default system RNG before releasing the lock so no other liboqs
        // consumer ever sees the deterministic RNG.
        g_det_rng = DetRngState{};
        std::memcpy(g_det_rng.seed.data(), seed.data(), KEYGEN_SEED_SIZE);
        g_det_rng.active = true;
        OQS_randombytes_custom_algorithm(&DeterministicRandomBytes);

        rc = OQS_SIG_keypair(sig, public_key.data(), secret_key.data());

        OQS_randombytes_switch_algorithm(OQS_RAND_alg_system);
        g_det_rng = DetRngState{}; // wipe seed material
    }
    if (rc != OQS_SUCCESS) return false;

    out.public_key = std::move(public_key);
    out.secret_key = std::move(secret_key);
    return true;
}

/**
 * SHA256 of the ML-DSA-65 public key derived from an all-zero 32-byte seed.
 *
 * This pins the seed -> key mapping documented in dilithium.h. It is not a FIPS
 * 204 test vector: it also captures how liboqs consumes our deterministic
 * randomness stream. Measured against liboqs 0.14.1-dev, whose ML-DSA-65 keygen
 * draws exactly 32 bytes and uses them as xi.
 *
 * If a liboqs upgrade changes that behaviour, every HD-derived wallet key would
 * silently change and existing wallets would become unrecoverable. Rather than
 * let that happen quietly, seeded key generation is refused outright until the
 * mapping is re-established and this vector deliberately updated.
 */
constexpr unsigned char SEEDED_KEYGEN_KAT_PUBKEY_SHA256[32] = {
    0x22, 0x32, 0x0b, 0x71, 0x9b, 0x79, 0x6d, 0xa8, 0x82, 0x22, 0x43, 0x44, 0x4a, 0x95, 0x4c, 0xb5,
    0x4f, 0xe8, 0x92, 0x4e, 0x4b, 0xa6, 0x4c, 0xdf, 0x43, 0xa8, 0x61, 0xcb, 0x8c, 0x25, 0xa7, 0x64,
};

//! Evaluate the seeded-keygen known-answer vector once per process and cache it.
bool SeededKeygenKatPasses()
{
    static const bool ok = [] {
        const std::array<unsigned char, KEYGEN_SEED_SIZE> seed{}; // all zeroes
        KeyPair kp;
        if (!GenerateKeyPairFromSeedUnchecked(Span<const unsigned char>(seed.data(), seed.size()), kp)) {
            return false;
        }
        if (kp.public_key.size() != PUBLIC_KEY_SIZE) return false;
        unsigned char digest[32];
        CSHA256().Write(kp.public_key.data(), kp.public_key.size()).Finalize(digest);
        return std::memcmp(digest, SEEDED_KEYGEN_KAT_PUBKEY_SHA256, sizeof(digest)) == 0;
    }();
    return ok;
}
} // namespace

bool GenerateKeyPairFromSeed(Span<const unsigned char> seed, KeyPair& out)
{
    // Refuse to derive keys at all if the pinned mapping no longer holds:
    // deriving the *wrong* key silently is far worse than failing loudly.
    if (!SeededKeygenKatPasses()) return false;
    return GenerateKeyPairFromSeedUnchecked(seed, out);
}

bool Sign(Span<const unsigned char> message, Span<const unsigned char> secret_key, Signature& sig_out)
{
    const OQS_SIG* sig = GetSig();
    if (sig == nullptr) return false;
    if (secret_key.size() != sig->length_secret_key) return false;

    Signature signature(sig->length_signature);
    size_t signature_len{0};

    // ML-DSA signing draws randomness (hedged signing); serialize with the
    // deterministic-keygen path so it never runs while the deterministic RNG is
    // installed.
    std::unique_lock<std::mutex> lock(g_rng_mutex);
    if (OQS_SIG_sign(sig, signature.data(), &signature_len,
                     message.data(), message.size(),
                     secret_key.data()) != OQS_SUCCESS) {
        return false;
    }
    lock.unlock();

    // ML-DSA-65 signatures are fixed length. Refuse to emit anything else rather
    // than hand back a blob that Verify() (and therefore consensus) would reject.
    if (signature_len != SIGNATURE_MAX_SIZE) return false;

    signature.resize(signature_len);
    sig_out = std::move(signature);
    return true;
}

bool Verify(Span<const unsigned char> message, Span<const unsigned char> signature, Span<const unsigned char> public_key)
{
    const OQS_SIG* sig = GetSig();
    if (sig == nullptr) return false;
    if (public_key.size() != sig->length_public_key) return false;

    // Consensus critical: require the exact FIPS 204 ML-DSA-65 signature length.
    //
    // liboqs' own verify rejects any other length (siglen != CRYPTO_BYTES), so
    // this is behaviour preserving today. It is asserted here so that the
    // non-malleability of the signature *length* is a QubitCoin consensus rule
    // rather than an internal invariant of a third-party library that a future
    // version, or an independent node implementation, might relax.
    if (signature.size() != SIGNATURE_MAX_SIZE) return false;
    if (signature.size() != sig->length_signature) return false;

    return OQS_SIG_verify(sig, message.data(), message.size(),
                          signature.data(), signature.size(),
                          public_key.data()) == OQS_SUCCESS;
}

bool SelfTest()
{
    const OQS_SIG* sig = GetSig();
    if (sig == nullptr) return false;

    // The runtime library must agree with our compile-time consensus constants.
    if (sig->length_public_key != PUBLIC_KEY_SIZE) return false;
    if (sig->length_secret_key != SECRET_KEY_SIZE) return false;
    if (sig->length_signature != SIGNATURE_MAX_SIZE) return false;

    // Wallet recoverability: the pinned seed -> key mapping must still hold.
    if (!SeededKeygenKatPasses()) return false;

    // Functional round trip on a fresh key, plus a negative case.
    KeyPair kp;
    if (!GenerateKeyPair(kp)) return false;

    std::array<unsigned char, 32> message{};
    for (size_t i = 0; i < message.size(); ++i) message[i] = static_cast<unsigned char>(i);

    Signature signature;
    if (!Sign(Span<const unsigned char>(message.data(), message.size()),
              Span<const unsigned char>(kp.secret_key.data(), kp.secret_key.size()),
              signature)) {
        return false;
    }
    if (signature.size() != SIGNATURE_MAX_SIZE) return false;
    if (!Verify(Span<const unsigned char>(message.data(), message.size()),
                Span<const unsigned char>(signature.data(), signature.size()),
                Span<const unsigned char>(kp.public_key.data(), kp.public_key.size()))) {
        return false;
    }

    signature[0] ^= 0x01;
    if (Verify(Span<const unsigned char>(message.data(), message.size()),
               Span<const unsigned char>(signature.data(), signature.size()),
               Span<const unsigned char>(kp.public_key.data(), kp.public_key.size()))) {
        return false; // a mutated signature must never verify
    }

    return true;
}

#else // !ENABLE_DILITHIUM

bool IsAvailable() noexcept { return false; }
bool GenerateKeyPair(KeyPair&) { return false; }
bool GenerateKeyPairFromSeed(Span<const unsigned char>, KeyPair&) { return false; }
bool Sign(Span<const unsigned char>, Span<const unsigned char>, Signature&) { return false; }
bool Verify(Span<const unsigned char>, Span<const unsigned char>, Span<const unsigned char>) { return false; }
bool SelfTest() { return false; }

#endif // ENABLE_DILITHIUM

} // namespace dilithium

// Copyright (c) 2026 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DILITHIUMKEY_H
#define BITCOIN_DILITHIUMKEY_H

#include <crypto/dilithium.h>
#include <dilithiumpubkey.h>
#include <span.h>
#include <support/allocators/secure.h>
#include <uint256.h>

#include <vector>

/**
 * An encapsulated post-quantum ML-DSA-65 (Dilithium3) private key.
 *
 * This is the QubitCoin analogue of Bitcoin's CKey. It wraps the liboqs-backed
 * key generation and signing primitives from src/crypto/dilithium.*.
 *
 * The secret key bytes (4032 bytes) are held in cleansing (secure) storage. The
 * corresponding public key is cached alongside because liboqs derives it during
 * key generation and it cannot be cheaply recomputed from the secret key alone.
 */
class CDilithiumKey
{
public:
    //! Serialized ML-DSA-65 secret key size (4032 bytes).
    static constexpr unsigned int SIZE = dilithium::SECRET_KEY_SIZE;

private:
    //! Secret key material in secure storage. Empty when invalid.
    dilithium::SecretKey keydata;

    //! Cached public key bytes (dilithium::PUBLIC_KEY_SIZE) matching keydata.
    std::vector<unsigned char> pubkeydata;

public:
    CDilithiumKey() = default;

    //! Check whether this private key is valid.
    bool IsValid() const { return keydata.size() == SIZE && pubkeydata.size() == dilithium::PUBLIC_KEY_SIZE; }

    //! Read-only vector-like interface to the secret key bytes.
    unsigned int size() const { return keydata.size(); }
    const unsigned char* data() const { return keydata.data(); }
    const unsigned char* begin() const { return keydata.data(); }
    const unsigned char* end() const { return keydata.data() + keydata.size(); }

    //! Generate a new ML-DSA-65 key pair using liboqs' CSPRNG.
    void MakeNewKey();

    //! Deterministically (re)generate this key pair from a 32-byte seed. The same
    //! seed always produces the same key, which is what makes QubitCoin wallets
    //! recoverable from a single backed-up secret. Invalidates on failure.
    void MakeNewKeyFromSeed(const uint256& seed);

    //! Load an existing key pair from raw secret + public key bytes. Returns
    //! false (and invalidates) on size mismatch.
    bool Set(Span<const unsigned char> secret, Span<const unsigned char> pubkey);

    //! The public key cached alongside the secret. This is a stored value, not a
    //! derivation: ML-DSA offers no way to recover the public key from the secret
    //! alone, so comparing it against a claimed public key proves nothing. Use
    //! VerifyPubKey() to check that the two actually belong together.
    CDilithiumPubKey GetPubKey() const;

    /**
     * Verify that this secret key really corresponds to `pubkey`.
     *
     * The QubitCoin analogue of CKey::VerifyPubKey(), and it works the same way:
     * sign a fresh random challenge with the secret and require that the
     * *supplied* public key verifies it. Nothing about the cached pubkeydata
     * takes part, so a record pairing one key's secret with another's public key
     * fails here even though it is structurally well-formed.
     *
     * A round trip is used rather than re-deriving the public key because
     * FIPS 204 secret keys do not carry t1, and liboqs exposes no key-recovery
     * routine. It costs one signature plus one verification (~150 us).
     */
    bool VerifyPubKey(const CDilithiumPubKey& pubkey) const;

    /**
     * Sign a 32-byte message hash (typically a transaction sighash) with this
     * ML-DSA-65 key. The resulting signature is variable length but bounded by
     * dilithium::SIGNATURE_MAX_SIZE. Returns false on failure.
     */
    bool Sign(const uint256& hash, std::vector<unsigned char>& vchSig) const;
};

//! Generate a fresh random Dilithium private key.
CDilithiumKey GenerateRandomDilithiumKey();

/**
 * Derive the per-index child seed for a wallet's Dilithium HD chain.
 *
 * QubitCoin does not use BIP32 (which is secp256k1-specific). Instead each
 * Dilithium key is derived deterministically from a single 32-byte wallet master
 * seed and a monotonically increasing child index:
 *
 *   child_seed(i) = HMAC-SHA256(key = master_seed, msg = "QBTC-ML-DSA-65-HD" || LE32(i))
 *
 * The child seed is then fed to CDilithiumKey::MakeNewKeyFromSeed(). Backing up
 * the master seed (and remembering the highest used index / doing a gap-limit
 * scan) is sufficient to recover every Dilithium key in the wallet.
 */
uint256 DeriveDilithiumChildSeed(const uint256& master_seed, uint32_t index);

#endif // BITCOIN_DILITHIUMKEY_H

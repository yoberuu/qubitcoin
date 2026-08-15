// Copyright (c) 2026 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DILITHIUMPUBKEY_H
#define BITCOIN_DILITHIUMPUBKEY_H

#include <crypto/dilithium.h>
#include <hash.h>
#include <pubkey.h> // for CKeyID
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <cstring>
#include <vector>

/**
 * An encapsulated post-quantum ML-DSA-65 (Dilithium3) public key.
 *
 * This is the QubitCoin analogue of Bitcoin's CPubKey, used on the consensus
 * signature-verification path. Unlike secp256k1 keys, ML-DSA public keys are a
 * fixed, large size (1952 bytes), so this class stores the raw bytes in a
 * std::vector rather than a small fixed buffer.
 *
 * A public key is considered "valid" (syntactically) iff it holds exactly SIZE
 * bytes. This mirrors CPubKey::IsValid() being consensus-observable via the
 * signature checker.
 */
class CDilithiumPubKey
{
public:
    //! Serialized ML-DSA-65 public key size (1952 bytes).
    static constexpr unsigned int SIZE = dilithium::PUBLIC_KEY_SIZE;

private:
    //! Raw public key bytes. Empty when invalid.
    std::vector<unsigned char> vch;

public:
    CDilithiumPubKey() = default;

    //! Initialize a public key using begin/end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend)
    {
        if (size_t(pend - pbegin) == SIZE) {
            vch.assign(reinterpret_cast<const unsigned char*>(&pbegin[0]),
                       reinterpret_cast<const unsigned char*>(&pbegin[0]) + SIZE);
        } else {
            vch.clear();
        }
    }

    //! Construct a public key using begin/end iterators to byte data.
    template <typename T>
    CDilithiumPubKey(const T pbegin, const T pend) { Set(pbegin, pend); }

    //! Construct a public key from a byte span.
    explicit CDilithiumPubKey(Span<const uint8_t> _vch) { Set(_vch.begin(), _vch.end()); }

    //! Read-only vector-like interface.
    unsigned int size() const { return vch.size(); }
    const unsigned char* data() const { return vch.data(); }
    const unsigned char* begin() const { return vch.data(); }
    const unsigned char* end() const { return vch.data() + vch.size(); }
    const unsigned char& operator[](unsigned int pos) const { return vch[pos]; }

    friend bool operator==(const CDilithiumPubKey& a, const CDilithiumPubKey& b) { return a.vch == b.vch; }
    friend bool operator!=(const CDilithiumPubKey& a, const CDilithiumPubKey& b) { return a.vch != b.vch; }
    friend bool operator<(const CDilithiumPubKey& a, const CDilithiumPubKey& b) { return a.vch < b.vch; }

    //! Check syntactic correctness (correct length). Consensus critical, as
    //! CheckDilithiumSignature() relies on it.
    bool IsValid() const { return vch.size() == SIZE; }

    //! Get the KeyID (Hash160) of this public key, e.g. for P2PKH-style scripts.
    CKeyID GetID() const { return CKeyID(Hash160(vch)); }

    //! Get the 256-bit hash of this public key.
    uint256 GetHash() const { return Hash(vch); }

    /**
     * Verify an ML-DSA-65 signature over a 32-byte message hash (typically a
     * transaction sighash). Returns false if the key is invalid.
     */
    bool Verify(const uint256& hash, Span<const unsigned char> vchSig) const;

    //! Serialize as a byte vector with a CompactSize length prefix (like CPubKey).
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::WriteCompactSize(s, vch.size());
        if (!vch.empty()) s << Span{vch};
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const unsigned int len(::ReadCompactSize(s));
        if (len == SIZE) {
            vch.resize(SIZE);
            s >> Span{vch};
        } else {
            s.ignore(len);
            vch.clear();
        }
    }
};

#endif // BITCOIN_DILITHIUMPUBKEY_H

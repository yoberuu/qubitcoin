// Copyright (c) 2026 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dilithiumkey.h>

#include <crypto/common.h>
#include <crypto/dilithium.h>
#include <crypto/hmac_sha256.h>
#include <hash.h>
#include <random.h>

#include <cstring>
#include <string>

void CDilithiumKey::MakeNewKey()
{
    dilithium::KeyPair kp;
    if (!dilithium::GenerateKeyPair(kp)) {
        keydata.clear();
        pubkeydata.clear();
        return;
    }
    keydata = std::move(kp.secret_key);
    pubkeydata.assign(kp.public_key.begin(), kp.public_key.end());
}

void CDilithiumKey::MakeNewKeyFromSeed(const uint256& seed)
{
    dilithium::KeyPair kp;
    if (!dilithium::GenerateKeyPairFromSeed(Span<const unsigned char>(seed.data(), seed.size()), kp)) {
        keydata.clear();
        pubkeydata.clear();
        return;
    }
    keydata = std::move(kp.secret_key);
    pubkeydata.assign(kp.public_key.begin(), kp.public_key.end());
}

bool CDilithiumKey::Set(Span<const unsigned char> secret, Span<const unsigned char> pubkey)
{
    if (secret.size() != SIZE || pubkey.size() != dilithium::PUBLIC_KEY_SIZE) {
        keydata.clear();
        pubkeydata.clear();
        return false;
    }
    keydata.assign(secret.begin(), secret.end());
    pubkeydata.assign(pubkey.begin(), pubkey.end());
    return true;
}

CDilithiumPubKey CDilithiumKey::GetPubKey() const
{
    if (!IsValid()) return CDilithiumPubKey();
    return CDilithiumPubKey(pubkeydata.begin(), pubkeydata.end());
}

bool CDilithiumKey::VerifyPubKey(const CDilithiumPubKey& pubkey) const
{
    if (!IsValid() || !pubkey.IsValid()) return false;

    // Random challenge, so a stale or replayed signature cannot stand in for
    // proof that this secret matches this public key.
    unsigned char rnd[8];
    const std::string str = "QubitCoin ML-DSA-65 key verification\n";
    GetRandBytes(rnd);
    const uint256 hash{Hash(str, rnd)};

    std::vector<unsigned char> vchSig;
    if (!Sign(hash, vchSig)) return false;
    return pubkey.Verify(hash, vchSig);
}

bool CDilithiumKey::Sign(const uint256& hash, std::vector<unsigned char>& vchSig) const
{
    if (!IsValid()) return false;
    dilithium::Signature sig;
    if (!dilithium::Sign(Span<const unsigned char>(hash.data(), hash.size()),
                         Span<const unsigned char>(keydata.data(), keydata.size()),
                         sig)) {
        return false;
    }
    vchSig = std::move(sig);
    return true;
}

CDilithiumKey GenerateRandomDilithiumKey()
{
    CDilithiumKey key;
    key.MakeNewKey();
    return key;
}

uint256 DeriveDilithiumChildSeed(const uint256& master_seed, uint32_t index)
{
    // Domain-separated PRF: HMAC-SHA256(master_seed, "QBTC-ML-DSA-65-HD" || LE32(index)).
    static const unsigned char LABEL[] = "QBTC-ML-DSA-65-HD";
    CHMAC_SHA256 hmac(master_seed.data(), master_seed.size());
    hmac.Write(LABEL, sizeof(LABEL) - 1); // exclude the trailing NUL
    unsigned char idx[4];
    WriteLE32(idx, index);
    hmac.Write(idx, sizeof(idx));
    uint256 out;
    hmac.Finalize(out.data());
    return out;
}

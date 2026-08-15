// Copyright (c) 2026 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dilithiumpubkey.h>

#include <crypto/dilithium.h>
#include <span.h>

bool CDilithiumPubKey::Verify(const uint256& hash, Span<const unsigned char> vchSig) const
{
    if (!IsValid()) return false;
    return dilithium::Verify(
        Span<const unsigned char>(hash.data(), hash.size()),
        vchSig,
        Span<const unsigned char>(vch.data(), vch.size()));
}

// Copyright (c) 2026 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <crypto/dilithium.h>
#include <dilithiumkey.h>
#include <dilithiumpubkey.h>
#include <hash.h>
#include <key.h>
#include <uint256.h>

#include <cassert>
#include <vector>

/**
 * Microbenchmark: ML-DSA-65 (Dilithium3) verification cost on this build.
 *
 * Used to justify DILITHIUM_VERIFY_SIGOP_COST relative to ECDSA. Run with:
 *   ./src/bench/bench_bitcoin -filter='Dilithium.*|ECDSA.*'
 */
static void DilithiumVerify(benchmark::Bench& bench)
{
    CDilithiumKey key = GenerateRandomDilithiumKey();
    const CDilithiumPubKey pubkey = key.GetPubKey();
    const uint256 hash = Hash(std::vector<unsigned char>{1, 2, 3, 4, 5, 6, 7, 8});
    std::vector<unsigned char> sig;
    assert(key.Sign(hash, sig));

    bench.run([&] {
        assert(pubkey.Verify(hash, sig));
    });
}

static void ECDSAVerify(benchmark::Bench& bench)
{
    ECC_Context ecc{};
    CKey key = GenerateRandomKey();
    const CPubKey pubkey = key.GetPubKey();
    const uint256 hash = Hash(std::vector<unsigned char>{1, 2, 3, 4, 5, 6, 7, 8});
    std::vector<unsigned char> sig;
    assert(key.Sign(hash, sig));

    bench.run([&] {
        assert(pubkey.Verify(hash, sig));
    });
}

BENCHMARK(DilithiumVerify, benchmark::PriorityLevel::HIGH);
BENCHMARK(ECDSAVerify, benchmark::PriorityLevel::HIGH);

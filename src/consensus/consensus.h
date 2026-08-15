// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <cstdlib>
#include <stdint.h>

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 4000000;
/** The maximum allowed weight for a block, see BIP 141 (network rule) */
static const unsigned int MAX_BLOCK_WEIGHT = 4000000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const int64_t MAX_BLOCK_SIGOPS_COST = 80000;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;

static const int WITNESS_SCALE_FACTOR = 4;

/**
 * QubitCoin post-quantum verification-cost accounting (network rule).
 *
 * Every OP_CHECKSIG/OP_CHECKSIGVERIFY that executes on this chain performs a
 * Dilithium (ML-DSA-65) verification. Bitcoin's legacy sigop accounting only
 * charges a transaction for the CHECKSIG opcodes in its own outputs and
 * scriptSigs, so a transaction that *spends* many pre-existing outputs would be
 * almost free while forcing O(inputs) verifications at validation time — a DoS
 * vector.
 *
 * To account for that cost we charge each executed verification (counted from
 * the prevout being spent) this many additional legacy-sigop-equivalent units, in
 * GetTransactionSigOpCost(). This is expressed in pre-WITNESS_SCALE_FACTOR units;
 * the per-verification cost folded into the block sigop budget is therefore
 * DILITHIUM_VERIFY_SIGOP_COST * WITNESS_SCALE_FACTOR.
 *
 * Chosen value (5): microbenchmarks of liboqs ML-DSA-65 Verify vs libsecp256k1
 * ECDSA Verify on this codebase's host (~42 µs vs ~30 µs, ~1.4×) show Dilithium
 * verify is only modestly slower than ECDSA — not the ~50× implied by an earlier
 * placeholder. We round up from ~1.4× to 5× ECDSA-equivalent to cover slower
 * platforms (no AVX2, cold caches, interpreter overhead) while still reflecting
 * measured CPU cost. See bench/dilithium.cpp and dilithium_ecdsa_audit_suite.
 *
 * With cost=5, MAX_BLOCK_SIGOPS_COST allows 80000/(5*4) = 4000 Dilithium
 * verifications per block, and MAX_STANDARD_TX_SIGOPS_COST allows ~800 per
 * standard tx. In practice ~5.3 kB Dilithium inputs make block/tx *weight* the
 * tighter limit (~188 inputs/block, ~18/standard tx), and policy also caps
 * Dilithium inputs per relayed tx (MAX_STANDARD_DILITHIUM_INPUTS). This constant
 * remains defense-in-depth plus a fee signal via GetVirtualTransactionSize.
 */
static const int64_t DILITHIUM_VERIFY_SIGOP_COST = 5;

static const size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60; // 60 is the lower bound for the size of a valid serialized CTransaction
static const size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10; // 10 is the lower bound for the size of a serialized CTransaction

/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
static constexpr unsigned int LOCKTIME_VERIFY_SEQUENCE = (1 << 0);

/**
 * Maximum number of seconds that the timestamp of the first
 * block of a difficulty adjustment period is allowed to
 * be earlier than the last block of the previous period (BIP94).
 */
static constexpr int64_t MAX_TIMEWARP = 600;

#endif // BITCOIN_CONSENSUS_CONSENSUS_H

// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_POLICY_H
#define BITCOIN_POLICY_POLICY_H

#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <crypto/dilithium.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/solver.h>

#include <cstddef>
#include <cstdint>
#include <string>

class CCoinsViewCache;
class CFeeRate;
class CScript;
class CTransaction;

/**
 * QubitCoin: canonical worst-case sizes of a post-quantum (ML-DSA-65) spend.
 *
 * Every spend on this chain satisfies OP_CHECKSIG with a 3309-byte Dilithium
 * signature plus its 1-byte sighash type, and a 1952-byte Dilithium public key.
 * Both lengths are fixed by FIPS 204, so unlike ECDSA these sizes are exact
 * rather than upper bounds: there is no low-r grinding and no key compression,
 * and a signed input is never smaller than the numbers below.
 *
 * Two shapes are both consensus-valid and relayable, and they differ ~3.9x in
 * weight because segwit discounts witness bytes 4:1:
 *
 *   bare    TxoutType::PUBKEYHASH         both elements in the scriptSig
 *   witness TxoutType::WITNESS_V0_KEYHASH both elements in the witness
 *
 * The witness form is the efficient one and is what dust and fee estimation
 * should reward. (A P2WSH-shaped Dilithium spend is consensus-valid too, but
 * non-standard: the 3310-byte signature element exceeds
 * MAX_STANDARD_P2WSH_STACK_ITEM_SIZE. P2SH-wrapping either form only adds the
 * redeemScript, so it is never cheaper than the shapes above.)
 *
 * A script push and a witness-element CompactSize both cost 3 bytes of prefix
 * for the element sizes involved here (OP_PUSHDATA2 / 0xfd + uint16), which is
 * why the two encodings below share the same element overhead.
 */
/** Signature element pushed by a Dilithium spend: the signature + sighash byte. */
static constexpr size_t DILITHIUM_SIG_ELEMENT_SIZE{dilithium::SIGNATURE_MAX_SIZE + 1};
/** Public key element pushed by a Dilithium spend. */
static constexpr size_t DILITHIUM_PUBKEY_ELEMENT_SIZE{dilithium::PUBLIC_KEY_SIZE};
/** scriptSig of a bare Dilithium P2PKH spend: push(sig) push(pubkey). */
static constexpr size_t DILITHIUM_P2PKH_SCRIPTSIG_SIZE{(3 + DILITHIUM_SIG_ELEMENT_SIZE) +
                                                       (3 + DILITHIUM_PUBKEY_ELEMENT_SIZE)};
/** Serialized bare Dilithium P2PKH input: outpoint + scriptSig + nSequence. */
static constexpr size_t DILITHIUM_P2PKH_INPUT_SIZE{32 + 4 + 3 + DILITHIUM_P2PKH_SCRIPTSIG_SIZE + 4};
/** Weight of a bare Dilithium P2PKH input (no witness, so 4x the byte size). */
static constexpr int64_t DILITHIUM_P2PKH_INPUT_WEIGHT{int64_t{DILITHIUM_P2PKH_INPUT_SIZE} * WITNESS_SCALE_FACTOR};
/** Virtual size of a bare Dilithium P2PKH input (equals its byte size). */
static constexpr size_t DILITHIUM_P2PKH_INPUT_VSIZE{DILITHIUM_P2PKH_INPUT_SIZE};
/** Witness of a Dilithium P2WPKH spend: stack count + sig element + pubkey element. */
static constexpr size_t DILITHIUM_P2WPKH_WITNESS_SIZE{1 + (3 + DILITHIUM_SIG_ELEMENT_SIZE) +
                                                      (3 + DILITHIUM_PUBKEY_ELEMENT_SIZE)};
/** Non-witness part of a Dilithium P2WPKH input: outpoint + empty scriptSig + nSequence. */
static constexpr size_t DILITHIUM_P2WPKH_INPUT_NONWITNESS_SIZE{32 + 4 + 1 + 4};
/** Weight of a witness Dilithium P2WPKH input: the witness bytes are discounted 4:1. */
static constexpr int64_t DILITHIUM_P2WPKH_INPUT_WEIGHT{
    int64_t{DILITHIUM_P2WPKH_INPUT_NONWITNESS_SIZE} * WITNESS_SCALE_FACTOR + int64_t{DILITHIUM_P2WPKH_WITNESS_SIZE}};
/** Virtual size of a witness Dilithium P2WPKH input (weight rounded up). */
static constexpr size_t DILITHIUM_P2WPKH_INPUT_VSIZE{
    (DILITHIUM_P2WPKH_INPUT_WEIGHT + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR};

static_assert(DILITHIUM_P2PKH_INPUT_SIZE == 5311);
static_assert(DILITHIUM_P2PKH_INPUT_WEIGHT == 21244);
static_assert(DILITHIUM_P2WPKH_INPUT_WEIGHT == 5433);
static_assert(DILITHIUM_P2WPKH_INPUT_VSIZE == 1359);

/** Default for -blockmaxweight, which controls the range of block weights the mining code will create **/
static constexpr unsigned int DEFAULT_BLOCK_MAX_WEIGHT{MAX_BLOCK_WEIGHT - 4000};
/** Default for -blockmintxfee, which sets the minimum feerate for a transaction in blocks created by mining code **/
static constexpr unsigned int DEFAULT_BLOCK_MIN_TX_FEE{1000};
/** The maximum weight for transactions we're willing to relay/mine.
 *
 * QubitCoin note: a post-quantum Dilithium input weighs 21,244 WU in the bare
 * form and 5,433 WU in the witness form (see above), versus a few hundred for an
 * ECDSA input. Bitcoin's 400,000 limit therefore admits 18 bare or 73 witness
 * Dilithium inputs in one standard transaction, which covers ordinary payments
 * and reasonable consolidations. It was left unchanged: it is a relay-level DoS
 * parameter, and raising it interacts with coin-selection weight bounding and
 * mempool ancestor/descendant sizing. It is also the constraint that prices
 * Dilithium verification cost at relay (see MAX_STANDARD_DILITHIUM_INPUTS). */
static constexpr int32_t MAX_STANDARD_TX_WEIGHT{400000};
/** The minimum non-witness size for transactions we're willing to relay/mine: one larger than 64  */
static constexpr unsigned int MIN_STANDARD_TX_NONWITNESS_SIZE{65};
/** Maximum number of signature check operations in an IsStandard() P2SH script */
static constexpr unsigned int MAX_P2SH_SIGOPS{15};
/** The maximum number of sigops we're willing to relay/mine in a single tx */
static constexpr unsigned int MAX_STANDARD_TX_SIGOPS_COST{MAX_BLOCK_SIGOPS_COST/5};
/** Default for -incrementalrelayfee, which sets the minimum feerate increase for mempool limiting or replacement **/
static constexpr unsigned int DEFAULT_INCREMENTAL_RELAY_FEE{1000};
/** Default for -bytespersigop */
static constexpr unsigned int DEFAULT_BYTES_PER_SIGOP{20};
/** Default for -permitbaremultisig */
static constexpr bool DEFAULT_PERMIT_BAREMULTISIG{true};
/** The maximum number of witness stack items in a standard P2WSH script */
static constexpr unsigned int MAX_STANDARD_P2WSH_STACK_ITEMS{100};
/** The maximum size in bytes of each witness stack item in a standard P2WSH script */
static constexpr unsigned int MAX_STANDARD_P2WSH_STACK_ITEM_SIZE{80};
/** The maximum size in bytes of each witness stack item in a standard BIP 342 script (Taproot, leaf version 0xc0) */
static constexpr unsigned int MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE{80};
/** The maximum size in bytes of a standard witnessScript */
static constexpr unsigned int MAX_STANDARD_P2WSH_SCRIPT_SIZE{3600};
/** The maximum size of a standard ScriptSig.
 *
 * QubitCoin note: Bitcoin uses 1650 (large enough for a 15-of-15 P2SH multisig).
 * A post-quantum Dilithium P2PKH spend pushes a ~3310-byte signature plus a
 * 1952-byte public key onto the scriptSig (~5.3 KB with push overhead), so this
 * limit is raised to 8000 so such transactions are relayed as standard. This is
 * a policy/relay change only (not consensus). */
static constexpr unsigned int MAX_STANDARD_SCRIPTSIG_SIZE{8000};
/**
 * Least weight a standard transaction can pay per ML-DSA-65 verification.
 *
 * A verification needs both the signature and the public key on the stack, so
 * the cheapest standard shape that can demand one is a witness P2WPKH spend.
 * Every other standard shape (bare P2PKH, or either form P2SH-wrapped) is
 * strictly heavier.
 */
static constexpr int64_t MIN_STANDARD_DILITHIUM_VERIFY_WEIGHT{DILITHIUM_P2WPKH_INPUT_WEIGHT};
/**
 * Maximum number of Dilithium-looking inputs in a standard (relayed) transaction.
 *
 * Policy only — not consensus: the consensus layer still accepts such a
 * transaction in a mined block.
 *
 * Weight, not CPU, is what actually prices post-quantum verification here. Each
 * verification drags at least MIN_STANDARD_DILITHIUM_VERIFY_WEIGHT of relayed
 * weight behind it, and MAX_STANDARD_TX_WEIGHT already bounds that: 18 bare or
 * 73 witness inputs. The CPU those imply is negligible (73 x ~43 us is ~3 ms,
 * against the ~500 ms a full Bitcoin block of ECDSA verifications costs), so
 * there is no CPU-derived number that would bind sooner than weight does.
 *
 * This cap is therefore derived from the weight ceiling and the cheapest spend
 * form rather than picked by hand. Two properties follow, and they are why it
 * replaced a hand-tuned count of 15:
 *
 *  - Form-neutral. It never penalises the efficient (witness) form. The old
 *    fixed 15 was drawn from bare-P2PKH intuition and would have thrown away
 *    most of the witness form's 4x weight advantage.
 *  - Unbypassable. Together, the cap and MAX_STANDARD_TX_WEIGHT bound
 *    verifications per standard transaction no matter what shape is used: a
 *    shape at or above the minimum verify weight is bounded by weight, and one
 *    below it (something carrying a Dilithium key more cheaply than a real
 *    P2WPKH spend) is bounded by this count. Counting covers scriptSig pushes,
 *    P2SH redeemScript / P2WSH witnessScript nesting, and witness stack items,
 *    so no shape escapes being counted in the first place.
 *
 * Caveat, at consensus level rather than relay: GetTransactionSigOpCost charges
 * the Dilithium sigop surcharge only for CHECKSIGs in the prevout scriptPubKey,
 * so witness and P2SH verifications are under-charged there. That is a separate
 * consensus question and is not what this relay bound is doing.
 */
static constexpr unsigned int MAX_STANDARD_DILITHIUM_INPUTS{
    static_cast<unsigned int>(MAX_STANDARD_TX_WEIGHT / MIN_STANDARD_DILITHIUM_VERIFY_WEIGHT)};
/** Min feerate for defining dust.
 * Changing the dust limit changes which transactions are
 * standard and should be done with care and ideally rarely. It makes sense to
 * only increase the dust limit after prior releases were already not creating
 * outputs below the new threshold */
static constexpr unsigned int DUST_RELAY_TX_FEE{3000};
/** Default for -minrelaytxfee, minimum relay fee for transactions */
static constexpr unsigned int DEFAULT_MIN_RELAY_TX_FEE{1000};
/** Default for -limitancestorcount, max number of in-mempool ancestors */
static constexpr unsigned int DEFAULT_ANCESTOR_LIMIT{25};
/** Default for -limitancestorsize, maximum kilobytes of tx + all in-mempool ancestors */
static constexpr unsigned int DEFAULT_ANCESTOR_SIZE_LIMIT_KVB{101};
/** Default for -limitdescendantcount, max number of in-mempool descendants */
static constexpr unsigned int DEFAULT_DESCENDANT_LIMIT{25};
/** Default for -limitdescendantsize, maximum kilobytes of in-mempool descendants */
static constexpr unsigned int DEFAULT_DESCENDANT_SIZE_LIMIT_KVB{101};
/** Default for -datacarrier */
static const bool DEFAULT_ACCEPT_DATACARRIER = true;
/**
 * Default setting for -datacarriersize. 80 bytes of data, +1 for OP_RETURN,
 * +2 for the pushdata opcodes.
 */
static const unsigned int MAX_OP_RETURN_RELAY = 83;
/**
 * An extra transaction can be added to a package, as long as it only has one
 * ancestor and is no larger than this. Not really any reason to make this
 * configurable as it doesn't materially change DoS parameters.
 */
static constexpr unsigned int EXTRA_DESCENDANT_TX_SIZE_LIMIT{10000};


/**
 * Mandatory script verification flags that all new transactions must comply with for
 * them to be valid. Failing one of these tests may trigger a DoS ban;
 * see CheckInputScripts() for details.
 *
 * Note that this does not affect consensus validity; see GetBlockScriptFlags()
 * for that.
 */
static constexpr unsigned int MANDATORY_SCRIPT_VERIFY_FLAGS{SCRIPT_VERIFY_P2SH |
                                                             SCRIPT_VERIFY_DERSIG |
                                                             SCRIPT_VERIFY_NULLDUMMY |
                                                             SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                                                             SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
                                                             SCRIPT_VERIFY_WITNESS |
                                                             SCRIPT_VERIFY_TAPROOT};

/**
 * Standard script verification flags that standard transactions will comply
 * with. However we do not ban/disconnect nodes that forward txs violating
 * the additional (non-mandatory) rules here, to improve forwards and
 * backwards compatibility.
 */
static constexpr unsigned int STANDARD_SCRIPT_VERIFY_FLAGS{MANDATORY_SCRIPT_VERIFY_FLAGS |
                                                             SCRIPT_VERIFY_STRICTENC |
                                                             SCRIPT_VERIFY_MINIMALDATA |
                                                             SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
                                                             SCRIPT_VERIFY_CLEANSTACK |
                                                             SCRIPT_VERIFY_MINIMALIF |
                                                             SCRIPT_VERIFY_NULLFAIL |
                                                             SCRIPT_VERIFY_LOW_S |
                                                             SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |
                                                             SCRIPT_VERIFY_WITNESS_PUBKEYTYPE |
                                                             SCRIPT_VERIFY_CONST_SCRIPTCODE |
                                                             SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |
                                                             SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS |
                                                             SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE};

/** For convenience, standard but not mandatory verify flags. */
static constexpr unsigned int STANDARD_NOT_MANDATORY_VERIFY_FLAGS{STANDARD_SCRIPT_VERIFY_FLAGS & ~MANDATORY_SCRIPT_VERIFY_FLAGS};

/** Used as the flags parameter to sequence and nLocktime checks in non-consensus code. */
static constexpr unsigned int STANDARD_LOCKTIME_VERIFY_FLAGS{LOCKTIME_VERIFY_SEQUENCE};

CAmount GetDustThreshold(const CTxOut& txout, const CFeeRate& dustRelayFee);

bool IsDust(const CTxOut& txout, const CFeeRate& dustRelayFee);

bool IsStandard(const CScript& scriptPubKey, const std::optional<unsigned>& max_datacarrier_bytes, TxoutType& whichType);

/**
 * Number of inputs of `tx` that carry an ML-DSA-65 public key, and so can demand
 * a Dilithium verification. Bounded by MAX_STANDARD_DILITHIUM_INPUTS in
 * IsStandardTx(); exposed so the counting itself can be tested directly.
 */
unsigned int CountDilithiumSpendInputs(const CTransaction& tx);


// Changing the default transaction version requires a two step process: first
// adapting relay policy by bumping TX_MAX_STANDARD_VERSION, and then later
// allowing the new transaction version in the wallet/RPC.
static constexpr decltype(CTransaction::version) TX_MAX_STANDARD_VERSION{3};

/**
* Check for standard transaction types
* @return True if all outputs (scriptPubKeys) use only standard transaction forms
*/
bool IsStandardTx(const CTransaction& tx, const std::optional<unsigned>& max_datacarrier_bytes, bool permit_bare_multisig, const CFeeRate& dust_relay_fee, std::string& reason);
/**
* Check for standard transaction types
* @param[in] mapInputs       Map of previous transactions that have outputs we're spending
* @return True if all inputs (scriptSigs) use only standard transaction forms
*/
bool AreInputsStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs);
/**
* Check if the transaction is over standard P2WSH resources limit:
* 3600bytes witnessScript size, 80bytes per witness stack element, 100 witness stack elements
* These limits are adequate for multisignatures up to n-of-100 using OP_CHECKSIG, OP_ADD, and OP_EQUAL.
*
* Also enforce a maximum stack item size limit and no annexes for tapscript spends.
*/
bool IsWitnessStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs);

/** Compute the virtual transaction size (weight reinterpreted as bytes). */
int64_t GetVirtualTransactionSize(int64_t nWeight, int64_t nSigOpCost, unsigned int bytes_per_sigop);
int64_t GetVirtualTransactionSize(const CTransaction& tx, int64_t nSigOpCost, unsigned int bytes_per_sigop);
int64_t GetVirtualTransactionInputSize(const CTxIn& tx, int64_t nSigOpCost, unsigned int bytes_per_sigop);

static inline int64_t GetVirtualTransactionSize(const CTransaction& tx)
{
    return GetVirtualTransactionSize(tx, 0, 0);
}

static inline int64_t GetVirtualTransactionInputSize(const CTxIn& tx)
{
    return GetVirtualTransactionInputSize(tx, 0, 0);
}

#endif // BITCOIN_POLICY_POLICY_H

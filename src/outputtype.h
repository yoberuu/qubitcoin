// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OUTPUTTYPE_H
#define BITCOIN_OUTPUTTYPE_H

#include <addresstype.h>
#include <script/signingprovider.h>

#include <array>
#include <optional>
#include <string>
#include <vector>

enum class OutputType {
    LEGACY,
    P2SH_SEGWIT,
    BECH32,
    BECH32M,
    //! QubitCoin post-quantum: P2PKH-style output backed by a Dilithium (ML-DSA-65) key.
    DILITHIUM,
    UNKNOWN,
};

// Note: DILITHIUM is deliberately excluded here. OUTPUT_TYPES enumerates the
// descriptor-capable output types iterated during descriptor wallet setup and
// "all address types" loops. Post-quantum Dilithium is served only by the legacy
// ScriptPubKeyMan (see LEGACY_OUTPUT_TYPES) and is selected explicitly.
static constexpr auto OUTPUT_TYPES = std::array{
    OutputType::LEGACY,
    OutputType::P2SH_SEGWIT,
    OutputType::BECH32,
    OutputType::BECH32M,
};

std::optional<OutputType> ParseOutputType(const std::string& str);
const std::string& FormatOutputType(OutputType type);

/**
 * Get a destination of the requested type (if possible) to the specified key.
 * The caller must make sure LearnRelatedScripts has been called beforehand.
 */
CTxDestination GetDestinationForKey(const CPubKey& key, OutputType);

/** Get all destinations (potentially) supported by the wallet for the given key. */
std::vector<CTxDestination> GetAllDestinationsForKey(const CPubKey& key);

/**
 * Get a destination of the requested type (if possible) to the specified script.
 * This function will automatically add the script (and any other
 * necessary scripts) to the keystore.
 */
CTxDestination AddAndGetDestinationForScript(FlatSigningProvider& keystore, const CScript& script, OutputType);

/** Get the OutputType for a CTxDestination */
std::optional<OutputType> OutputTypeFromDestination(const CTxDestination& dest);

/**
 * Keep leftover ECDSA encoding when a descriptor still names LEGACY.
 *
 * ExtractDestination maps every P2PKH script to DilithiumPKHash so on-chain
 * RPCs match getnewaddress. pkh() and addr(<ECDSA P2PKH>) still mean an
 * unspendable destination; encoding those as Dilithium would make
 * deriveaddresses mint a payable-looking address that burns the funds.
 */
CTxDestination PreserveDescriptorAddressType(CTxDestination extracted, std::optional<OutputType> type);

#endif // BITCOIN_OUTPUTTYPE_H

// Copyright (c) 2026 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * QubitCoin address burn-hazard tests.
 *
 * Only ML-DSA-65 signatures verify on this chain, so every address type
 * inherited from Bitcoin is a permanent burn if it is paid. These tests pin the
 * classification that the send paths rely on, and the property that forces the
 * check to live at the address layer rather than the script layer.
 *
 *   ./src/test/test_bitcoin --run_test=dilithium_address_tests
 */

#include <addresstype.h>
#include <chainparams.h>
#include <dilithiumkey.h>
#include <dilithiumpubkey.h>
#include <hash.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <pubkey.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <algorithm>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(dilithium_address_tests, BasicTestingSetup)

/**
 * Exactly one destination type is spendable here. Every alternative of
 * CTxDestination is listed so that adding a type without deciding whether it
 * can be paid is not possible: the visitor stops compiling, and this case stops
 * covering everything.
 */
BOOST_AUTO_TEST_CASE(dilithium_is_the_only_spendable_destination_type)
{
    const CDilithiumKey dil_key = GenerateRandomDilithiumKey();
    CKey ecdsa_key;
    ecdsa_key.MakeNewKey(/*fCompressedIn=*/true);
    const CPubKey ecdsa_pub = ecdsa_key.GetPubKey();
    const CScript script = CScript() << OP_TRUE;

    const std::vector<std::pair<CTxDestination, std::string>> unspendable{
        {CNoDestination{script}, "bare script"},
        {PubKeyDestination{ecdsa_pub}, "P2PK"},
        {PKHash{ecdsa_pub}, "legacy P2PKH"},
        {ScriptHash{script}, "P2SH"},
        {WitnessV0KeyHash{PKHash{ecdsa_pub}}, "P2WPKH"},
        {WitnessV0ScriptHash{script}, "P2WSH"},
        {WitnessV1Taproot{XOnlyPubKey{ecdsa_pub}}, "P2TR"},
        {PayToAnchor{}, "P2A"},
        {WitnessUnknown{2, std::vector<unsigned char>(32, 0x01)}, "witness v2"},
    };

    for (const auto& [dest, name] : unspendable) {
        BOOST_CHECK_MESSAGE(!IsDilithiumDestination(dest), "must not be spendable: " << name);
        BOOST_CHECK_EQUAL(DestinationTypeName(dest), name);
    }

    const CTxDestination dilithium{DilithiumPKHash{dil_key.GetPubKey()}};
    BOOST_CHECK(IsDilithiumDestination(dilithium));
    BOOST_CHECK_EQUAL(DestinationTypeName(dilithium), "Dilithium P2PKH");

    // Spendability is a separate question from being a well-formed address:
    // these are dead ends the user can still type, not decoding failures.
    BOOST_CHECK(IsValidDestination(dilithium));
    BOOST_CHECK(IsValidDestination(CTxDestination{PKHash{ecdsa_pub}}));
    BOOST_CHECK(IsValidDestination(CTxDestination{WitnessV0KeyHash{PKHash{ecdsa_pub}}}));
}

/**
 * Why the guard has to be at the address layer: a Dilithium P2PKH and a legacy
 * P2PKH over the same key hash are the same output script, so the key type
 * survives only in the address encoding. Once an address has become a
 * scriptPubKey, a check would have to either reject genuine Dilithium payments
 * or let ECDSA-shaped burns through.
 */
BOOST_AUTO_TEST_CASE(the_key_type_survives_only_in_the_address_encoding)
{
    const CDilithiumKey key = GenerateRandomDilithiumKey();
    const CKeyID keyid = key.GetPubKey().GetID();
    const CTxDestination dilithium{DilithiumPKHash{keyid}};
    const CTxDestination legacy{PKHash{keyid}};

    // Same 20-byte payload, so the same script...
    BOOST_CHECK(GetScriptForDestination(dilithium) == GetScriptForDestination(legacy));
    // ...but distinct addresses, because the version byte differs.
    const std::string dilithium_addr = EncodeDestination(dilithium);
    const std::string legacy_addr = EncodeDestination(legacy);
    BOOST_CHECK(dilithium_addr != legacy_addr);

    // The address layer keeps the distinction, and both directions agree.
    BOOST_CHECK(IsDilithiumDestination(DecodeDestination(dilithium_addr)));
    BOOST_CHECK(!IsDilithiumDestination(DecodeDestination(legacy_addr)));

    // Script-derived destinations are Dilithium: a P2PKH script can only be
    // spent by an ML-DSA-65 key, so listunspent / getblock / gettransaction
    // must encode the same way getnewaddress does. Burn protection still
    // lives on the decoded user string, not on this extraction.
    CTxDestination extracted;
    BOOST_CHECK(ExtractDestination(GetScriptForDestination(dilithium), extracted));
    BOOST_CHECK(extracted == dilithium);
    BOOST_CHECK(IsDilithiumDestination(extracted));
    BOOST_CHECK_EQUAL(EncodeDestination(extracted), dilithium_addr);
    BOOST_CHECK(EncodeDestination(extracted) != legacy_addr);
}

/**
 * ExtractDestination must not emit the leftover ECDSA encoding for a P2PKH
 * script, even when that script was built from a PKHash. Display follows the
 * spendable type on this chain; the ECDSA version byte is only for strings
 * the user typed.
 */
BOOST_AUTO_TEST_CASE(p2pkh_scripts_encode_as_dilithium_addresses)
{
    const CDilithiumKey key = GenerateRandomDilithiumKey();
    const CKeyID keyid = key.GetPubKey().GetID();
    const CScript script = GetScriptForDestination(PKHash{keyid});

    CTxDestination extracted;
    BOOST_REQUIRE(ExtractDestination(script, extracted));
    BOOST_CHECK(std::holds_alternative<DilithiumPKHash>(extracted));
    BOOST_CHECK(IsDilithiumDestination(extracted));
    BOOST_CHECK_EQUAL(EncodeDestination(extracted), EncodeDestination(DilithiumPKHash{keyid}));
}

/**
 * deriveaddresses(pkh(ecdsa)) must keep the leftover ECDSA version byte.
 * Upgrading that string to Dilithium would make sendtoaddress accept a
 * destination nobody on this chain can spend.
 */
BOOST_AUTO_TEST_CASE(pkh_descriptor_keeps_leftover_ecdsa_encoding)
{
    CKey ecdsa_key;
    ecdsa_key.MakeNewKey(/*fCompressedIn=*/true);
    const CPubKey pub = ecdsa_key.GetPubKey();

    FlatSigningProvider provider;
    std::string error;
    const auto desc = Parse("pkh(" + HexStr(pub) + ")", provider, error, /*require_checksum=*/false);
    BOOST_REQUIRE_MESSAGE(desc, error);

    std::vector<CScript> scripts;
    BOOST_REQUIRE(desc->Expand(0, provider, scripts, provider));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);

    CTxDestination extracted;
    BOOST_REQUIRE(ExtractDestination(scripts[0], extracted));
    BOOST_CHECK(IsDilithiumDestination(extracted));

    const CTxDestination encoded = PreserveDescriptorAddressType(extracted, desc->GetOutputType());
    BOOST_CHECK(std::holds_alternative<PKHash>(encoded));
    BOOST_CHECK(!IsDilithiumDestination(encoded));
    BOOST_CHECK_EQUAL(EncodeDestination(encoded), EncodeDestination(PKHash{pub}));
}

/**
 * The address types a user is most likely to paste — anything produced by
 * Bitcoin-shaped tooling pointed at these chain parameters — must come back
 * unspendable after a full encode/decode round trip.
 */
BOOST_AUTO_TEST_CASE(encoded_non_dilithium_addresses_decode_as_unspendable)
{
    CKey ecdsa_key;
    ecdsa_key.MakeNewKey(/*fCompressedIn=*/true);
    const CPubKey pub = ecdsa_key.GetPubKey();
    const CScript redeem = GetScriptForDestination(WitnessV0KeyHash{PKHash{pub}});

    const std::vector<CTxDestination> dead{
        PKHash{pub},                                 // base58, ECDSA version byte
        ScriptHash{redeem},                          // base58, P2SH version byte
        WitnessV0KeyHash{PKHash{pub}},               // bech32 v0, 20-byte program
        WitnessV0ScriptHash{redeem},                 // bech32 v0, 32-byte program
        WitnessV1Taproot{XOnlyPubKey{pub}},          // bech32m, taproot
    };

    for (const CTxDestination& dest : dead) {
        const std::string addr = EncodeDestination(dest);
        BOOST_REQUIRE_MESSAGE(!addr.empty(), "encoding failed for " << DestinationTypeName(dest));
        const CTxDestination decoded = DecodeDestination(addr);
        BOOST_CHECK_MESSAGE(IsValidDestination(decoded), "should decode: " << addr);
        BOOST_CHECK_MESSAGE(!IsDilithiumDestination(decoded),
                            DestinationTypeName(dest) << " must be refused: " << addr);
    }

    // And the one that works: a wallet-issued Dilithium address survives the
    // round trip as spendable.
    const CTxDestination good{DilithiumPKHash{GenerateRandomDilithiumKey().GetPubKey()}};
    BOOST_CHECK(IsDilithiumDestination(DecodeDestination(EncodeDestination(good))));
}

/**
 * Every Dilithium address decodes, including the ones whose base58 text collides
 * with the Bech32 HRP.
 *
 * On mainnet the Dilithium version byte (58) puts every address under 'Q' and the
 * HRP is "qc", so an address whose second character is 'c' begins with the HRP.
 * Deciding the encoding from that prefix — as upstream does, safely, because no
 * Bitcoin base58 address can begin "bc" — sent roughly one wallet-issued address
 * in thirty down the Bech32 path, where it failed and decoded to nothing: refused
 * by every send path and reported invalid by `validateaddress`.
 *
 * The colliding hash is searched for rather than hardcoded so that this keeps
 * testing the real parameters if the version byte or the HRP changes. A test on a
 * random key finds this roughly one run in thirty, which is how it was found.
 */
BOOST_AUTO_TEST_CASE(dilithium_addresses_decode_even_when_they_look_like_bech32)
{
    const std::string hrp = Params().Bech32HRP();

    // A key hash whose Dilithium address starts with the Bech32 HRP. Not all
    // parameter choices admit one: testnet and regtest need 3-4 specific
    // characters, so the search is bounded and a miss is not a failure.
    std::string collides;
    CTxDestination collides_dest;
    for (uint32_t i = 0; i < 200000 && collides.empty(); ++i) {
        const uint256 seed{Hash(std::vector<unsigned char>{
            static_cast<unsigned char>(i), static_cast<unsigned char>(i >> 8),
            static_cast<unsigned char>(i >> 16), static_cast<unsigned char>(i >> 24)})};
        uint160 keyhash;
        std::copy(seed.begin(), seed.begin() + keyhash.size(), keyhash.begin());

        const CTxDestination dest{DilithiumPKHash{CKeyID{keyhash}}};
        const std::string addr = EncodeDestination(dest);
        if (ToLower(addr.substr(0, hrp.size())) == hrp) {
            collides = addr;
            collides_dest = dest;
        }
    }

    if (collides.empty()) {
        BOOST_TEST_MESSAGE("no Dilithium address collides with HRP \"" << hrp << "\" on this network");
        return;
    }

    BOOST_TEST_MESSAGE("Dilithium address colliding with HRP \"" << hrp << "\": " << collides);
    const CTxDestination decoded = DecodeDestination(collides);
    BOOST_CHECK_MESSAGE(IsValidDestination(decoded), "must decode despite the HRP prefix: " << collides);
    BOOST_CHECK(IsDilithiumDestination(decoded));
    BOOST_CHECK(decoded == collides_dest);

    // The Bech32 branch is still reachable: a genuine Bech32 address for this
    // network decodes, and a corrupted one reports a Bech32 error rather than a
    // base58 one.
    CKey ecdsa_key;
    ecdsa_key.MakeNewKey(/*fCompressedIn=*/true);
    const std::string segwit = EncodeDestination(WitnessV0KeyHash{PKHash{ecdsa_key.GetPubKey()}});
    BOOST_REQUIRE(ToLower(segwit.substr(0, hrp.size())) == hrp);
    BOOST_CHECK(std::holds_alternative<WitnessV0KeyHash>(DecodeDestination(segwit)));

    std::string error;
    std::string corrupt = segwit;
    corrupt.back() = corrupt.back() == 'q' ? 'p' : 'q';
    BOOST_CHECK(!IsValidDestination(DecodeDestination(corrupt, error)));
    BOOST_CHECK_MESSAGE(error.find("Base58") == std::string::npos,
                        "a broken Bech32 address must not be diagnosed as base58: " << error);
}

BOOST_AUTO_TEST_SUITE_END()

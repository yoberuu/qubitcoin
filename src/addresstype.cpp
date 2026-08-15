// Copyright (c) 2023 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>

#include <crypto/sha256.h>
#include <dilithiumpubkey.h>
#include <hash.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/solver.h>
#include <uint256.h>
#include <util/hash_type.h>

#include <cassert>
#include <string>
#include <vector>

typedef std::vector<unsigned char> valtype;

ScriptHash::ScriptHash(const CScript& in) : BaseHash(Hash160(in)) {}
ScriptHash::ScriptHash(const CScriptID& in) : BaseHash{in} {}

PKHash::PKHash(const CPubKey& pubkey) : BaseHash(pubkey.GetID()) {}
PKHash::PKHash(const CKeyID& pubkey_id) : BaseHash(pubkey_id) {}

DilithiumPKHash::DilithiumPKHash(const CDilithiumPubKey& pubkey) : BaseHash(pubkey.GetID()) {}
DilithiumPKHash::DilithiumPKHash(const CKeyID& pubkey_id) : BaseHash(pubkey_id) {}

WitnessV0KeyHash::WitnessV0KeyHash(const CPubKey& pubkey) : BaseHash(pubkey.GetID()) {}
WitnessV0KeyHash::WitnessV0KeyHash(const PKHash& pubkey_hash) : BaseHash{pubkey_hash} {}

CKeyID ToKeyID(const PKHash& key_hash)
{
    return CKeyID{uint160{key_hash}};
}

CKeyID ToKeyID(const DilithiumPKHash& key_hash)
{
    return CKeyID{uint160{key_hash}};
}

CKeyID ToKeyID(const WitnessV0KeyHash& key_hash)
{
    return CKeyID{uint160{key_hash}};
}

CScriptID ToScriptID(const ScriptHash& script_hash)
{
    return CScriptID{uint160{script_hash}};
}

WitnessV0ScriptHash::WitnessV0ScriptHash(const CScript& in)
{
    CSHA256().Write(in.data(), in.size()).Finalize(begin());
}

bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet)
{
    std::vector<valtype> vSolutions;
    TxoutType whichType = Solver(scriptPubKey, vSolutions);

    switch (whichType) {
    case TxoutType::PUBKEY: {
        CPubKey pubKey(vSolutions[0]);
        if (!pubKey.IsValid()) {
            addressRet = CNoDestination(scriptPubKey);
        } else {
            addressRet = PubKeyDestination(pubKey);
        }
        return false;
    }
    case TxoutType::PUBKEYHASH: {
        // QubitCoin is Dilithium-only: a P2PKH script can only be spent by an
        // ML-DSA-65 key, so the script-derived destination is DilithiumPKHash.
        // The leftover PKHash type exists only at the address layer, for
        // user-supplied strings that still carry the ECDSA version byte.
        addressRet = DilithiumPKHash(uint160(vSolutions[0]));
        return true;
    }
    case TxoutType::SCRIPTHASH: {
        addressRet = ScriptHash(uint160(vSolutions[0]));
        return true;
    }
    case TxoutType::WITNESS_V0_KEYHASH: {
        WitnessV0KeyHash hash;
        std::copy(vSolutions[0].begin(), vSolutions[0].end(), hash.begin());
        addressRet = hash;
        return true;
    }
    case TxoutType::WITNESS_V0_SCRIPTHASH: {
        WitnessV0ScriptHash hash;
        std::copy(vSolutions[0].begin(), vSolutions[0].end(), hash.begin());
        addressRet = hash;
        return true;
    }
    case TxoutType::WITNESS_V1_TAPROOT: {
        WitnessV1Taproot tap;
        std::copy(vSolutions[0].begin(), vSolutions[0].end(), tap.begin());
        addressRet = tap;
        return true;
    }
    case TxoutType::ANCHOR: {
        addressRet = PayToAnchor();
        return true;
    }
    case TxoutType::WITNESS_UNKNOWN: {
        addressRet = WitnessUnknown{vSolutions[0][0], vSolutions[1]};
        return true;
    }
    case TxoutType::MULTISIG:
    case TxoutType::NULL_DATA:
    case TxoutType::NONSTANDARD:
        addressRet = CNoDestination(scriptPubKey);
        return false;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

namespace {
class CScriptVisitor
{
public:
    CScript operator()(const CNoDestination& dest) const
    {
        return dest.GetScript();
    }

    CScript operator()(const PubKeyDestination& dest) const
    {
        return CScript() << ToByteVector(dest.GetPubKey()) << OP_CHECKSIG;
    }

    CScript operator()(const PKHash& keyID) const
    {
        return CScript() << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
    }

    CScript operator()(const DilithiumPKHash& keyID) const
    {
        // Identical P2PKH template to PKHash; the interpreter dispatches to
        // Dilithium verification based on the 1952-byte pubkey in the scriptSig.
        return CScript() << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
    }

    CScript operator()(const ScriptHash& scriptID) const
    {
        return CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    }

    CScript operator()(const WitnessV0KeyHash& id) const
    {
        return CScript() << OP_0 << ToByteVector(id);
    }

    CScript operator()(const WitnessV0ScriptHash& id) const
    {
        return CScript() << OP_0 << ToByteVector(id);
    }

    CScript operator()(const WitnessV1Taproot& tap) const
    {
        return CScript() << OP_1 << ToByteVector(tap);
    }

    CScript operator()(const WitnessUnknown& id) const
    {
        return CScript() << CScript::EncodeOP_N(id.GetWitnessVersion()) << id.GetWitnessProgram();
    }
};

class ValidDestinationVisitor
{
public:
    bool operator()(const CNoDestination& dest) const { return false; }
    bool operator()(const PubKeyDestination& dest) const { return false; }
    bool operator()(const PKHash& dest) const { return true; }
    bool operator()(const DilithiumPKHash& dest) const { return true; }
    bool operator()(const ScriptHash& dest) const { return true; }
    bool operator()(const WitnessV0KeyHash& dest) const { return true; }
    bool operator()(const WitnessV0ScriptHash& dest) const { return true; }
    bool operator()(const WitnessV1Taproot& dest) const { return true; }
    bool operator()(const WitnessUnknown& dest) const { return true; }
};

/**
 * Spelled out per destination type rather than as a single
 * std::holds_alternative check, so that adding a destination type is a
 * compile error here instead of a silently spendable new burn shape.
 */
class DilithiumDestinationVisitor
{
public:
    bool operator()(const DilithiumPKHash& dest) const { return true; }

    bool operator()(const CNoDestination& dest) const { return false; }
    bool operator()(const PubKeyDestination& dest) const { return false; }
    bool operator()(const PKHash& dest) const { return false; }
    bool operator()(const ScriptHash& dest) const { return false; }
    bool operator()(const WitnessV0KeyHash& dest) const { return false; }
    bool operator()(const WitnessV0ScriptHash& dest) const { return false; }
    bool operator()(const WitnessV1Taproot& dest) const { return false; }
    bool operator()(const WitnessUnknown& dest) const { return false; }
};

class DestinationTypeNameVisitor
{
public:
    std::string operator()(const CNoDestination& dest) const { return "bare script"; }
    std::string operator()(const PubKeyDestination& dest) const { return "P2PK"; }
    std::string operator()(const PKHash& dest) const { return "legacy P2PKH"; }
    std::string operator()(const DilithiumPKHash& dest) const { return "Dilithium P2PKH"; }
    std::string operator()(const ScriptHash& dest) const { return "P2SH"; }
    std::string operator()(const WitnessV0KeyHash& dest) const { return "P2WPKH"; }
    std::string operator()(const WitnessV0ScriptHash& dest) const { return "P2WSH"; }
    std::string operator()(const WitnessV1Taproot& dest) const { return "P2TR"; }
    std::string operator()(const PayToAnchor& dest) const { return "P2A"; }
    std::string operator()(const WitnessUnknown& dest) const
    {
        return "witness v" + std::to_string(dest.GetWitnessVersion());
    }
};
} // namespace

CScript GetScriptForDestination(const CTxDestination& dest)
{
    return std::visit(CScriptVisitor(), dest);
}

bool IsValidDestination(const CTxDestination& dest) {
    return std::visit(ValidDestinationVisitor(), dest);
}

bool IsDilithiumDestination(const CTxDestination& dest)
{
    return std::visit(DilithiumDestinationVisitor(), dest);
}

std::string DestinationTypeName(const CTxDestination& dest)
{
    return std::visit(DestinationTypeNameVisitor(), dest);
}

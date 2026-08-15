// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <type_traits>

// Workaround MSVC bug triggering C7595 when calling consteval constructors in
// initializer lists.
// A fix may be on the way:
// https://developercommunity.visualstudio.com/t/consteval-conversion-function-fails/1579014
#if defined(_MSC_VER)
auto consteval_ctor(auto&& input) { return input; }
#else
#define consteval_ctor(input) (input)
#endif

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * QubitCoin mainnet genesis (mined via contrib/devtools/mine_genesis.py):
 *   hash=000000002f4fcc60ef61353d1767c691562dd380f240c1fcf47bf0e1c655d011
 *   merkle=70be9292637f6486895bb3f4c3880350116284559985d492ff3c269b40d22255
 *   time=1783296000 nonce=1735730177 bits=0x1d00ffff reward=500 QBTC
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

static CBlock CreateQubitCoinMainGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Yelpful Technologies launches QubitCoin ($QBTC) 06/Jul/2026";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

static CBlock CreateQubitCoinRegtestGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "QubitCoin regtest genesis 06/Jul/2026";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

static CBlock CreateQubitCoinTestnet3GenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "QubitCoin Testnet3 09/Jul/2026";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

static CBlock CreateQubitCoinTestnet4GenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "QubitCoin Testnet4 09/Jul/2026";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

static CBlock CreateQubitCoinSignetGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "QubitCoin Signet genesis 09/Jul/2026";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000; // 500 QBTC -> 250 -> ... total ~210M QBTC
        // QubitCoin launches with modern rules active from block 1.
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342) — active from genesis
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x51; // QBTC
        pchMessageStart[1] = 0x42;
        pchMessageStart[2] = 0x54;
        pchMessageStart[3] = 0x43;
        nDefaultPort = 2096;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 620;
        m_assumed_chain_state_size = 14;

        genesis = CreateQubitCoinMainGenesisBlock(1783296000, 1735730177, 0x1d00ffff, 1, INITIAL_BLOCK_SUBSIDY);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"000000002f4fcc60ef61353d1767c691562dd380f240c1fcf47bf0e1c655d011"});
        assert(genesis.hashMerkleRoot == uint256{"70be9292637f6486895bb3f4c3880350116284559985d492ff3c269b40d22255"});
        consensus.BIP34Hash = consensus.hashGenesisBlock;

        // DNS seeds: temporary placeholders until QubitCoin seed infrastructure is deployed.
        // vSeeds.emplace_back("seed.qubitcoin.example.");

        // QubitCoin mainnet address encoding. Every prefix is deliberately
        // distinct from Bitcoin's so a QubitCoin address/key can never be a valid
        // Bitcoin address/key (and vice versa). The legacy secp256k1 prefixes are
        // vestigial on this Dilithium-only chain but are still made unique.
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,30);  // (unused ECDSA P2PKH), distinct from Dilithium's 58
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,63);  // not Bitcoin's 5 ('3')
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,145); // WIF, not Bitcoin's 128
        // BIP32 extended-key versions are left at Bitcoin's values: QubitCoin is
        // Dilithium-only and never serialises funds as xprv/xpub (Dilithium keys
        // use their own HD-seed scheme), so there is nothing here to collide.
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
        // QubitCoin post-quantum Dilithium P2PKH addresses (mainnet). Version
        // byte 58 renders a distinctive 'Q' address prefix. This is the primary
        // (and only user-facing) address type on this chain.
        base58Prefixes[PUBKEY_ADDRESS_DILITHIUM] = std::vector<unsigned char>(1,58);

        // Unique bech32 human-readable part: "qc" (QubitCoin), never Bitcoin's "bc".
        bech32_hrp = "qc";

        vFixedSeeds.clear();

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        m_assumeutxo_data = {};

        chainTxData = ChainTxData{
            .nTime    = 1783296000,
            .tx_count = 1,
            .dTxRate  = 0.0,
        };
    }
};

/**
 * Testnet (v3): QubitCoin public test network.
 *
 * Network identity (distinct from Bitcoin testnet and QubitCoin mainnet):
 *   magic bytes: 0x51 0x62 0x74 0x33 ("Qbt3")
 *   P2P port:    12096   RPC port: 12095   Tor onion: 12097
 *   bech32 HRP:  "tq"    Dilithium base58 version: 120 ('q' prefix)
 *
 * Consensus: fresh Dilithium-only chain with modern rules from block 1.
 *   BIP34/65/66/CSV at height 1, Segwit at 0, Taproot ALWAYS_ACTIVE.
 *   nMinimumChainWork and defaultAssumeValid are zeroed (no trusted checkpoints).
 *
 * Seeds: public fixed seeds at 142.93.6.69:12096 and 142.93.12.49:12096
 * (contrib/seeds/nodes_test.txt). Regenerate chainparamsseeds.h after changes.
 *
 * Genesis (mined via contrib/devtools/mine_genesis.py):
 *   hash=00000000c0f906a85aca8c26722998dd6292ef5c88f5912963eed730df17f09a
 *   merkle=f0c80bc6d5ba720c2f24a5e4ab7a791d8985266515d0772e81845327ce57b0e3
 *   time=1783555201 nonce=1728804986 bits=0x1d00ffff reward=500 QBTC
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        m_chain_type = ChainType::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000; // 500 QBTC -> 250 -> ... total ~210M QBTC
        // QubitCoin testnet3 launches with modern rules active from block 1.
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342) — active from genesis
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0x51; // Qbt3
        pchMessageStart[1] = 0x62;
        pchMessageStart[2] = 0x74;
        pchMessageStart[3] = 0x33;
        nDefaultPort = 12096;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 0;

        genesis = CreateQubitCoinTestnet3GenesisBlock(1783555201, 1728804986, 0x1d00ffff, 1, INITIAL_BLOCK_SUBSIDY);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"00000000c0f906a85aca8c26722998dd6292ef5c88f5912963eed730df17f09a"});
        assert(genesis.hashMerkleRoot == uint256{"f0c80bc6d5ba720c2f24a5e4ab7a791d8985266515d0772e81845327ce57b0e3"});
        consensus.BIP34Hash = consensus.hashGenesisBlock;

        // Public fixed seeds from contrib/seeds/nodes_test.txt:
        //   142.93.6.69:12096, 142.93.12.49:12096
        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));
        vSeeds.clear();
        // DNS seeds: add here when DNS seeders are deployed (optional; fixed seeds above are live).
        // vSeeds.emplace_back("seed.testnet3.qubitcoin.org.");

        // QubitCoin testnet3 address encoding: distinct from Bitcoin testnet
        // (111/196/239/"tb") and from QubitCoin's other networks.
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,90);   // (unused ECDSA P2PKH)
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,92);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,155);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        // QubitCoin post-quantum Dilithium P2PKH addresses (test networks): version
        // byte 120 renders a distinctive 'q' address prefix.
        base58Prefixes[PUBKEY_ADDRESS_DILITHIUM] = std::vector<unsigned char>(1,120);

        bech32_hrp = "tq";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        m_assumeutxo_data = {};

        chainTxData = ChainTxData{
            .nTime    = 1783555201,
            .tx_count = 1,
            .dTxRate  = 0.0,
        };
    }
};

/**
 * Testnet (v4): QubitCoin public test network (recommended over testnet3).
 *
 * Network identity (distinct from testnet3, Bitcoin testnet4, and mainnet):
 *   magic bytes: 0x51 0x62 0x74 0x34 ("Qbt4")
 *   P2P port:    42096   RPC port: 42095   Tor onion: 42097
 *   bech32 HRP:  "trq"   Dilithium base58 version: 121
 *
 * Consensus: same fresh-chain rule set as testnet3, plus enforce_BIP94=true
 * (Bitcoin testnet4 time-warp mitigation). BIP34/65/66/CSV at 1, Segwit at 0,
 * Taproot ALWAYS_ACTIVE. nMinimumChainWork and defaultAssumeValid zeroed.
 *
 * PoW: powLimit is softer than Bitcoin-style 00000000ffff… so that after the
 * min-difficulty rule applies (block time > 2× nPowTargetSpacing since tip),
 * CPU `generatetoaddress` with DEFAULT_MAX_TRIES can find blocks. Genesis keeps
 * bits=0x1d00ffff (harder than min-diff); CheckProofOfWork only requires the
 * claimed target ≤ powLimit, so the existing genesis remains valid.
 *
 * Seeds: public fixed seeds at 142.93.6.69:42096 and 142.93.12.49:42096
 * (contrib/seeds/nodes_testnet4.txt). Regenerate chainparamsseeds.h after changes.
 *
 * Genesis (mined via contrib/devtools/mine_genesis.py):
 *   hash=00000000f0760be464eb2acd0069f5fbd4e50638c8b629c5d6ac50966c060636
 *   merkle=d337a941ef9135233ff00b35ddaa2f8ff1d63515f057ce316eaf95ce96648022
 *   time=1783555201 nonce=147812606 bits=0x1d00ffff reward=500 QBTC
 */
class CTestNet4Params : public CChainParams {
public:
    CTestNet4Params() {
        m_chain_type = ChainType::TESTNET4;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000; // 500 QBTC -> 250 -> ... total ~210M QBTC
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        // ~2^16 hashes expected at min-difficulty (compact ≈ 0x1f00ffff).
        // Bitcoin-style 00000000ffff… needs ~2^32 and exhausts DEFAULT_MAX_TRIES.
        consensus.powLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0x51; // Qbt4
        pchMessageStart[1] = 0x62;
        pchMessageStart[2] = 0x74;
        pchMessageStart[3] = 0x34;
        nDefaultPort = 42096;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 0;

        genesis = CreateQubitCoinTestnet4GenesisBlock(1783555201, 147812606, 0x1d00ffff, 1, INITIAL_BLOCK_SUBSIDY);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"00000000f0760be464eb2acd0069f5fbd4e50638c8b629c5d6ac50966c060636"});
        assert(genesis.hashMerkleRoot == uint256{"d337a941ef9135233ff00b35ddaa2f8ff1d63515f057ce316eaf95ce96648022"});
        consensus.BIP34Hash = consensus.hashGenesisBlock;

        // Public fixed seeds from contrib/seeds/nodes_testnet4.txt:
        //   142.93.6.69:42096, 142.93.12.49:42096
        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_testnet4), std::end(chainparams_seed_testnet4));
        vSeeds.clear();
        // DNS seeds: add here when DNS seeders are deployed (optional; fixed seeds above are live).
        // vSeeds.emplace_back("seed.testnet4.qubitcoin.org.");

        // QubitCoin testnet4 address encoding: distinct from testnet3, Bitcoin
        // testnet, and QubitCoin's other networks.
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,91);   // (unused ECDSA P2PKH)
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,93);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,156);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x88, 0xD0};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x84, 0x95};
        // QubitCoin post-quantum Dilithium P2PKH addresses (version byte 121).
        base58Prefixes[PUBKEY_ADDRESS_DILITHIUM] = std::vector<unsigned char>(1,121);

        bech32_hrp = "trq";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        m_assumeutxo_data = {};

        chainTxData = ChainTxData{
            .nTime    = 1783555201,
            .tx_count = 1,
            .dTxRate  = 0.0,
        };
    }
};

/**
 * Signet: test network with an additional consensus parameter (see BIP325).
 *
 * QubitCoin signet genesis (mined via contrib/devtools/mine_genesis.py):
 *   hash=0000007dee6d791897d022315e2062b6045ec87d52a892c40d70b5d8425550d9
 *   merkle=8caefdf76e544019fee417763266e593f950ca1043eb8802031bea75d015fbe5
 *   time=1783555202 nonce=1164624 bits=0x1e0377ae reward=500 QBTC
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vSeeds.clear();

        if (!options.challenge) {
            // Default QubitCoin signet challenge (kept simple — same structure as Bitcoin signet)
            bin = ParseHex("512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae");
            // DNS seeds: temporary placeholders until QubitCoin signet seed infrastructure is deployed.
            // vSeeds.emplace_back("seed.signet.qubitcoin.example.");

            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 1;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                .nTime    = 1783555202,
                .tx_count = 1,
                .dTxRate  = 0.0,
            };
        } else {
            bin = *options.challenge;
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
            LogPrintf("Signet with challenge %s\n", HexStr(bin));
        }

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyHalvingInterval = 210000; // 500 QBTC -> 250 -> ... total ~210M QBTC
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 0;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"00000377ae000000000000000000000000000000000000000000000000000000"};
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Activation of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        // message start is defined as the first 4 bytes of the sha256d of the block script
        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        std::copy_n(hash.begin(), 4, pchMessageStart.begin());

        nDefaultPort = 32096;
        nPruneAfterHeight = 1000;

        genesis = CreateQubitCoinSignetGenesisBlock(1783555202, 1164624, 0x1e0377ae, 1, INITIAL_BLOCK_SUBSIDY);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"0000007dee6d791897d022315e2062b6045ec87d52a892c40d70b5d8425550d9"});
        assert(genesis.hashMerkleRoot == uint256{"8caefdf76e544019fee417763266e593f950ca1043eb8802031bea75d015fbe5"});
        consensus.BIP34Hash = consensus.hashGenesisBlock;

        vFixedSeeds.clear();

        m_assumeutxo_data = {};

        // QubitCoin signet address encoding: distinct from Bitcoin signet and from
        // QubitCoin's other networks.
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,90);   // (unused ECDSA P2PKH)
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,92);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,155);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        // QubitCoin post-quantum Dilithium P2PKH addresses (version byte 120 -> 'q').
        base58Prefixes[PUBKEY_ADDRESS_DILITHIUM] = std::vector<unsigned char>(1,120);

        // Signet uses its own bech32 HRP ("sq").
        bech32_hrp = "sq";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 1; // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;  // Always active unless overridden
        consensus.BIP66Height = 1;  // Always active unless overridden
        consensus.CSVHeight = 1;    // Always active unless overridden
        consensus.SegwitHeight = 0; // Always active unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 24 * 60 * 60; // one day
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0x51; // QBTR
        pchMessageStart[1] = 0x42;
        pchMessageStart[2] = 0x54;
        pchMessageStart[3] = 0x52;
        nDefaultPort = 21096;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:
                consensus.SegwitHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:
                consensus.CSVHeight = int{height};
                break;
            }
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

        genesis = CreateQubitCoinRegtestGenesisBlock(1783296001, 0, 0x207fffff, 1, INITIAL_BLOCK_SUBSIDY);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"7b9160d5ab91fb4fbe56014bdb86a9dcebafb9cc28c110f91142303f7b472747"});
        assert(genesis.hashMerkleRoot == uint256{"a77dea23a8843d1fdcba464815fdcef9cbeb1a46aaaf9e284b378810dcf9fe97"});
        consensus.BIP34Hash = consensus.hashGenesisBlock;

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");

        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        m_assumeutxo_data = {};

        chainTxData = ChainTxData{
            .nTime    = 1783296001,
            .tx_count = 1,
            .dTxRate  = 0.0,
        };

        // QubitCoin regtest address encoding: distinct from Bitcoin regtest
        // (111/196/239/"bcrt") and from QubitCoin's other networks.
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,90);   // (unused ECDSA P2PKH)
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,92);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,155);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        // QubitCoin post-quantum Dilithium P2PKH addresses (version byte 120 -> 'q').
        base58Prefixes[PUBKEY_ADDRESS_DILITHIUM] = std::vector<unsigned char>(1,120);

        bech32_hrp = "qcrt";
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    return std::make_unique<const SigNetParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet()
{
    return std::make_unique<const CTestNetParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet4()
{
    return std::make_unique<const CTestNet4Params>();
}

std::vector<int> CChainParams::GetAvailableSnapshotHeights() const
{
    std::vector<int> heights;
    heights.reserve(m_assumeutxo_data.size());

    for (const auto& data : m_assumeutxo_data) {
        heights.emplace_back(data.height);
    }
    return heights;
}

std::optional<ChainType> GetNetworkForMagic(const MessageStartChars& message)
{
    const auto mainnet_msg = CChainParams::Main()->MessageStart();
    const auto testnet_msg = CChainParams::TestNet()->MessageStart();
    const auto testnet4_msg = CChainParams::TestNet4()->MessageStart();
    const auto regtest_msg = CChainParams::RegTest({})->MessageStart();
    const auto signet_msg = CChainParams::SigNet({})->MessageStart();

    if (std::equal(message.begin(), message.end(), mainnet_msg.data())) {
        return ChainType::MAIN;
    } else if (std::equal(message.begin(), message.end(), testnet_msg.data())) {
        return ChainType::TESTNET;
    } else if (std::equal(message.begin(), message.end(), testnet4_msg.data())) {
        return ChainType::TESTNET4;
    } else if (std::equal(message.begin(), message.end(), regtest_msg.data())) {
        return ChainType::REGTEST;
    } else if (std::equal(message.begin(), message.end(), signet_msg.data())) {
        return ChainType::SIGNET;
    }
    return std::nullopt;
}

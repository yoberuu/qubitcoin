// Copyright (c) 2026 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <dilithiumkey.h>
#include <dilithiumpubkey.h>
#include <key_io.h>
#include <node/miner.h>
#include <primitives/block.h>
#include <script/script.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <util/time.h>
#include <validation.h>

#include <variant>

#include <boost/test/unit_test.hpp>

using node::BlockAssembler;

BOOST_FIXTURE_TEST_SUITE(dilithium_mining_tests, RegTestingSetup)

// CreateNewBlock + MineBlock must accept a Dilithium P2PKH coinbase script and
// advance the chain. This is the same scriptPubKey path generatetoaddress uses.
BOOST_AUTO_TEST_CASE(mine_block_to_dilithium_p2pkh)
{
    // Align mock time with (or after) genesis so CreateNewBlock is not rejected
    // as time-too-new on QubitCoin's 2026-era regtest genesis.
    SetMockTime(Params().GenesisBlock().nTime + 600);

    CDilithiumKey key = GenerateRandomDilithiumKey();
    const CDilithiumPubKey pubkey = key.GetPubKey();
    const CTxDestination dest = DilithiumPKHash(pubkey);
    const CScript coinbase_script = GetScriptForDestination(dest);

    BOOST_CHECK_EQUAL(coinbase_script.size(), 25U);
    BOOST_CHECK(std::holds_alternative<DilithiumPKHash>(dest));

    const int height_before = WITH_LOCK(m_node.chainman->GetMutex(), return m_node.chainman->ActiveHeight());
    const COutPoint coinbase_out = MineBlock(m_node, coinbase_script);
    BOOST_CHECK(!coinbase_out.hash.IsNull());

    const int height_after = WITH_LOCK(m_node.chainman->GetMutex(), return m_node.chainman->ActiveHeight());
    BOOST_CHECK_EQUAL(height_after, height_before + 1);

    CBlockIndex* tip = WITH_LOCK(m_node.chainman->GetMutex(), return m_node.chainman->ActiveChain().Tip());
    BOOST_REQUIRE(tip);
    CBlock block;
    BOOST_REQUIRE(m_node.chainman->m_blockman.ReadBlockFromDisk(block, *tip));
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 1U);
    BOOST_CHECK(block.vtx[0]->IsCoinBase());
    BOOST_CHECK(block.vtx[0]->vout[0].scriptPubKey == coinbase_script);

    SetMockTime(0);
}

// generatetoaddress helper must decode a Dilithium address and mine to it.
BOOST_AUTO_TEST_CASE(generatetoaddress_dilithium)
{
    SetMockTime(Params().GenesisBlock().nTime + 600);

    CDilithiumKey key = GenerateRandomDilithiumKey();
    const std::string address = EncodeDestination(DilithiumPKHash(key.GetPubKey()));
    BOOST_CHECK(std::holds_alternative<DilithiumPKHash>(DecodeDestination(address)));

    const int height_before = WITH_LOCK(m_node.chainman->GetMutex(), return m_node.chainman->ActiveHeight());
    const COutPoint coinbase_out = generatetoaddress(m_node, address);
    BOOST_CHECK(!coinbase_out.hash.IsNull());

    const int height_after = WITH_LOCK(m_node.chainman->GetMutex(), return m_node.chainman->ActiveHeight());
    BOOST_CHECK_EQUAL(height_after, height_before + 1);

    SetMockTime(0);
}

// BlockAssembler template for a Dilithium coinbase must be structurally valid
// (witness commitment present, expected P2PKH coinbase weight ballpark).
BOOST_AUTO_TEST_CASE(create_new_block_dilithium_coinbase)
{
    SetMockTime(Params().GenesisBlock().nTime + 600);

    CDilithiumKey key = GenerateRandomDilithiumKey();
    const CScript coinbase_script = GetScriptForDestination(DilithiumPKHash(key.GetPubKey()));

    BlockAssembler::Options options;
    auto pblocktemplate = BlockAssembler{
        m_node.chainman->ActiveChainstate(),
        m_node.mempool.get(),
        options}
                                 .CreateNewBlock(coinbase_script);
    BOOST_REQUIRE(pblocktemplate);
    BOOST_REQUIRE(!pblocktemplate->block.vtx.empty());
    BOOST_CHECK(pblocktemplate->block.vtx[0]->IsCoinBase());
    BOOST_CHECK(pblocktemplate->block.vtx[0]->vout[0].scriptPubKey == coinbase_script);

    // Segwit commitment adds a second coinbase output; total weight is small
    // (Dilithium is only in the address layer — on-chain script is 25-byte P2PKH).
    const int64_t weight = GetBlockWeight(pblocktemplate->block);
    BOOST_CHECK_GT(weight, 0);
    BOOST_CHECK_LT(weight, 4000);

    SetMockTime(0);
}

BOOST_AUTO_TEST_SUITE_END()

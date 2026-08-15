// Copyright (c) 2026 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// QubitCoin Phase 4: prove that the (legacy) wallet can generate, store,
// recognise (IsMine), encrypt/decrypt and spend post-quantum Dilithium
// (ML-DSA-65) keys through the normal wallet interfaces.

#include <addresstype.h>
#include <consensus/validation.h>
#include <dilithiumkey.h>
#include <dilithiumpubkey.h>
#include <key_io.h>
#include <outputtype.h>
#include <policy/policy.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <wallet/crypter.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/types.h>
#include <wallet/wallet.h>
#include <uint256.h>

#include <algorithm>
#include <string>
#include <variant>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(dilithium_wallet_integration_tests, BasicTestingSetup)

//! Build an unencrypted legacy wallet ready to hand out keys.
static std::unique_ptr<CWallet> MakeLegacyWallet(interfaces::Chain* chain)
{
    auto wallet = std::make_unique<CWallet>(chain, "", CreateMockableWalletDatabase());
    wallet->SetupLegacyScriptPubKeyMan();
    return wallet;
}

// The wallet can generate a Dilithium address via the normal GetNewDestination
// interface, and recognises it as its own.
BOOST_AUTO_TEST_CASE(wallet_generate_and_ismine)
{
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;
    auto wallet = MakeLegacyWallet(chain.get());

    auto op_dest = wallet->GetNewDestination(OutputType::DILITHIUM, "pq-label");
    BOOST_REQUIRE(op_dest);
    const CTxDestination dest = *op_dest;
    BOOST_CHECK(std::holds_alternative<DilithiumPKHash>(dest));

    // The address encodes/decodes as a post-quantum destination.
    const std::string address = EncodeDestination(dest);
    BOOST_CHECK(std::holds_alternative<DilithiumPKHash>(DecodeDestination(address)));

    // The wallet reports ownership of the corresponding script.
    const CScript spk = GetScriptForDestination(dest);
    BOOST_CHECK_EQUAL(wallet->IsMine(spk), ISMINE_SPENDABLE);

    // A different, unknown Dilithium destination is NOT ours.
    CDilithiumKey stranger = GenerateRandomDilithiumKey();
    BOOST_CHECK_EQUAL(wallet->IsMine(GetScriptForDestination(DilithiumPKHash(stranger.GetPubKey()))), ISMINE_NO);
}

// The wallet stores the private key so it can be retrieved for signing.
BOOST_AUTO_TEST_CASE(wallet_stores_private_key)
{
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;
    auto wallet = MakeLegacyWallet(chain.get());

    auto op_dest = wallet->GetNewDestination(OutputType::DILITHIUM, "");
    BOOST_REQUIRE(op_dest);
    const CKeyID keyid = ToKeyID(std::get<DilithiumPKHash>(*op_dest));

    LegacyScriptPubKeyMan* spk_man = wallet->GetLegacyScriptPubKeyMan();
    BOOST_REQUIRE(spk_man);
    LOCK(spk_man->cs_KeyStore);
    BOOST_CHECK(spk_man->HaveDilithiumKey(keyid));
    CDilithiumKey key;
    BOOST_CHECK(spk_man->GetDilithiumKey(keyid, key));
    BOOST_CHECK(key.IsValid());
    BOOST_CHECK(key.GetPubKey().GetID() == keyid);
}

// Fund a Dilithium output and spend it, producing the signature through the
// wallet's SigningProvider (the same path SignTransaction uses).
BOOST_AUTO_TEST_CASE(wallet_receives_and_spends)
{
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;
    auto wallet = MakeLegacyWallet(chain.get());

    auto op_dest = wallet->GetNewDestination(OutputType::DILITHIUM, "");
    BOOST_REQUIRE(op_dest);
    const CScript scriptPubKey = GetScriptForDestination(*op_dest);

    const CAmount amount = 0; // legacy sighash does not commit to amount
    const CTransaction txCredit{BuildCreditingTransaction(scriptPubKey, amount)};
    CMutableTransaction txSpend = BuildSpendingTransaction(CScript(), CScriptWitness(), txCredit);

    LegacyScriptPubKeyMan* spk_man = wallet->GetLegacyScriptPubKeyMan();
    BOOST_REQUIRE(spk_man);

    SignatureData sigdata;
    {
        LOCK(spk_man->cs_KeyStore);
        BOOST_REQUIRE(SignSignature(*spk_man, scriptPubKey, txSpend, 0, amount, SIGHASH_ALL, sigdata));
    }
    BOOST_CHECK(sigdata.complete);

    ScriptError serr = SCRIPT_ERR_OK;
    const MutableTransactionSignatureChecker checker(&txSpend, 0, amount, MissingDataBehavior::ASSERT_FAIL);
    BOOST_CHECK_MESSAGE(
        VerifyScript(txSpend.vin[0].scriptSig, scriptPubKey, nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serr),
        "VerifyScript failed: " << ScriptErrorString(serr));
}

// Fee estimation has to size a Dilithium input for what it really is. The
// descriptor engine has no ML-DSA key type, so both spend forms are handled by a
// dedicated path; if that path ever stops recognising a form, estimation falls
// back to ECDSA-shaped numbers and every fee is off by more than an order of
// magnitude.
BOOST_AUTO_TEST_CASE(wallet_estimates_dilithium_input_sizes)
{
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;
    auto wallet = MakeLegacyWallet(chain.get());

    auto op_dest = wallet->GetNewDestination(OutputType::DILITHIUM, "");
    BOOST_REQUIRE(op_dest);
    const CKeyID keyid = ToKeyID(std::get<DilithiumPKHash>(*op_dest));
    const CScript bare_spk = GetScriptForDestination(*op_dest);

    // Bare form: the wallet's own address type.
    const CTxOut bare_txout{1 * COIN, bare_spk};
    int bare_size;
    {
        LOCK(wallet->cs_wallet);
        bare_size = CalculateMaximumSignedInputSize(bare_txout, wallet.get(), /*coin_control=*/nullptr);
    }
    BOOST_CHECK_EQUAL(bare_size, static_cast<int>(DILITHIUM_P2PKH_INPUT_VSIZE));

    // Witness form: not an address type this wallet hands out, but reachable via
    // an external signing provider (funding an external input, PSBT).
    LegacyScriptPubKeyMan* spk_man = wallet->GetLegacyScriptPubKeyMan();
    BOOST_REQUIRE(spk_man);
    CDilithiumKey dkey;
    {
        LOCK(spk_man->cs_KeyStore);
        BOOST_REQUIRE(spk_man->GetDilithiumKey(keyid, dkey));
    }
    FillableSigningProvider provider;
    BOOST_REQUIRE(provider.AddDilithiumKey(dkey));
    const CTxOut witness_txout{1 * COIN, GetScriptForDestination(WitnessV0KeyHash(uint160{keyid}))};
    const int witness_size = CalculateMaximumSignedInputSize(witness_txout, COutPoint(), &provider,
                                                             /*can_grind_r=*/true, /*coin_control=*/nullptr);
    BOOST_CHECK_EQUAL(witness_size, static_cast<int>(DILITHIUM_P2WPKH_INPUT_VSIZE));

    // Neither is anywhere near an ECDSA-sized estimate, and the witness form is
    // the cheaper of the two.
    BOOST_CHECK_GT(witness_size, 148);
    BOOST_CHECK_LT(witness_size, bare_size);

    // Whole-transaction estimation must match what signing actually produces.
    const CTransaction credit{BuildCreditingTransaction(bare_spk, 1 * COIN)};
    CMutableTransaction spend = BuildSpendingTransaction(CScript(), CScriptWitness(), credit);
    TxSize estimate;
    {
        LOCK(wallet->cs_wallet);
        estimate = CalculateMaximumSignedTxSize(CTransaction{spend}, wallet.get(),
                                                {credit.vout[0]}, /*coin_control=*/nullptr);
    }
    SignatureData sigdata;
    {
        LOCK(spk_man->cs_KeyStore);
        BOOST_REQUIRE(SignSignature(*spk_man, bare_spk, spend, 0, 1 * COIN, SIGHASH_ALL, sigdata));
    }
    BOOST_CHECK_EQUAL(estimate.weight, GetTransactionWeight(CTransaction{spend}));
    BOOST_CHECK_EQUAL(estimate.vsize, GetVirtualTransactionSize(CTransaction{spend}));
}

// Encrypting the wallet migrates an existing plaintext Dilithium key into the
// encrypted store; after unlocking the key is still spendable.
BOOST_AUTO_TEST_CASE(wallet_encrypt_existing_key)
{
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;
    auto wallet = MakeLegacyWallet(chain.get());

    auto op_dest = wallet->GetNewDestination(OutputType::DILITHIUM, "");
    BOOST_REQUIRE(op_dest);
    const CScript scriptPubKey = GetScriptForDestination(*op_dest);
    const CKeyID keyid = ToKeyID(std::get<DilithiumPKHash>(*op_dest));

    BOOST_REQUIRE(wallet->EncryptWallet("qbtc-pass"));
    // EncryptWallet leaves the wallet locked.
    LegacyScriptPubKeyMan* spk_man = wallet->GetLegacyScriptPubKeyMan();
    BOOST_REQUIRE(spk_man);

    // Ownership is still recognised while locked (no secret needed).
    BOOST_CHECK_EQUAL(wallet->IsMine(scriptPubKey), ISMINE_SPENDABLE);

    // While locked, the private key cannot be produced.
    {
        LOCK(spk_man->cs_KeyStore);
        CDilithiumKey locked_key;
        BOOST_CHECK(!spk_man->GetDilithiumKey(keyid, locked_key));
    }

    // After unlocking, the key decrypts and can sign.
    BOOST_REQUIRE(wallet->Unlock("qbtc-pass"));
    const CAmount amount = 0;
    const CTransaction txCredit{BuildCreditingTransaction(scriptPubKey, amount)};
    CMutableTransaction txSpend = BuildSpendingTransaction(CScript(), CScriptWitness(), txCredit);
    SignatureData sigdata;
    {
        LOCK(spk_man->cs_KeyStore);
        CDilithiumKey key;
        BOOST_CHECK(spk_man->GetDilithiumKey(keyid, key));
        BOOST_REQUIRE(SignSignature(*spk_man, scriptPubKey, txSpend, 0, amount, SIGHASH_ALL, sigdata));
    }
    BOOST_CHECK(sigdata.complete);
}

// The post-decryption integrity check has to bind the decrypted secret to the
// public key the record was stored under. It used to compare the stored public
// key with itself (key.Set() caches it, GetPubKey() echoes it), so a "dckey"
// record pairing one key's secret with another's public key decrypted cleanly
// and then signed with a key nothing on the chain could verify.
BOOST_AUTO_TEST_CASE(decrypt_dilithium_key_rejects_mismatched_pubkey)
{
    const CKeyingMaterial master_key(WALLET_CRYPTO_KEY_SIZE, 0x42);
    const CDilithiumKey good = GenerateRandomDilithiumKey();
    const CDilithiumKey other = GenerateRandomDilithiumKey();
    BOOST_REQUIRE(good.IsValid() && other.IsValid());
    const CDilithiumPubKey right_pub = good.GetPubKey();
    const CDilithiumPubKey wrong_pub = other.GetPubKey();
    const CKeyingMaterial secret(good.begin(), good.end());

    // An honest record still loads, and yields a key that signs under its pubkey.
    std::vector<unsigned char> honest;
    BOOST_REQUIRE(EncryptSecret(master_key, secret, right_pub.GetHash(), honest));
    CDilithiumKey loaded;
    BOOST_CHECK(DecryptDilithiumKey(master_key, honest, right_pub, loaded));
    BOOST_REQUIRE(loaded.IsValid());
    BOOST_CHECK(loaded.GetPubKey() == right_pub);
    BOOST_CHECK(loaded.VerifyPubKey(right_pub));

    // The corrupted record: good's secret, stored under other's public key.
    std::vector<unsigned char> franken;
    BOOST_REQUIRE(EncryptSecret(master_key, secret, wrong_pub.GetHash(), franken));
    CDilithiumKey mismatched;
    BOOST_CHECK_MESSAGE(!DecryptDilithiumKey(master_key, franken, wrong_pub, mismatched),
                        "a secret that does not match its stored public key must be refused");

    // ...and the refusal is really about the pairing, not a decryption failure:
    // the ciphertext unwraps to exactly the secret that went in.
    CKeyingMaterial plaintext;
    BOOST_REQUIRE(DecryptSecret(master_key, franken, wrong_pub.GetHash(), plaintext));
    BOOST_CHECK_EQUAL(plaintext.size(), CDilithiumKey::SIZE);
    BOOST_CHECK(std::equal(plaintext.begin(), plaintext.end(), good.begin()));

    // A wrong master key is still rejected too (unchanged behaviour).
    const CKeyingMaterial wrong_master(WALLET_CRYPTO_KEY_SIZE, 0x43);
    CDilithiumKey wrong_pass;
    BOOST_CHECK(!DecryptDilithiumKey(wrong_master, honest, right_pub, wrong_pass));
}

// A key generated on an already-encrypted, unlocked wallet is stored encrypted
// and survives a lock/unlock cycle.
BOOST_AUTO_TEST_CASE(wallet_generate_on_encrypted_wallet)
{
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;
    auto wallet = MakeLegacyWallet(chain.get());

    BOOST_REQUIRE(wallet->EncryptWallet("qbtc-pass"));

    // Locked wallet cannot generate a new Dilithium key.
    BOOST_CHECK(!wallet->GetNewDestination(OutputType::DILITHIUM, ""));

    // Unlock, generate, then lock and confirm ownership persists.
    BOOST_REQUIRE(wallet->Unlock("qbtc-pass"));
    auto op_dest = wallet->GetNewDestination(OutputType::DILITHIUM, "");
    BOOST_REQUIRE(op_dest);
    const CKeyID keyid = ToKeyID(std::get<DilithiumPKHash>(*op_dest));
    const CScript scriptPubKey = GetScriptForDestination(*op_dest);

    BOOST_REQUIRE(wallet->Lock());
    BOOST_CHECK_EQUAL(wallet->IsMine(scriptPubKey), ISMINE_SPENDABLE);

    LegacyScriptPubKeyMan* spk_man = wallet->GetLegacyScriptPubKeyMan();
    BOOST_REQUIRE(spk_man);
    BOOST_REQUIRE(wallet->Unlock("qbtc-pass"));
    LOCK(spk_man->cs_KeyStore);
    CDilithiumKey key;
    BOOST_CHECK(spk_man->GetDilithiumKey(keyid, key));
    BOOST_CHECK(key.GetPubKey().GetID() == keyid);
}

// Phase 7 (Critical: key backup/recovery). Every Dilithium key the wallet hands
// out is deterministically derived from the wallet's Dilithium HD seed. Backing up
// that single seed is therefore sufficient to recover all keys: here we re-derive
// them from just the seed and confirm they match what the wallet generated.
BOOST_AUTO_TEST_CASE(wallet_dilithium_hd_recovery)
{
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;
    auto wallet = MakeLegacyWallet(chain.get());

    LegacyScriptPubKeyMan* spk_man = wallet->GetLegacyScriptPubKeyMan();
    BOOST_REQUIRE(spk_man);

    constexpr uint32_t N = 4;
    std::vector<CKeyID> generated;
    for (uint32_t i = 0; i < N; ++i) {
        auto op_dest = wallet->GetNewDestination(OutputType::DILITHIUM, "");
        BOOST_REQUIRE(op_dest);
        generated.push_back(ToKeyID(std::get<DilithiumPKHash>(*op_dest)));
    }

    // Extract the master seed (the single thing a user needs to back up).
    uint256 master_seed;
    {
        LOCK(spk_man->cs_KeyStore);
        BOOST_REQUIRE(spk_man->HasDilithiumHDSeed());
        BOOST_REQUIRE(spk_man->GetDilithiumHDSeed(master_seed));
    }

    // Recovery: re-derive each key from the seed alone; it must match, in order.
    for (uint32_t i = 0; i < N; ++i) {
        CDilithiumKey k;
        k.MakeNewKeyFromSeed(DeriveDilithiumChildSeed(master_seed, i));
        BOOST_REQUIRE(k.IsValid());
        BOOST_CHECK_MESSAGE(k.GetPubKey().GetID() == generated[i],
                            "recovered key " << i << " does not match wallet-generated key");
    }
}

// The Dilithium HD seed survives an encrypt + lock/unlock cycle and still
// re-derives the same keys (recovery works on encrypted wallets too).
BOOST_AUTO_TEST_CASE(wallet_dilithium_hd_recovery_encrypted)
{
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;
    auto wallet = MakeLegacyWallet(chain.get());

    auto op_dest = wallet->GetNewDestination(OutputType::DILITHIUM, "");
    BOOST_REQUIRE(op_dest);
    const CKeyID id0 = ToKeyID(std::get<DilithiumPKHash>(*op_dest));

    BOOST_REQUIRE(wallet->EncryptWallet("qbtc-pass"));
    BOOST_REQUIRE(wallet->Unlock("qbtc-pass"));

    LegacyScriptPubKeyMan* spk_man = wallet->GetLegacyScriptPubKeyMan();
    BOOST_REQUIRE(spk_man);

    uint256 master_seed;
    {
        LOCK(spk_man->cs_KeyStore);
        BOOST_REQUIRE(spk_man->GetDilithiumHDSeed(master_seed));
    }

    // The first (pre-encryption) key must re-derive from the decrypted seed.
    CDilithiumKey k0;
    k0.MakeNewKeyFromSeed(DeriveDilithiumChildSeed(master_seed, 0));
    BOOST_REQUIRE(k0.IsValid());
    BOOST_CHECK(k0.GetPubKey().GetID() == id0);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet

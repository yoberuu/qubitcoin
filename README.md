QubitCoin ($QBTC)
=================

https://qubitcoin.org

QubitCoin is a post-quantum cryptocurrency built on Bitcoin Core. It keeps
Bitcoin's UTXO model, consensus structure, and node software, but replaces ECDSA
with **pure Dilithium (ML-DSA-65, FIPS 204) signatures** from genesis. No
hybrids, no fallbacks: a transaction that isn't signed with Dilithium is invalid
on this chain.

Read this before using mainnet
------------------------------

> **QubitCoin mainnet is experimental. Do not store significant value on it.**
>
> - **No professional third-party audit has been performed.** What exists is an
>   internal cryptographic and consensus review, documented in full — including
>   the parts that still need attention — in
>   [doc/dilithium-crypto-audit.md](doc/dilithium-crypto-audit.md).
> - The Dilithium integration has been reviewed from first principles and is
>   covered by consensus-level tests, measured size/fee models, and end-to-end
>   node testing. That reduces risk; it does not eliminate it. **Bugs are still
>   possible, including bugs that lose coins.**
> - **Consensus or wallet changes may still be required.** If a serious flaw is
>   found, fixing it could mean a hard fork, a chain restart, or a wallet format
>   change. Nothing about this chain should be treated as final.
> - Post-quantum keys and signatures are large. Fees are higher and throughput
>   is lower than Bitcoin's, by design and by physics — see
>   [Known limitations](#known-limitations).
> - Back up your wallet file. There is no seed phrase and no private key export
>   on this chain: see [doc/qubitcoin-recovery.md](doc/qubitcoin-recovery.md).
>
> Treat mainnet as a public experiment that happens to be running for real, with
> real block times and a real difficulty adjustment — not as a store of value.

What QubitCoin is
-----------------

- **A pure Dilithium UTXO chain.** Every spend is authorised by an ML-DSA-65
  signature. ECDSA and Schnorr are consensus-invalid: there is no code path that
  accepts them, and no legacy key can spend a coin here.
- **A fresh chain.** New genesis block, no imported balances, no Bitcoin history.
  Nothing was carried over except the software.
- **Bitcoin-like monetary policy at 10× the unit scale.** 500 QBTC initial block
  subsidy, halving every 210,000 blocks, 10-minute target spacing — a total
  supply of 210,000,000 QBTC.
- **A grassroots experiment.** QubitCoin is not trying to replace Bitcoin or
  claim to be an improvement on it. It exists to find out what a clean-slate,
  quantum-aware UTXO chain actually looks like when you commit fully to
  post-quantum cryptography and stay close to a codebase that has been attacked
  for over fifteen years.

### Why a pure fork instead of a hybrid

Signature schemes are a one-way door. Once keys and addresses are in the wild,
migrating later means moving every coin and hoping everyone follows along. A
pure Dilithium chain lets us prove the whole stack works — consensus, mempool,
wallet, P2P, compact blocks — with one signature type and one set of
assumptions, instead of a hypothetical flag day.

Key differences from Bitcoin
----------------------------

| | Bitcoin | QubitCoin |
|---|---------|-----------|
| Signature scheme | ECDSA / Schnorr (secp256k1) | Dilithium (ML-DSA-65) only |
| Public key / signature | 33 B / ~72 B | 1,952 B / 3,309 B |
| Total supply | 21,000,000 BTC | 210,000,000 QBTC |
| Initial block subsidy | 50 BTC | 500 QBTC |
| Genesis block | Bitcoin genesis | Fresh QubitCoin genesis |
| Address type | bech32 (P2WPKH) | Dilithium P2PKH (`Q…` on mainnet) |
| bech32 HRP | `bc` | `qc` |
| P2P / RPC port | 8333 / 8332 | 2096 / 2095 |
| Dust threshold | ~546 sat | ~16,035 sat (bare), ~4,170 sat (witness) |
| 1-in-1-out spend | ~110 vB | ~5,330 vB (bare), ~1,378 vB (witness) |

Block structure, the halving schedule shape, the P2P protocol, the RPC surface,
and the wallet architecture are all kept close to Bitcoin Core, so anyone who
has run `bitcoind` will feel at home.

### Mainnet parameters

| Parameter | Value |
|-----------|-------|
| Chain flag | none (default) or `-chain=main` |
| Magic bytes | `0x51 0x42 0x54 0x43` ("QBTC") |
| P2P port | **2096** |
| RPC port | **2095** |
| Tor onion port | **2097** |
| Dilithium addresses | Base58Check version byte 58 (`Q…` prefix) |
| bech32 HRP | `qc` |
| Genesis hash | `000000002f4fcc60ef61353d1767c691562dd380f240c1fcf47bf0e1c655d011` |
| Data directory | `~/.qubitcoin/` (config file `qubitcoin.conf`) |
| Subsidy halving | every 210,000 blocks |
| Consensus | BIP34/65/66/CSV at height 1, segwit at height 0, Taproot always active |
| Assumed-valid / min chain work | zeroed — every block is fully verified |
| Checkpoints | genesis only |

Known limitations
-----------------

These are real properties of the current code, not a roadmap. Plan around them.

- **No professional audit.** The only review is internal
  ([doc/dilithium-crypto-audit.md](doc/dilithium-crypto-audit.md)), which lists
  both what was fixed and what remains open.
- **Transactions are large and fees are correspondingly higher.** An ML-DSA-65
  signature is 3,309 bytes and a public key is 1,952 bytes, so a one-input,
  one-output bare Dilithium spend is ~5,330 vB — roughly 50× a Bitcoin P2WPKH
  spend. At the 1 sat/vB relay minimum that is ~5,300 sat in fees; at the
  wallet's 10 sat/vB fallback rate, ~53,000 sat. Throughput is proportionally
  lower: a standard transaction fits about **18 bare Dilithium inputs** before
  hitting the 400,000 WU standardness limit.
- **Witness Dilithium is ~3.9× cheaper, but the wallet does not use it yet.**
  Spending a Dilithium key through a P2WPKH-shaped output costs 5,433 WU per
  input against 21,244 WU for the bare P2PKH form (a 1-in-1-out spend measures
  5,511 WU against 21,320 WU), so roughly 73 witness inputs fit in a standard
  transaction where 18 bare ones do. That form is consensus-valid and is modelled
  correctly by dust and fee estimation, but the wallet currently only generates
  and pays bare Dilithium P2PKH addresses. Getting the cheaper form into the
  wallet is future work.
- **Dust thresholds are high.** ~16,035 sat for an output that will be spent
  bare, ~4,170 sat for the witness form. Below that, an output costs more to
  spend than it is worth and will not relay.
- **Legacy Bitcoin address types are unspendable here, and the wallet refuses to
  pay them.** A legacy `PKHash`, P2SH, P2WPKH, P2WSH, or Taproot destination can
  receive coins that nobody can ever spend. Every send RPC and the GUI reject
  non-Dilithium destinations, and `validateaddress` reports
  `"ispostquantum": false` plus an explicit warning. This protects the sends you
  make with this software; it cannot protect a payment made by other software.
- **Txid malleability on non-witness spends.** Bare Dilithium P2PKH spends carry
  the signature in the scriptSig, which BIP143 does not commit to. A third party
  cannot forge the signature, but it can re-encode the pushes around it — for
  example with `OP_PUSHDATA4` — leaving the spend valid under mandatory consensus
  flags while changing the txid, exactly as in pre-segwit Bitcoin. Since the bare
  form is the only one the wallet produces, this affects every spend in practice:
  do not build anything on unconfirmed txids. The witness form is not affected.
- **No message signing.** `signmessage` / `verifymessage` are ECDSA-only and
  fail on Dilithium addresses (`Address does not refer to key`). Proving control
  of an address off-chain is not supported yet.
- **No private key export or import.** There is no `dumpprivkey`, no key import,
  and `dumpwallet` writes a file containing **no keys at all**. The wallet file
  is the only backup. See
  [doc/qubitcoin-recovery.md](doc/qubitcoin-recovery.md).
- **Descriptor wallets are not supported for Dilithium.** Dilithium keys live in
  the legacy key manager; descriptor wallets remain ECDSA-shaped and therefore
  cannot hold spendable keys on this chain.
- **Some upstream Bitcoin test vectors fail by design.** Large parts of Bitcoin
  Core's script and key corpora assert that ECDSA signatures and legacy key
  encodings are valid. On a Dilithium-only chain they are not, so those vectors
  fail. The failures are catalogued in the audit document; the Dilithium-specific
  suites are the ones that must pass.
- **Peer discovery is not deployed on mainnet yet.** There are no DNS seeds and
  no compiled-in fixed seeds for mainnet, so a new node finds no peers on its
  own. Use `-addnode`/`-connect` until seed infrastructure is live.

Safety features already implemented
-----------------------------------

None of these make the chain audited. They close specific failure modes that the
internal review found, and each has regression tests.

- **Startup self-test.** `dilithium::SelfTest()` runs in the node's sanity
  checks: it verifies the linked liboqs still reports ML-DSA-65's expected key
  and signature sizes, re-checks the pinned seed→key known-answer test, and does
  a sign/verify round trip plus a mutated-signature negative case. If any part
  fails, **the node refuses to start** rather than risk deriving the wrong keys
  or misvalidating blocks.
- **Explicit signature length enforcement.** ML-DSA-65 signatures are a fixed
  3,309 bytes; the verifier requires exactly that and rejects truncated, padded,
  or over-long signatures instead of relying on the library to notice.
- **Domain-separated signing message.** A Dilithium key signs a BIP340-style
  tagged hash of the BIP143 sighash, tagged `QBTC-ML-DSA-65-SIGHASH`, so what it
  signs can never be confused with a Bitcoin ECDSA or Schnorr digest. The signer
  and the verifier obtain that message from one shared function.
- **Defined hashtype allow-list.** Only the six meaningful sighash bytes
  (`SIGHASH_ALL`/`NONE`/`SINGLE`, each with and without `ANYONECANPAY`) are
  accepted; every other value is rejected as a script error. Undefined bytes stay
  undefined instead of becoming a malleability vector.
- **Address burn protection.** Non-Dilithium destinations are rejected wherever a
  user-supplied address becomes an output — every send RPC, the change-address
  option, and the GUI — with an error that says the funds would be burned.
- **Real wallet key binding check.** Decrypted Dilithium secret material has to
  prove it belongs to the stored public key: the wallet signs a fresh random
  challenge with the secret and verifies that signature against the claimed
  public key. A corrupted or mismatched pair now fails instead of passing a
  comparison of the stored public key against itself.
- **Correct dust and weight modelling.** Dust thresholds, standardness limits,
  and wallet fee estimation use measured Dilithium input sizes for both the bare
  and witness spend forms, rather than leftover ECDSA-sized estimates.

Quick start
-----------

### Build

QubitCoin requires [liboqs](https://github.com/open-quantum-safe/liboqs) with
ML-DSA-65 (`OQS_SIG_alg_ml_dsa_65`) available. The current tree is built, measured,
and tested against **liboqs 0.14.1-dev**.

```bash
git clone <repository-url>   # see https://qubitcoin.org
cd QubitCoin-L1
./autogen.sh
./configure --with-liboqs=yes    # see note below
make -j$(nproc)
```

Pass `--with-liboqs=yes` explicitly. The default is `auto`, which silently
builds a binary *without* Dilithium support if liboqs is not found — and such a
binary cannot run at all, because the startup self-test fails. `=yes` turns a
missing dependency into a clear configure error instead.

**Record the exact liboqs version you built against** (`pkg-config --modversion
liboqs`, and the commit if you built it from source), and keep it with your
backups. Wallet key derivation depends on how liboqs consumes randomness during
key generation; see [doc/qubitcoin-recovery.md](doc/qubitcoin-recovery.md) for
why this matters and how the pinned known-answer test protects you.

Binaries land in `src/`: `qbitcoind`, `qbitcoin-cli`, `qbitcoin-wallet`,
`qbitcoin-tx`, `qbitcoin-util`. See
[doc/build-unix.md](doc/build-unix.md) (and the platform-specific variants) for
the rest of the dependency list.

### Mainnet

```bash
./src/qbitcoind -daemon
./src/qbitcoin-cli getblockchaininfo

# Peer discovery is not deployed yet — add a known peer explicitly:
./src/qbitcoin-cli addnode "PEER_IP:2096" "add"
./src/qbitcoin-cli getpeerinfo

# Wallet
./src/qbitcoin-cli createwallet mywallet
./src/qbitcoin-cli -rpcwallet=mywallet getnewaddress   # returns a Q… address
./src/qbitcoin-cli -rpcwallet=mywallet backupwallet ~/qbtc-wallet.bak
```

Re-read the [warning above](#read-this-before-using-mainnet) before you put
anything you care about on this chain.

### Regtest (local dev — instant blocks, no peers needed)

```bash
./src/qbitcoind -regtest -daemon
./src/qbitcoin-cli -regtest createwallet dev
ADDR=$(./src/qbitcoin-cli -regtest -rpcwallet=dev getnewaddress)
./src/qbitcoin-cli -regtest -rpcwallet=dev generatetoaddress 101 "$ADDR"
./src/qbitcoin-cli -regtest -rpcwallet=dev getbalance
./src/qbitcoin-cli -regtest -rpcwallet=dev sendtoaddress "$ADDR" 10.0
```

Regtest ports: P2P **21096**, RPC **21095**.

### Testnet

```bash
# Recommended: testnet4
./src/qbitcoind -testnet4 -daemon
./src/qbitcoin-cli -testnet4 getblockchaininfo

# Legacy testnet3 (still supported)
./src/qbitcoind -testnet -daemon
```

Testnet4 ports: P2P **42096**, RPC **42095**. Testnet3: P2P **12096**, RPC
**12095**. Full command reference, wallet workflows, encryption, and debugging
tips: **[doc/testnet.md](doc/testnet.md)**.

Wallet, backup, and recovery
----------------------------

Every Dilithium key in a wallet is derived deterministically from a single
32-byte master seed stored in the wallet file:

```
child_seed(i) = HMAC-SHA256(key = master_seed, msg = "QBTC-ML-DSA-65-HD" || LE32(i))
```

The derivation from a child seed to an ML-DSA-65 key pair is pinned by a
known-answer test that runs at startup, so a liboqs upgrade that would change
your addresses stops the node instead of silently producing a different wallet.

Two consequences worth internalising:

1. **Back up the wallet file**, with `backupwallet` or by copying
   `wallets/<name>/` while the node is stopped. There is no seed phrase to write
   down, `dumpwallet` produces nothing usable, and `dumpprivkey` does not work
   for Dilithium addresses. Lose the file and the coins are gone.
2. **Recovery depends on the pinned derivation and on liboqs.** Keep a note of
   the liboqs version alongside the backup.

[doc/qubitcoin-recovery.md](doc/qubitcoin-recovery.md) documents the exact
derivation, the backup and restore procedure, and what happens if the
known-answer test ever fails. The cryptographic reasoning behind it is in
[doc/dilithium-crypto-audit.md](doc/dilithium-crypto-audit.md) §1.

Documentation
-------------

| Doc | Contents |
|-----|----------|
| [doc/qubitcoin-recovery.md](doc/qubitcoin-recovery.md) | Wallet backup, key derivation, recovery |
| [doc/dilithium-crypto-audit.md](doc/dilithium-crypto-audit.md) | Internal Dilithium crypto & consensus audit |
| [doc/testnet.md](doc/testnet.md) | Node operator guide, command reference, limitations |
| [doc/build-unix.md](doc/build-unix.md) | Build instructions (Unix/Linux) |
| [contrib/explorer/README.md](contrib/explorer/README.md) | Docker block explorer (btc-rpc-explorer) |
| [share/examples/qubitcoin.conf](share/examples/qubitcoin.conf) | Example configuration |
| [doc/](doc/) | Additional Bitcoin Core-derived documentation |

License
-------

QubitCoin is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The `qubitcoin-main` branch is regularly built (see `doc/build-*.md` for instructions) and tested, but it is not guaranteed to be
completely stable.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md)
and useful hints for developers can be found in [doc/developer-notes.md](doc/developer-notes.md).

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Tests

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code.

There are also [regression and integration tests](test/README.md), written
in Python.

The Dilithium-specific suites are the ones that must pass on this fork:

```bash
make -C src test/test_bitcoin
for t in dilithium_tests dilithiumkey_tests dilithium_crypto_audit_tests \
         dilithium_address_tests dilithium_size_tests dilithium_mining_tests \
         dilithium_wallet_tests dilithium_ecdsa_audit_suite; do
  ./src/test/test_bitcoin --run_test=$t
done

test/functional/wallet_dilithium_address_safety.py --legacy-wallet
test/functional/wallet_dilithium_mining.py --legacy-wallet
```

Upstream suites that assert ECDSA validity fail by design; see
[doc/dilithium-crypto-audit.md](doc/dilithium-crypto-audit.md).

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.

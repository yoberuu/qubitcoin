# QubitCoin Node & Operator Guide

This guide covers running a node on mainnet, testnet, or local regtest, and the
RPC commands you'll actually use. If you've run `bitcoind` before, you're 90%
of the way there — the binaries are just named `qbitcoind` and `qbitcoin-cli`.

> **Mainnet is experimental.** There has been no professional third-party audit,
> only the internal review in [dilithium-crypto-audit.md](dilithium-crypto-audit.md).
> Bugs are still possible, and consensus or wallet changes may still be needed.
> Do not store significant value on this chain. See the
> [README](../README.md#read-this-before-using-mainnet) for the full warning.

**Status:** Mainnet chain parameters are locked, but seed infrastructure is not
deployed: mainnet has no DNS seeds and no compiled-in fixed seeds, so peers must
be supplied with `-addnode`. Testnet3/testnet4 have live fixed seeds. The faucet
and public block explorer are still being finalized.

---

## Table of contents

1. [Networks at a glance](#networks-at-a-glance)
2. [Quick start — mainnet](#quick-start--mainnet)
3. [Quick start — testnet4](#quick-start--testnet4)
4. [Quick start — regtest](#quick-start--regtest)
5. [Bootstrap & connecting to peers](#bootstrap--connecting-to-peers)
6. [Command reference](#command-reference)
7. [Known limitations](#known-limitations)
8. [Reporting bugs](#reporting-bugs)

---

## Networks at a glance

### Mainnet (default, `-chain=main`)

| Parameter | Value |
|-----------|-------|
| Chain flag | none (default) or `-chain=main` |
| Magic bytes | `0x51 0x42 0x54 0x43` ("QBTC") |
| P2P port | **2096** |
| RPC port | **2095** |
| Tor onion port | **2097** |
| bech32 HRP | `qc` |
| Dilithium addresses | version byte 58 (`Q…` prefix) |
| Genesis hash | `000000002f4fcc60ef61353d1767c691562dd380f240c1fcf47bf0e1c655d011` |
| Data directory | `~/.qubitcoin/` |
| Block subsidy | 500 QBTC, halving every 210,000 blocks (210,000,000 QBTC total) |
| Target spacing | 10 minutes, retarget every 2016 blocks |
| Peer discovery | **none deployed yet** — use `-addnode` |

### Testnet4 — recommended testnet (`-testnet4`)

| Parameter | Value |
|-----------|-------|
| Chain flag | `-testnet4` or `-chain=testnet4` |
| Magic bytes | `0x51 0x62 0x74 0x34` ("Qbt4") |
| P2P port | **42096** |
| RPC port | **42095** |
| Tor onion port | **42097** |
| bech32 HRP | `trq` |
| Dilithium addresses | version byte 121 (`r...` prefix) |
| Genesis hash | `00000000f0760be464eb2acd0069f5fbd4e50638c8b629c5d6ac50966c060636` |
| Data directory | `~/.qubitcoin/testnet4/` |
| Extra rule | `enforce_BIP94` (time-warp mitigation) |

### Testnet3 (`-testnet`)

| Parameter | Value |
|-----------|-------|
| Chain flag | `-testnet` or `-chain=test` |
| Magic bytes | `0x51 0x62 0x74 0x33` ("Qbt3") |
| P2P port | **12096** |
| RPC port | **12095** |
| Tor onion port | **12097** |
| bech32 HRP | `tq` |
| Dilithium addresses | version byte 120 (`q...` prefix) |
| Genesis hash | `00000000c0f906a85aca8c26722998dd6292ef5c88f5912963eed730df17f09a` |
| Data directory | `~/.qubitcoin/testnet3/` |

### Regtest (local only)

| Parameter | Value |
|-----------|-------|
| Chain flag | `-regtest` or `-chain=regtest` |
| P2P port | **21096** |
| RPC port | **21095** |
| Data directory | `~/.qubitcoin/regtest/` |
| Notes | Instant mining, no peers required |

### Consensus (all networks)

Fresh Dilithium-only chains with modern rules from genesis:

- BIP34, BIP65, BIP66, CSV: height **1**
- Segwit: height **0**
- Taproot: **ALWAYS_ACTIVE**
- `nMinimumChainWork` and `defaultAssumeValid`: **zeroed** (every block verified)
- Checkpoints: genesis only

---

## Quick start — mainnet

```bash
# 1. Start the node (mainnet is the default chain — no flag needed)
qbitcoind -daemon

# 2. Confirm you're on the right chain
qbitcoin-cli getblockchaininfo
# chain should be "main"; the genesis hash is
# 000000002f4fcc60ef61353d1767c691562dd380f240c1fcf47bf0e1c655d011

# 3. Add peers by hand — mainnet has no DNS or fixed seeds yet
qbitcoin-cli addnode "PEER_IP:2096" "add"
qbitcoin-cli getpeerinfo

# 4. Create a wallet and back it up immediately
qbitcoin-cli createwallet mywallet
qbitcoin-cli -rpcwallet=mywallet getnewaddress          # returns a Q… address
qbitcoin-cli -rpcwallet=mywallet backupwallet ~/mywallet.bak
```

The wallet file is the only backup that exists — there is no seed phrase and
`dumpwallet` writes no keys. Read
[qubitcoin-recovery.md](qubitcoin-recovery.md) before you receive coins.

Everything in the [command reference](#command-reference) below works on mainnet:
drop the `-regtest` flag entirely rather than replacing it.

---

## Quick start — testnet4

```bash
# 1. Start the node
qbitcoind -testnet4 -daemon

# 2. Confirm you're on the right chain
qbitcoin-cli -testnet4 getblockchaininfo
# bestblockhash should be: 00000000f0760be464eb2acd0069f5fbd4e50638c8b629c5d6ac50966c060636

# 3. Create a wallet (Dilithium is the default address type)
qbitcoin-cli -testnet4 createwallet mywallet

# 4. Get a receive address
qbitcoin-cli -testnet4 -rpcwallet=mywallet getnewaddress
# Returns an r... Dilithium address on testnet4

# 5. Check peer connectivity
qbitcoin-cli -testnet4 getnetworkinfo
qbitcoin-cli -testnet4 getpeerinfo
```

**Getting test coins:** Once the public testnet is live, a faucet will distribute
QBTC. Until then, you can mine blocks if you have hashpower on the testnet, or
ask a peer operator to send to your address. On regtest you can mine instantly
(see below).

**Stopping the node** (always prefer RPC over `kill`):

```bash
qbitcoin-cli -testnet4 stop
```

---

## Quick start — regtest

Regtest is the fastest way to try QubitCoin without waiting for peers or a
faucet. Blocks mine instantly.

```bash
# Start
qbitcoind -regtest -daemon

# Wallet + mine 101 blocks (100 needed before coinbase matures)
qbitcoin-cli -regtest createwallet dev
ADDR=$(qbitcoin-cli -regtest -rpcwallet=dev getnewaddress)
qbitcoin-cli -regtest -rpcwallet=dev generatetoaddress 101 "$ADDR"

# Verify
qbitcoin-cli -regtest -rpcwallet=dev getbalance
qbitcoin-cli -regtest getblockchaininfo

# Send coins
DEST=$(qbitcoin-cli -regtest -rpcwallet=dev getnewaddress)
qbitcoin-cli -regtest -rpcwallet=dev sendtoaddress "$DEST" 25.0
qbitcoin-cli -regtest -rpcwallet=dev generatetoaddress 1 "$ADDR"   # confirm tx

# Stop
qbitcoin-cli -regtest stop
```

---

## Bootstrap & connecting to peers

### Automatic peer discovery

By default, `qbitcoind` uses DNS seeds and fixed seeds to find peers. On
QubitCoin only the testnets have them so far:

| Network  | Seed nodes |
|----------|------------|
| mainnet  | **none deployed** — supply peers with `-addnode` or `-connect` |
| testnet3 | `142.93.6.69:12096`, `142.93.12.49:12096` |
| testnet4 | `142.93.6.69:42096`, `142.93.12.49:42096` |

On the testnets, new nodes should connect automatically after startup. On mainnet
a fresh node will sit at zero connections until you give it a peer, because
`vSeeds` and `vFixedSeeds` are both empty for `main` in
`src/kernel/chainparams.cpp`. Use `-addnode` (manual section below).

### Manual peer connection

If you know a peer's IP or hostname:

```bash
# On startup
qbitcoind -testnet4 -addnode=PEER_IP:42096 -daemon

# Or while running
qbitcoin-cli -testnet4 addnode "PEER_IP:42096" "add"
qbitcoin-cli -testnet4 getpeerinfo
```

### Configuration file

Copy [share/examples/qubitcoin.conf](../share/examples/qubitcoin.conf) to your
data directory and uncomment network-specific options:

```ini
[testnet4]
testnet4=1
# addnode=seed.example.com:42096
```

### Updating fixed seeds (operators)

1. Edit `contrib/seeds/nodes_testnet4.txt` (or `nodes_test.txt` for testnet3)
2. Run `python3 contrib/seeds/generate-seeds.py contrib/seeds`
3. Rebuild and redeploy

DNS seed hostnames are commented in `src/kernel/chainparams.cpp` — uncomment
when live infrastructure exists.

---

## Command reference

Throughout this section, replace `-regtest` with `-testnet4` or `-testnet` as
needed, or drop the chain flag entirely for mainnet. Add `-rpcwallet=WALLET` when
a command requires a loaded wallet.

### Node startup & shutdown

```bash
# Regtest
qbitcoind -regtest -daemon
qbitcoind -regtest -daemon -datadir=/path/to/data

# Testnet4 (recommended)
qbitcoind -testnet4 -daemon

# Testnet3
qbitcoind -testnet -daemon

# Foreground with debug output (no -daemon)
qbitcoind -regtest -printtoconsole -debug=net,rpc,wallet

# Stop gracefully
qbitcoin-cli -regtest stop
qbitcoin-cli -testnet4 stop
```

### Chain & network info

```bash
qbitcoin-cli -regtest getblockchaininfo
qbitcoin-cli -regtest getnetworkinfo
qbitcoin-cli -regtest getpeerinfo
qbitcoin-cli -regtest getconnectioncount
qbitcoin-cli -regtest getmempoolinfo
qbitcoin-cli -regtest getrawmempool
qbitcoin-cli -regtest getmininginfo
qbitcoin-cli -regtest getblockcount
qbitcoin-cli -regtest getbestblockhash

# Inspect a specific block
qbitcoin-cli -regtest getblock "$(qbitcoin-cli -regtest getbestblockhash)" 2
```

### Wallet creation & loading

```bash
# Create a legacy Dilithium wallet (default and recommended)
qbitcoin-cli -regtest createwallet mywallet

# Create with options
qbitcoin-cli -regtest createwallet mywallet false false "" false false true
# args: name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors, load_on_startup

# List and load wallets
qbitcoin-cli -regtest listwallets
qbitcoin-cli -regtest listwalletdir
qbitcoin-cli -regtest loadwallet mywallet
qbitcoin-cli -regtest unloadwallet mywallet

# Wallet info
qbitcoin-cli -regtest -rpcwallet=mywallet getwalletinfo
```

### Address generation

```bash
# Default: Dilithium P2PKH (q... on regtest/testnet3, r... on testnet4)
qbitcoin-cli -regtest -rpcwallet=mywallet getnewaddress
qbitcoin-cli -regtest -rpcwallet=mywallet getnewaddress "" "dilithium"

# Change address
qbitcoin-cli -regtest -rpcwallet=mywallet getrawchangeaddress

# Address details
qbitcoin-cli -regtest -rpcwallet=mywallet getaddressinfo "qYOUR_ADDRESS"
qbitcoin-cli -regtest -rpcwallet=mywallet listreceivedbyaddress 0 true

# Validate an address
qbitcoin-cli -regtest validateaddress "qYOUR_ADDRESS"
```

### Mining & getting coins

```bash
# Regtest: mine blocks to your address (instant)
ADDR=$(qbitcoin-cli -regtest -rpcwallet=mywallet getnewaddress)
qbitcoin-cli -regtest -rpcwallet=mywallet generatetoaddress 101 "$ADDR"

# Mine to a specific address without wallet
qbitcoin-cli -regtest generatetoaddress 10 "qADDRESS"

# Testnet4: after the tip is >20 minutes old, min-difficulty applies and
# CPU generatetoaddress succeeds with the default maxtries budget.
# Use a Dilithium address (getnewaddress "" "dilithium").
qbitcoin-cli -testnet4 -rpcwallet=mywallet generatetoaddress 1 "$ADDR"

# Mining several blocks back-to-back: only the first after a 20+ minute gap is
# easy. Subsequent blocks within 20 minutes inherit the tip's retained difficulty
# (genesis-level) unless you wait again or pass a much larger maxtries.
qbitcoin-cli -testnet4 generatetoaddress 1 "$ADDR" 100000000

# If mining fails with "Failed to find a valid proof-of-work within maxtries",
# raise maxtries or wait for the min-difficulty rule.
```

Coinbase outputs mature after **100 blocks**. Mine at least 101 before spending.

Note: wallet logs may show `Legacy Wallet Keys: 0` and an empty ECDSA keypool even
after `getnewaddress` — that is expected. Dilithium keys are counted on the
separate `Dilithium Wallet Keys:` log line and are not part of the ECDSA keypool.

### Sending transactions

```bash
# Simple send
qbitcoin-cli -regtest -rpcwallet=mywallet sendtoaddress "qDEST" 1.5

# Send with comment
qbitcoin-cli -regtest -rpcwallet=mywallet sendtoaddress "qDEST" 1.5 "donation" "invoice-42"

# Set explicit fee rate (sat/vB) if needed
qbitcoin-cli -regtest -rpcwallet=mywallet sendtoaddress "qDEST" 1.5 "" "" false true null "unset" 0.00005000

# Send to multiple recipients
qbitcoin-cli -regtest -rpcwallet=mywallet sendmany "" '{"qADDR1":1.0,"qADDR2":2.0}'

# Multi-input transactions happen automatically when the wallet has
# multiple UTXOs and needs them to fund a send. To build multi-input txs
# deliberately:
qbitcoin-cli -regtest -rpcwallet=mywallet sendtoaddress "$A" 10
qbitcoin-cli -regtest -rpcwallet=mywallet sendtoaddress "$A" 10
qbitcoin-cli -regtest -rpcwallet=mywallet sendtoaddress "$A" 10
qbitcoin-cli -regtest generatetoaddress 1 "$ADDR"    # confirm
qbitcoin-cli -regtest -rpcwallet=mywallet sendtoaddress "$B" 25   # uses multiple inputs

# Confirm a pending tx
qbitcoin-cli -regtest generatetoaddress 1 "$ADDR"
```

### Balances & transaction history

```bash
qbitcoin-cli -regtest -rpcwallet=mywallet getbalance
qbitcoin-cli -regtest -rpcwallet=mywallet getunconfirmedbalance
qbitcoin-cli -regtest -rpcwallet=mywallet listtransactions
qbitcoin-cli -regtest -rpcwallet=mywallet listtransactions "*" 10
qbitcoin-cli -regtest -rpcwallet=mywallet gettransaction "TXID"
qbitcoin-cli -regtest getrawtransaction "TXID" true
qbitcoin-cli -regtest -rpcwallet=mywallet listunspent
qbitcoin-cli -regtest -rpcwallet=mywallet listunspent 1 9999999 '["qADDR"]'
```

### Encryption & recovery

```bash
# Encrypt an existing wallet
qbitcoin-cli -regtest -rpcwallet=mywallet encryptwallet "my secret passphrase"
# Wallet will stop; reload it after encrypting

qbitcoin-cli -regtest loadwallet mywallet

# Unlock for sending (timeout in seconds)
qbitcoin-cli -regtest -rpcwallet=mywallet walletpassphrase "my secret passphrase" 300

# Lock again
qbitcoin-cli -regtest -rpcwallet=mywallet walletlock

# Change passphrase
qbitcoin-cli -regtest -rpcwallet=mywallet walletpassphrasechange "old" "new"

# Backup (do this before and after encrypting)
qbitcoin-cli -regtest -rpcwallet=mywallet backupwallet /path/to/mywallet.bak

# Restore into a named wallet
qbitcoin-cli -regtest restorewallet mywallet /path/to/mywallet.bak
# Or manually: stop node, replace wallet.dat in wallets/mywallet/, restart
```

The wallet file is the **only** backup on this chain. There is no seed phrase,
`dumpprivkey` does not work for Dilithium addresses, and `dumpwallet` succeeds
while writing a file that contains no keys at all — it is not a backup. Full
details, including the exact key derivation and what recovery depends on:
**[qubitcoin-recovery.md](qubitcoin-recovery.md)**.

### Low-level / debugging

```bash
# Decode a raw transaction
qbitcoin-cli -regtest decoderawtransaction "HEX"

# Create and sign a raw transaction (advanced)
qbitcoin-cli -regtest createrawtransaction '[{"txid":"...","vout":0}]' '{"qADDR":1.0}'
qbitcoin-cli -regtest -rpcwallet=mywallet fundrawtransaction "HEX"
qbitcoin-cli -regtest -rpcwallet=mywallet signrawtransactionwithwallet "HEX"

# Estimate fees
qbitcoin-cli -regtest estimatesmartfee 6

# Note: signmessage / verifymessage are ECDSA-only and fail on Dilithium
# addresses with "Address does not refer to key". Message signing is not
# available on this chain.

# Node health
qbitcoin-cli -regtest getmemoryinfo
qbitcoin-cli -regtest uptime
qbitcoin-cli -regtest getchaintxstats
qbitcoin-cli -regtest gettxoutsetinfo

# Rescan after import (can be slow)
qbitcoin-cli -regtest -rpcwallet=mywallet rescanblockchain
```

### Multi-node regtest (P2P testing)

Terminal 1 — node A:

```bash
qbitcoind -regtest -datadir=/tmp/qbtc-a -daemon -port=21096
qbitcoin-cli -regtest -datadir=/tmp/qbtc-a createwallet w
ADDR=$(qbitcoin-cli -regtest -datadir=/tmp/qbtc-a -rpcwallet=w getnewaddress)
qbitcoin-cli -regtest -datadir=/tmp/qbtc-a -rpcwallet=w generatetoaddress 101 "$ADDR"
```

Terminal 2 — node B, connect to A:

```bash
qbitcoind -regtest -datadir=/tmp/qbtc-b -daemon -port=21097 -rpcport=21098 \
  -connect=127.0.0.1:21096
qbitcoin-cli -regtest -datadir=/tmp/qbtc-b getpeerinfo
qbitcoin-cli -regtest -datadir=/tmp/qbtc-a getpeerinfo
```

---

## Dilithium × ECDSA audit suite

A self-contained mainnet-readiness audit lives at
`src/test/dilithium_ecdsa_audit_suite.cpp`. It prints PASS/FAIL consensus
checks, Dilithium correctness proofs, size/fee economics, mining sanity, and a
structured readiness report.

```bash
# Build tests, then run the audit (report goes to stdout)
make -C src test/test_bitcoin
./src/test/test_bitcoin --run_test=dilithium_ecdsa_audit_suite --log_level=all
```

---

## Known limitations

These are real constraints on the current codebase — not bugs, but things to
plan around:

| Limitation | Detail |
|------------|--------|
| **No professional audit** | The only review is internal: [dilithium-crypto-audit.md](dilithium-crypto-audit.md). Mainnet is experimental. |
| **Large transactions** | An ML-DSA-65 signature is 3,309 B and a public key 1,952 B. A 1-in-1-out bare Dilithium spend is ~5,330 vB (~50× a Bitcoin P2WPKH spend), and a standard tx tops out around **18 inputs** in the bare form, or **73** in the witness form, before hitting the 400,000 WU limit. |
| **Witness form is ~3.9× cheaper, but unused by the wallet** | 5,433 WU per witness Dilithium input against 21,244 WU bare (1-in-1-out spends: 5,511 WU against 21,320 WU). Consensus-valid and correctly modelled by dust/fee estimation, but the wallet only generates and pays bare Dilithium P2PKH addresses today. |
| **Dust threshold** | Depends on how the output is spent: **~16,035 sat** (0.00016035 QBTC) for a bare Dilithium address, **~4,170 sat** for a witness one. Below that an output costs more to spend than it is worth and won't be relayed. |
| **Fees** | Minimum relay rate is 1,000 sat/kvB (1 sat/vB) and the wallet's fallback rate is 10,000 sat/kvB (10 sat/vB) — so a single 1-in-1-out bare spend costs roughly 5,300–53,000 sat. Large PQ txs incurring noticeable fees is expected. |
| **Txid malleability on bare spends** | Bare Dilithium P2PKH puts the signature in the scriptSig, which BIP143 does not commit to. A third party can't forge the signature, but it can re-encode the pushes around it (e.g. `OP_PUSHDATA4`) and change the txid while the spend stays valid, as in pre-segwit Bitcoin. Don't depend on unconfirmed txids. The witness form is unaffected. |
| **Wallet type** | Dilithium keys live in the legacy key manager. Descriptor wallets are secp256k1-shaped and cannot hold spendable keys here. |
| **No message signing** | `signmessage` / `verifymessage` are ECDSA-only and fail on Dilithium addresses. |
| **No key export/import** | No `dumpprivkey`, no key import, and `dumpwallet` writes a keyless file. Back up the wallet file: [qubitcoin-recovery.md](qubitcoin-recovery.md). |
| **ECDSA disabled** | There is no ECDSA on this chain. Legacy Bitcoin addresses and scripts are not valid for spending. Paying one would burn the coins, so the wallet refuses: every send RPC and the GUI reject any destination that is not a Dilithium address, and `validateaddress` reports `ispostquantum: false` plus a warning for the rest. |
| **Upstream test vectors fail by design** | Bitcoin Core's script and key corpora assert that ECDSA signatures and legacy key encodings are valid; on a Dilithium-only chain they aren't. The Dilithium suites are the ones that must pass. |
| **Peer discovery** | Mainnet has **no** DNS or fixed seeds yet — use `-addnode`. Testnet3/testnet4 fixed seeds are live (see bootstrap section). |
| **No faucet yet** | Testnet coins require mining or a friendly peer until the faucet launches. |

---

## Reporting bugs

Found something broken? We'd rather hear about it early.

**Before filing:**

1. Confirm you're on the right network (`getblockchaininfo` → check `chain` and `bestblockhash`)
2. Note your version (`qbitcoind --version` or `getnetworkinfo` → `subversion`)
3. Capture relevant logs from `debug.log` in your data directory
4. For wallet issues, include whether the wallet is encrypted and the output of `getwalletinfo`

**What to include in a bug report:**

- Network: regtest / testnet3 / testnet4
- Steps to reproduce
- Expected vs actual behavior
- Relevant RPC output or log snippets
- OS and build method (guix, make, etc.)

File issues on the project repository. For security-sensitive findings, please
use responsible disclosure and do **not** post exploit details publicly until
patched.

---

## See also

- [qubitcoin-recovery.md](qubitcoin-recovery.md) — wallet backup, key derivation, recovery
- [dilithium-crypto-audit.md](dilithium-crypto-audit.md) — internal Dilithium crypto & consensus audit
- [contrib/explorer/README.md](../contrib/explorer/README.md) — Docker block explorer (btc-rpc-explorer)

## For maintainers: updating seeds

```bash
# 1. Edit seed node lists
vim contrib/seeds/nodes_testnet4.txt   # port 42096
vim contrib/seeds/nodes_test.txt       # port 12096

# 2. Regenerate embedded seed data
python3 contrib/seeds/generate-seeds.py contrib/seeds

# 3. Uncomment DNS seeds in src/kernel/chainparams.cpp when ready

# 4. Rebuild
make -j$(nproc)
```

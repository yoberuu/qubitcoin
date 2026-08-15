# QubitCoin wallet backup & recovery

This document is the user-facing reference for how QubitCoin wallet keys are
derived, what a backup actually contains, and what recovery does and does not
depend on. The cryptographic reasoning behind these rules is in
[dilithium-crypto-audit.md](dilithium-crypto-audit.md) §1.

> **QubitCoin mainnet is experimental and has not had a professional third-party
> audit.** Read the warning at the top of the [README](../README.md) before
> putting value on this chain.

---

## The short version

1. **Back up the wallet file.** `backupwallet` while the node runs, or copy
   `wallets/<name>/` with the node stopped. Do it again after you encrypt the
   wallet, and after you hand out new addresses.
2. **There is no seed phrase.** No BIP39 words, no `xprv`, no `dumpprivkey`, no
   key import. `dumpwallet` runs without error but writes a file that contains
   **no keys**. It is not a backup. The wallet file is the only backup.
3. **Record the liboqs version** you built or downloaded your binaries against.
   Keep that note with the backup.

Everything below explains why.

---

## What a wallet contains

A QubitCoin wallet is a legacy (non-descriptor) wallet holding post-quantum key
records. In the wallet database:

| Record | Contents |
| --- | --- |
| `dhdseed` / `dchdseed` | the 32-byte Dilithium HD master seed, plaintext or encrypted, plus the next child index |
| `dkey` / `dckey` | one record per key: the full 4,032-byte ML-DSA-65 secret key, plaintext or encrypted, indexed by its 1,952-byte public key |

Two things follow from that layout:

- **Every secret key is stored in full, not re-derived on load.** So an existing
  wallet file does not depend on the derivation below still being reproducible.
- **The master seed plus an index is enough to regenerate a key** — but only if
  the derivation is reproducible, which is what the pinned known-answer test and
  the startup self-test exist to guarantee.

Dilithium addresses are created on demand rather than from a keypool: there is no
pre-generated look-ahead, so the stored index counter is exactly the number of
keys that have ever been handed out.

The ECDSA key manager is still present and still empty. `getwalletinfo` reporting
`"keypoolsize": 0` and wallet logs reporting `Legacy Wallet Keys: 0` are expected:
Dilithium keys are counted separately, on the `Dilithium Wallet Keys:` log line.

---

## Backing up

```bash
# Hot backup, with the node running (safe, uses a consistent DB snapshot)
qbitcoin-cli -rpcwallet=mywallet backupwallet /secure/media/mywallet-2026-08-15.bak

# Cold backup: stop the node first, then copy the whole wallet directory
qbitcoin-cli stop
cp -a ~/.qubitcoin/wallets/mywallet /secure/media/mywallet-dir-2026-08-15
```

Back up again when:

- **You encrypt the wallet.** `encryptwallet` re-encrypts the HD seed and every
  Dilithium key in place; the RPC itself tells you to make a new backup. An older
  backup still works, but it is unencrypted — treat it as a plaintext key file.
- **You change the passphrase** — same reasoning.
- **You have handed out new addresses.** Keys are derived on demand, so a backup
  taken before an address existed does not contain it. It can be recovered — the
  derivation is deterministic — but only by walking the index forward by hand and
  rescanning; see [below](#if-the-backup-predates-some-of-your-addresses).

Store backups the way you would store a private key file, because that is what
they are. An unencrypted `wallet.dat` gives anyone who reads it complete control
over the coins.

---

## Restoring

```bash
# Preferred: restore a backup file into a named wallet
qbitcoin-cli restorewallet mywallet /secure/media/mywallet-2026-08-15.bak

# Or, manually: stop the node, drop the file into an otherwise empty wallet
# directory (leftover -journal files from another wallet will confuse the DB),
# then restart
qbitcoin-cli stop
mkdir -p ~/.qubitcoin/wallets/mywallet
cp /secure/media/mywallet-2026-08-15.bak ~/.qubitcoin/wallets/mywallet/wallet.dat
qbitcoind -daemon
qbitcoin-cli loadwallet mywallet
```

Then confirm the restore actually sees your coins:

```bash
qbitcoin-cli -rpcwallet=mywallet getwalletinfo
qbitcoin-cli -rpcwallet=mywallet getbalance
qbitcoin-cli -rpcwallet=mywallet getaddressinfo "QYOUR_ADDRESS"   # expect "ismine": true
```

### If the backup predates some of your addresses

Dilithium addresses are **not** keypool-backed: each `getnewaddress` derives the
next index on demand and writes that key immediately. There is no look-ahead pool
and no automatic gap-limit scan, so a backup taken at index `N` contains keys
`0…N-1` and knows nothing about addresses you handed out afterwards.

Because derivation is deterministic, you can walk it forward again. Call
`getnewaddress` on the restored wallet until it reproduces the addresses you
remember — it will regenerate exactly the same ones, in the same order — then
rescan:

```bash
qbitcoin-cli -rpcwallet=mywallet getnewaddress   # repeat past your last used index
qbitcoin-cli -rpcwallet=mywallet rescanblockchain
qbitcoin-cli -rpcwallet=mywallet getbalance
```

This is verified behaviour, not a theory: restoring a stale backup and calling
`getnewaddress` once reproduces the next address byte for byte, and the rescan
then credits the coins that were paid to it. Rescanning a full chain is slow, so
prefer keeping the backup current over relying on this.

---

## How Dilithium keys are derived (normative)

QubitCoin does not use BIP32; BIP32 is secp256k1-specific. Each wallet key comes
from one 32-byte master seed and a monotonically increasing child index:

```
child_seed(i) = HMAC-SHA256(key = master_seed, msg = "QBTC-ML-DSA-65-HD" || LE32(i))

xi            = SHA256(child_seed || LE64(0))
(pk, sk)      = ML-DSA-65.KeyGen_internal(xi)          [FIPS 204 §5.1]

keyid         = Hash160(pk)                            [RIPEMD160(SHA256(pk))]
address       = Base58Check(version_byte || keyid)
scriptPubKey  = OP_DUP OP_HASH160 <keyid> OP_EQUALVERIFY OP_CHECKSIG
```

where `"QBTC-ML-DSA-65-HD"` is the 17-byte ASCII label without a trailing NUL,
`LE32`/`LE64` are little-endian, `pk` is the raw 1,952-byte ML-DSA-65 public key,
and the address version byte is:

| Network | Dilithium version byte | Address prefix |
| --- | --- | --- |
| mainnet | 58 | `Q…` |
| testnet3 / signet / regtest | 120 | `q…` |
| testnet4 | 121 | `r…` |

Reference implementations: `DeriveDilithiumChildSeed()` in `src/dilithiumkey.cpp`,
`dilithium::GenerateKeyPairFromSeed()` in `src/crypto/dilithium.cpp`, and
`CDilithiumPubKey::GetID()` in `src/dilithiumpubkey.h`.

### The one step that is not standardized

`ML-DSA-65.KeyGen_internal(xi)` is FIPS 204. The step above it — turning a child
seed into `xi` — is **not** a standard. liboqs 0.14.1 exposes no derandomized
keygen entry point, so QubitCoin installs a process-local RNG that emits
`SHA256(seed || LE64(counter))` blocks and calls `OQS_SIG_keypair`. ML-DSA-65
keygen happens to draw exactly 32 bytes, which makes `xi = SHA256(seed || LE64(0))`.

That is an observed property of a specific liboqs version, not a guarantee. If a
future liboqs draws a different number of bytes, or draws them in a different
order, the same seed would produce a different key — and a seed-only recovery
would silently produce the wrong addresses.

### How the code stops that from happening silently

- `SEEDED_KEYGEN_KAT_PUBKEY_SHA256` in `src/crypto/dilithium.cpp` pins the
  expected result for an all-zero seed:
  `SHA256(pk) = 22320b719b796da8822243444a954cb54fe8924e4ba64cdf43a861cb8c25a764`.
  An independent implementation can check itself against that value.
- `GenerateKeyPairFromSeed()` evaluates the vector once per process and **refuses
  to derive any key** if it fails. Failing loudly beats deriving a wrong key.
- `dilithium::SelfTest()` runs from `AppInitSanityChecks()` in `src/init.cpp`, so
  a mismatched liboqs **stops the node at startup** with
  `Post-quantum (ML-DSA-65) cryptography sanity check failure`, instead of coming
  up and quietly behaving like a different wallet.

You can check the pinned vector directly:

```bash
make -C src test/test_bitcoin
./src/test/test_bitcoin --run_test=dilithium_crypto_audit_tests/kat_seed_to_pubkey_is_pinned
```

### Practical consequence: record your liboqs version

```bash
pkg-config --modversion liboqs      # plus the commit, if you built it yourself
```

Keep that with your backups. If a node ever refuses to start with the
post-quantum sanity check error:

- **Do not delete or "repair" the wallet.** Your stored secret keys are unaffected
  — they are held in full in the wallet file, not re-derived.
- Go back to the liboqs version the binaries were built against, and report the
  mismatch.
- The derivation is only re-pinned deliberately, as a documented change, never as
  a silent side effect of a dependency upgrade.

---

## What does not work on this chain

These are not bugs to work around; they are missing capabilities. Nothing in this
list has a workaround today.

| You might expect | Reality |
| --- | --- |
| A BIP39 seed phrase to write down | Does not exist. There is no mnemonic, and no way to display or import the master seed. |
| `dumpwallet` as a backup | Runs successfully and writes a file with **zero keys** in it. Useless as a backup. Do not rely on it. |
| `dumpprivkey` | Fails on Dilithium addresses (`Private key for address … is not known`). Individual keys cannot be exported. |
| `importprivkey` / `importwallet` | No import path exists for Dilithium keys; the import RPCs only understand secp256k1 WIF. |
| `signmessage` / `verifymessage` | ECDSA-only; fails with `Address does not refer to key`. Off-chain proof of address control is not supported. |
| Descriptor wallets, `importdescriptors` | Descriptors are secp256k1-shaped. A descriptor wallet cannot hold a spendable key here. |
| Hardware wallets, external signers | No device supports this derivation or signature scheme. |
| Paying a legacy `1…`, `3…`, `bc1…` or `qc1…` address | Refused by the wallet: those outputs are unspendable on a Dilithium-only chain, so paying one burns the coins. `validateaddress` reports `"ispostquantum": false` with a warning. |

Encryption works normally, with one QubitCoin-specific note: decrypted Dilithium
secret material has to prove it matches the public key stored beside it. The
wallet signs a fresh random challenge with the secret and verifies that signature
against the claimed public key, so a corrupted or mismatched pair fails loudly
instead of loading silently.

---

## Checklist

- [ ] Wallet file backed up, off the machine that runs the node
- [ ] Backup refreshed after encrypting or changing the passphrase
- [ ] Backup treated as key material (encrypted at rest, or physically secured)
- [ ] liboqs version (and commit) recorded alongside the backup
- [ ] Restore actually tested once — `restorewallet` into a scratch datadir,
      then check `getbalance` and `getaddressinfo` → `"ismine": true`
- [ ] You have read the experimental-mainnet warning in the
      [README](../README.md) and are not storing value you cannot lose

---

## See also

- [dilithium-crypto-audit.md](dilithium-crypto-audit.md) — internal cryptographic
  and consensus review, including the derivation analysis (§1) and everything
  still open
- [testnet.md](testnet.md) — node operator guide and command reference
- [managing-wallets.md](managing-wallets.md) — upstream Bitcoin Core wallet
  management notes (descriptor-wallet sections do not apply here)

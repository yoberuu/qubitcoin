# QubitCoin — Dilithium (ML-DSA-65) cryptographic & consensus audit

Scope: cryptomath and consensus safety of the ML-DSA-65 / FIPS 204 integration.
Method: source review from first principles, plus direct measurement against the
linked liboqs (0.14.1-dev) and new consensus-level tests. Existing suites were
treated as unproven until re-derived.

**This is an internal review, not a professional third-party audit.** It was
carried out by the project rather than by an independent security firm, and it is
published in full — including the findings that are still open — precisely so that
readers can judge the residual risk themselves. QubitCoin mainnet is experimental;
see the [README warning](../README.md#read-this-before-using-mainnet). Users who
only need the practical consequences for backups and recovery should read
[qubitcoin-recovery.md](qubitcoin-recovery.md).

Reproduce:

```
./src/test/test_bitcoin --run_test=dilithium_crypto_audit_tests --log_level=message
./src/test/test_bitcoin --run_test=dilithium_ecdsa_audit_suite
./src/test/test_bitcoin --run_test=dilithium_mining_tests
./src/test/test_bitcoin --run_test=dilithiumkey_tests
./src/test/test_bitcoin --run_test=dilithium_tests
./src/test/test_bitcoin --run_test=sigopcount_tests
./src/test/test_bitcoin --run_test=transaction_tests/test_IsStandard
./src/test/test_bitcoin --run_test=dilithium_size_tests --log_level=message
./src/test/test_bitcoin --run_test=dilithium_address_tests
./src/test/test_bitcoin --run_test=dilithium_wallet_tests
./test/functional/wallet_dilithium_address_safety.py --legacy-wallet
```

## Measured facts (liboqs 0.14.1-dev, this build)

| Quantity | Measured |
| --- | --- |
| Public key | 1952 B |
| Secret key | 4032 B |
| Signature | 3309 B, fixed |
| Randomness drawn by `keypair` | exactly 32 bytes |
| Randomness drawn by `sign` | 32 bytes (hedged) |
| Verify latency | 43.4 µs |
| Sign latency | 106.3 µs |
| Truncated / padded / bit-flipped sigs accepted | 0 of 162 trials |

## Verdicts

Findings marked **FIXED** were remediated during the audit; the rest are
recommendations. See "Recommended fixes, ranked" for current status.

| # | Item | Verdict |
| --- | --- | --- |
| 1.1 | Deterministic keygen follows FIPS 204 ξ → key pair | NEEDS ATTENTION → **FIXED** (guarded) |
| 1.2 | Global RNG swap is safely scoped | PASS (note) |
| 1.3 | `secure_allocator` for secrets; no plaintext left after encryption | PASS |
| 1.4 | Secret ↔ public key binding on wallet load | **was FAIL** → **FIXED** |
| 2.1 | Public key exactly 1952 B; signature within ML-DSA-65 bounds | PASS → caveat **FIXED** |
| 2.2 | Sighash domain separation | PASS → caveat **FIXED** (tagged) |
| 2.3 | Hashtype committed and restricted to defined values | PASS (sig) / **FIXED** (undefined bytes) / **FAIL** (txid) |
| 2.4 | Cross-scheme (ECDSA leftover) confusion impossible | PASS |
| 3.1 | `OP_CHECKSIG(VERIFY)` accept only 1952 B keys | PASS |
| 3.2 | `CheckECDSASignature` / `CheckSchnorrSignature` unconditionally false | PASS |
| 3.3 | Sigcache `'D'` domain separation collision-free | PASS |
| 4.1 | Worst-case block weight recomputed | PASS |
| 4.2 | `DILITHIUM_VERIFY_SIGOP_COST = 5` appropriate | PASS on value / NEEDS ATTENTION on effect |
| 4.3 | Dilithium input policy cap enforced and unbypassable | **was FAIL** → fixed at relay; consensus gap open |
| 4.4 | Dust and fee estimation match real spend cost, both forms | **was FAIL** → **FIXED** |
| 5.1 | No undomain-separated 32-byte digest signing | PASS → caveat **FIXED** |
| 5.2 | No non-constant-time comparison on secrets | PASS |
| 5.3 | No residual ECDSA assumptions on Dilithium paths | PASS |
| 5.4 | Serialization edge cases | PASS (note) |
| 5.5 | Script interpreter regression coverage | NEEDS ATTENTION |
| 5.6 | Every wallet-issued Dilithium address decodes | **was FAIL** (mainnet, ~3.3%) → **FIXED** |

---

## 1. Key generation & determinism

### 1.1 Seed → key pair is deterministic, but the mapping is not standardized — NEEDS ATTENTION

`dilithium::GenerateKeyPairFromSeed` (`src/crypto/dilithium.cpp:118`) does **not**
feed the seed to a FIPS 204 derandomized keygen. liboqs 0.14.1 exposes no such
entry point (verified: `sig.h` declares only `OQS_SIG_keypair`). Instead it
installs a process-global custom RNG emitting `SHA256(seed ‖ LE64(counter))`
blocks and calls `OQS_SIG_keypair`.

Measurement: ML-DSA-65 keygen draws **exactly 32 bytes** from `randombytes`.
So in effect

```
ξ = SHA256(seed ‖ 0x0000000000000000)
(pk, sk) = ML-DSA.KeyGen_internal(ξ)          [FIPS 204 §5.1]
```

The keygen itself is FIPS 204 compliant — liboqs expands
`(ρ, ρ′, K) = H(ξ ‖ k ‖ ℓ, 128)`, `A = ExpandA(ρ)`, `(s₁,s₂) = ExpandS(ρ′)`,
`t = A·s₁ + s₂`, `(t₁,t₀) = Power2Round(t, 13)`. What is *not* standardized is
the seed → ξ step, which is an artefact of how many bytes liboqs happens to draw
and in what order.

Why this matters: if a liboqs upgrade changes that consumption pattern — draws
64 bytes, adds a rejection loop, reorders calls — every HD-derived key silently
changes and every wallet becomes unrecoverable. Nothing in the build detected
this before.

**S1 — FIXED.** Three layers now guard this:

1. The derivation is documented normatively in `crypto/dilithium.h`, so an
   independent implementation can reproduce it. The previous comment claimed
   recovery was "stable for any FIPS 204-compliant ML-DSA-65 implementation",
   which was false; that claim is removed.
2. `SEEDED_KEYGEN_KAT_PUBKEY_SHA256` in `crypto/dilithium.cpp` pins
   SHA256(pubkey) for an all-zero seed. `GenerateKeyPairFromSeed` evaluates it
   once per process and **refuses to derive anything if it fails** — deriving the
   wrong key silently is far worse than failing loudly.
3. `dilithium::SelfTest()` is called from `AppInitSanityChecks`
   (`init.cpp`), so a mismatched liboqs aborts startup with a clear error instead
   of quietly producing a different wallet. Also asserted in `sanity_tests` and
   `dilithium_crypto_audit_tests`.

The derivation is now also written up for users, with the KAT digest, the backup
and restore procedure, and what to do if the self-test ever fails, in
[qubitcoin-recovery.md](qubitcoin-recovery.md).

Residual: the liboqs version should still be pinned in the build itself — the
release notes and recovery document ask operators to record it, which is a
process control rather than a technical one. Moving to a derandomized keygen
(choosing ξ ourselves) remains the cleaner long-term shape if liboqs ever exposes
one.

### 1.2 Global RNG swap — PASS (note)

`g_rng_mutex` serializes all three randomness-consuming entry points
(`GenerateKeyPair`, `GenerateKeyPairFromSeed`, `Sign`). `Verify` correctly takes
no lock — measured, verification draws zero randomness. The deterministic RNG is
installed and torn down inside the lock and the seed state is zeroed afterwards.

Two notes:

- `OQS_randombytes_custom_algorithm` mutates *process-global* state. This is safe
  only because QubitCoin is the sole liboqs consumer in the process. It is worth
  an explicit invariant comment, because a future library that also links liboqs
  would silently receive deterministic bytes during the keygen window.
- The mutex serializes all Dilithium signing process-wide. A throughput ceiling,
  not a security issue.

**Signing randomness is not an ECDSA-style nonce.** `OQS_SIG_sign` draws 32 bytes
for the hedging value `rnd` in `ρ″ = H(K ‖ rnd ‖ μ)`. Unlike an ECDSA nonce,
reusing or fixing `rnd` does not leak the secret key — deterministic ML-DSA
(`rnd = 0³²`) is an approved FIPS 204 mode. Even a bug that pinned the signing
randomness would not be key-extracting. This is a real structural safety gain
over secp256k1.

### 1.3 Secret storage — PASS

`dilithium::SecretKey` is a `secure_allocator` vector backing
`CDilithiumKey::keydata`; `CKeyingMaterial` (also secure) carries the plaintext
in `EncryptSecret` / `DecryptDilithiumKey`. The deterministic-RNG seed is wiped
after use. Grep-verified: no `memcmp` or `==` on secret bytes anywhere;
`IsValid()` compares sizes only.

Minor: `g_det_rng` is a plain `std::array`, not secure storage. It holds seed
material transiently and is explicitly zeroed, but is not non-swappable. LOW.

### 1.4 The wallet's post-decryption integrity check was a tautology — FIXED (was medium)

`wallet/crypter.cpp:DecryptDilithiumKey` used to end with:

```cpp
if (!key.Set(vchSecret, vchPubKey)) return false;
return key.GetPubKey() == vchPubKey;
```

`CDilithiumKey::Set()` stores the supplied public key verbatim, and `GetPubKey()`
returns that cached copy. The comparison can never fail. The ECDSA path does the
real thing — `DecryptKey` calls `CKey::VerifyPubKey()`, which re-derives.

Consequence: a corrupted or mismatched `dckey` record that pairs secret A with
public key B loaded without complaint and produced signatures nothing can verify.
A wrong passphrase was still caught (AES-CBC padding, then the length check), so
this was a data-integrity defect rather than an authentication bypass.

**Fix applied.** `CDilithiumKey::VerifyPubKey()` (`dilithiumkey.cpp`) signs a
fresh random challenge with the secret and requires the *argument* public key to
verify it, which is the same construction `CKey::VerifyPubKey()` uses and for the
same reason: the cached copy takes no part, so a mismatched pair fails. It is a
round trip rather than a re-derivation because a FIPS 204 secret key does not
carry `t1` and liboqs exposes no key-recovery routine, so the public key genuinely
cannot be recomputed from the secret — the property the old comment on
`GetPubKey()` glossed over, and the reason the check has to be behavioural. Cost
is one signature plus one verification, ~150 µs, per key decryption.

`DecryptDilithiumKey` now calls it. The plaintext `dkey` path
(`walletdb.cpp:LoadDilithiumKey`) got the same treatment for records written
without the `Hash(pubkey || secret)` checksum, mirroring how `LoadKey` treats
`fSkipCheck` for ECDSA; a validated checksum already ties the pair, so ordinary
wallets load at unchanged speed.

Regression cover: `dilithiumkey_verify_pubkey` (the primitive, both directions,
including a key whose cached public key was swapped), `dilithium_key_binds_secret_to_pubkey`
(the audit witness, rewritten to assert the fix), and
`decrypt_dilithium_key_rejects_mismatched_pubkey` (the wallet path: a `dckey`
record holding one key's secret under another's public key, which decrypts
cleanly and must still be refused). All three fail if the tautology is restored.

---

## 2. Signature scheme correctness

### 2.1 Sizes — PASS (caveat)

Constants match the runtime library, and `GenerateKeyPair*` re-check
`sig->length_public_key` / `length_secret_key` on every call, failing closed on
mismatch. Signatures are fixed at 3309 B. Measured: truncation by 1, 2, 100 and
all bytes, padding by 1 and 8 bytes, and 96 single-bit mutations were all
rejected.

The caveat found by this audit was that canonicality was enforced only *inside
liboqs* (`siglen != CRYPTO_BYTES → reject`); `dilithium::Verify` itself accepted
anything with `!empty() && size() <= length_signature`. Consensus should not rest
on a third party's internal invariant.

**S2 — FIXED.** `dilithium::Verify` now requires
`signature.size() == SIGNATURE_MAX_SIZE` (and cross-checks it against the runtime
library's advertised length) before calling liboqs, making length
non-malleability a QubitCoin consensus rule. `dilithium::Sign` symmetrically
refuses to emit a signature of any other length rather than returning a blob that
verification would reject. `SelfTest()` asserts the runtime library agrees with
all three compile-time size constants. Behaviour-preserving on liboqs 0.14.1;
regression-tested by `verify_enforces_exact_signature_length`.

### 2.2 Sighash domain separation — FIXED (was PASS with caveat)

`CheckDilithiumSignature` (`interpreter.cpp`) forces `SigVersion::WITNESS_V0`
regardless of script context, and
`MutableTransactionSignatureCreator::CreateDilithiumSig` (`sign.cpp`) does the
same. Signer and verifier agree; verified end to end. This keeps sighash O(1) per
input via the BIP143 midstates, which `PrecomputedTransactionData::Init`
unconditionally precomputes — necessary because Dilithium P2PKH spends carry no
witness and would otherwise not trigger it.

The amount commitment is correctly wired: `CScriptCheck::operator()` passes the
real `m_tx_out.nValue` (`validation.cpp:2095`), and `CheckDilithiumSignature`
fails closed through `HandleMissingData` when `amount < 0`.

The caveat was that the signed digest was byte-identical to Bitcoin's BIP143, with
no QubitCoin- or ML-DSA-specific tag. That was safe *because* the sighash was the
only thing ever signed with a Dilithium key (`signmessage` is ECDSA-only,
verified), which is a property of today's code rather than of the protocol.

**Fix applied.** What a Dilithium key signs is now, normatively:

```
msg = SHA256(SHA256(tag) || SHA256(tag) || sighash)
      where tag     = "QBTC-ML-DSA-65-SIGHASH"
            sighash = BIP143 sighash (SigVersion::WITNESS_V0)
```

i.e. a BIP340-style tagged hash of the BIP143 sighash. The tag names the chain and
the scheme, and follows the wallet's HD label (`"QBTC-ML-DSA-65-HD"`) so QubitCoin's
domain labels read alike; a second post-quantum scheme would get its own tag rather
than inherit this one. It is deliberately unversioned: any change to what is signed
is a hard fork, and would be expressed as a new tag.

Three notes on why this shape:

- **It is a wrapper, not a new sighash algorithm.** The inner digest is untouched,
  so every property established elsewhere in this section — O(1) per input,
  hashtype injectivity, the amount commitment — carries over unchanged, and the
  tagged hash is injective on the inner digest for the same reason BIP340's is.
  `sighash_commits_hashtype_and_amount` now asserts those properties on the tagged
  message rather than the inner sighash, which also demonstrates the wrapper does
  not collapse distinctions the sighash draws.
- **One definition, used by both sides.** `DilithiumSignatureMessage()`
  (`interpreter.h` / `interpreter.cpp`) is the single place the message is
  computed; the signer and the verifier each call it rather than each assembling
  the digest. The previous arrangement kept them in agreement through duplicated
  comments in two files, which is the shape a consensus split starts as. Removing
  the tag from that one function makes `dilithium_sighash_is_domain_separated`
  fail; making only one side tag makes `SignSignature` fail in three suites.
- **liboqs offers no alternative.** FIPS 204 defines a context string for exactly
  this purpose, but liboqs 0.14 exposes no `ctx` parameter (it signs in pure mode
  with an empty context), so passing one is not available without depending on
  library internals — the same dependency S1 and S2 were about removing.

Regression cover: `dilithium_sighash_is_domain_separated` pins the tag string and
the construction (recomputed from the literal tag rather than by calling the same
helper), and checks end to end that a signature over the untagged sighash, or over
the same sighash under any other tag, does not verify.

Consequence worth stating plainly: this changed what every Dilithium signature
commits to, so any coin signed before it is unspendable by a node after it. That is
why S4 was scoped pre-launch.

### 2.3 Hashtype is committed; txid is still malleable — PASS (sig) / FAIL (txid)

Injectivity: BIP143 serializes `nHashType` as a 4-byte little-endian int, and the
byte comes from `vchSig.back()` ∈ [0,255]. Distinct hashtypes give distinct
preimages. Verified exhaustively — all 256 values produce 256 distinct sighashes,
and flipping the trailing byte invalidates the spend end to end. FIPS 204 claims
EUF-CMA for ML-DSA (liboqs reports `euf_cma = 1` for this algorithm), and no
mutated signature verified in 162 trials. Strong unforgeability is not something
this audit can assert from measurement alone, but no signature-reshaping
transformation is known, so a third party cannot practically touch the signature
blob.

**But the scriptSig around it is malleable.** Dilithium spends are non-witness and
BIP143 does not commit to the scriptSig. Push encoding is constrained only by
`SCRIPT_VERIFY_MINIMALDATA`, which is a standardness flag, not a mandatory one.
Proven by `non_minimal_push_encoding_is_third_party_malleable`: re-encoding both
pushes with `OP_PUSHDATA4` keeps the spend valid under
`MANDATORY_SCRIPT_VERIFY_FLAGS` and changes the txid.

This is legacy Bitcoin's problem, but here it affects **every spend on the chain**,
because the only spend type in use is non-witness. Anything building on unconfirmed
txids (chained transactions, payment channels, L2) inherits it. See S7 — adopting
segwit-shaped Dilithium spends would eliminate it.

**Undefined hashtype bytes — FIXED (was S6, LOW).** All 256 values used to be
accepted, because `STRICTENC`'s `IsDefinedHashtypeSignature` is not applied on this
path (3.1). None of them was third-party malleable — the byte is committed, as above
— but `SignatureHash` only reads the low five bits and the ANYONECANPAY bit, so 0x21
meant precisely what SIGHASH_ALL means, and a *signer* had 250 spare encodings of
each intent to choose from. Six values are now defined and nothing else verifies:

| Byte | Meaning |
| --- | --- |
| `0x01` | SIGHASH_ALL |
| `0x02` | SIGHASH_NONE |
| `0x03` | SIGHASH_SINGLE |
| `0x81` | SIGHASH_ALL \| SIGHASH_ANYONECANPAY |
| `0x82` | SIGHASH_NONE \| SIGHASH_ANYONECANPAY |
| `0x83` | SIGHASH_SINGLE \| SIGHASH_ANYONECANPAY |

`IsDefinedDilithiumHashtype()` (`interpreter.h` / `interpreter.cpp`) is the single
allow-list, written as an explicit switch rather than derived by masking so the
accepted set can be read off. `EvalChecksigPreTapscript` rejects anything else with
`SCRIPT_ERR_SIG_HASHTYPE`, and `CreateDilithiumSig` refuses to sign it, so the two
sides cannot drift. Three deliberate details:

- **Consensus, not policy.** The ECDSA equivalent hangs off `SCRIPT_VERIFY_STRICTENC`,
  a standardness flag; this is enforced under `MANDATORY_SCRIPT_VERIFY_FLAGS`, which
  the test asserts, because a rule that only relay enforces would leave the spare
  encodings valid in blocks. Hard-forking, hence pre-launch, like S4.
- **The empty signature is exempt.** It carries no hashtype byte to judge and remains
  the compact way to fail a `CHECKSIG`, handled by NULLFAIL; it fails with
  `SCRIPT_ERR_EVAL_FALSE`, not a hashtype error.
- **`SIGHASH_DEFAULT` (0x00) is translated, not refused.** It has no encoding of its
  own outside Taproot, so the signer maps it to SIGHASH_ALL and emits `0x01`, as
  upstream does for BASE/WITNESS_V0. Nothing emits or accepts a `0x00` byte.

Regression cover: `only_defined_hashtypes_are_accepted` signs all 256 byte values
*correctly for their own byte*, so the only thing under test is whether the byte is
allowed — six verify, 250 fail with `SCRIPT_ERR_SIG_HASHTYPE`.
`signing_path_only_produces_defined_hashtypes` checks the signer round-trips each of
the six and refuses undefined ones (and values that do not fit in a byte). Reverting
the allow-list to "accept everything" produces 757 failures across the two.

### 2.4 Cross-scheme confusion — PASS

The size gate at `interpreter.cpp:341` is total: any key whose length is not
exactly 1952 fails with `SCRIPT_ERR_PUBKEYTYPE`. Since 1952 ∉ {32, 33, 65}, no
secp256k1 or x-only key can reach the Dilithium verifier, and no Dilithium key can
reach an ECDSA verifier. Verified for lengths {0, 1, 32, 33, 65, 520, 1951, 1953,
4096}.

---

## 3. Verification path

### 3.1 Key-type gate — PASS

`OP_CHECKSIG` and `OP_CHECKSIGVERIFY` share one case block and both funnel through
`EvalChecksig` → `EvalChecksigPreTapscript`, where the single 1952-byte gate lives.

`CheckSignatureEncoding` and `CheckPubKeyEncoding` are deliberately not called on
this path, so `SCRIPT_VERIFY_LOW_S`, `DERSIG`, `STRICTENC` and
`WITNESS_PUBKEYTYPE` are inert for Dilithium. That is correct — DER and low-S are
meaningless for ML-DSA — and it is the direct answer to red flag 5.3. It is also
what opens 4.3, since `WITNESS_PUBKEYTYPE` was the check that would have rejected
a 1952-byte key inside segwit.

### 3.2 ECDSA and Schnorr are dead — PASS

`CheckECDSASignature` (`interpreter.cpp:1671`) has no branch at all: `return false`.
Verified against a *genuinely valid* secp256k1 signature — raw `CPubKey::Verify`
returns true while the consensus checker returns false. `CheckSchnorrSignature`
(`interpreter.cpp:1721`) always sets `SCRIPT_ERR_SCHNORR_SIG`.

Reachability is complete: `OP_CHECKMULTISIG(VERIFY)` funnels through
`CheckECDSASignature` (`interpreter.cpp:1175`), and both Taproot key-path and
tapscript route to `CheckSchnorrSignature`. Neither can ever succeed.

Consequence worth calling out: **any output paying to a Taproot or ECDSA address is
permanently unspendable.** Address decoding parses those addresses and `sendtoaddress`
used to accept them, so a paste of the wrong address type silently burned the funds.

**Fix applied (send-time only).** `IsDilithiumDestination` (`addresstype.cpp`) is now
the single definition of a payable destination, and every path where a user-supplied
address string becomes an output consults it: `ParseOutputs` (`rawtransaction_util.cpp`,
which every send RPC and `createrawtransaction` funnel through), the `change_address`
option, and Qt's `prepareTransaction` and custom-change field. `validateaddress` and
`getaddressinfo` report `ispostquantum` for every address type rather than only the
Dilithium one, and `validateaddress` attaches a warning, so a bare `isvalid: true` no
longer reads as "safe to pay".

Two properties of the fix are worth stating, because they are consequences of the
design in 4.4 rather than choices:

- **It has to be at the address layer.** A `DilithiumPKHash` and a legacy `PKHash`
  over the same key hash produce byte-identical P2PKH scripts, so once an address
  has become a scriptPubKey the key type is gone. A check on scripts would reject
  genuine Dilithium payments (`fundrawtransaction` recovers destinations with
  `ExtractDestination`, which returns `PKHash` for a Dilithium output) while still
  missing the ECDSA-shaped burn it was meant to catch. `dilithium_address_tests`
  pins this both ways.
- **Hand-built scripts stay out of reach.** Funding a raw transaction whose outputs
  were assembled as scripts rather than addresses is not covered, by the same
  argument. That is the expert path, not the accidental one.

The refusal is deliberately stricter than consensus: witness v0 keyhash is refused
even though a P2WPKH over an ML-DSA key hash is spendable (4.3), because nothing on
this chain issues such an address, so one that reaches a user today came from
Bitcoin-shaped tooling over a secp256k1 key. That is the single line to revisit if
S7 is resolved by adopting the witness form.

- **S5 (MEDIUM) — FIXED** at the send path. Residual: `addmultisigaddress` and
  `createmultisig` still mint P2SH addresses that can only be received to and never
  spent, and `bitcoin-tx` builds outputs without consulting the check.

### 3.3 Signature cache domain separation — PASS

The three salted hashers share a 32-byte random nonce but differ in a 32-byte
padding block (`'E'` / `'S'` / `'D'` followed by zeros), so the 64-byte first
SHA-256 block differs and the three midstates are independent. A cross-domain
collision requires a SHA-256 collision.

Within the Dilithium domain the preimage is `salt ‖ msg(32) ‖ pubkey(1952) ‖ sig`,
where `msg` is the tagged message of 2.2 — the cache keys on what was verified, not
on the inner sighash. Both `msg` and `pubkey` are fixed width — pubkey validity is checked before
`ComputeEntryDilithium` is reachable — so the concatenation is unambiguously
parseable and no two distinct `(hash, pubkey, sig)` triples share a preimage. This
is strictly better than the ECDSA entry, where the pubkey is 33-or-65 bytes and the
signature is variable-length DER.

Verified by `sigcache_domain_separation`. Note that with ECDSA and Schnorr dead,
only Dilithium entries can ever be inserted into the shared cuckoo cache.

---

## 4. Size, weight & DoS math

### 4.1 Worst-case block weight — recomputed

Two spend forms relay, and they differ by nearly the full segwit discount. Both
are exact rather than upper bounds: ML-DSA-65 signatures and public keys are
fixed length, so there is no low-r grinding and no key compression.

Bare P2PKH Dilithium input:

```
36 (outpoint) + 3 (scriptSig varint) + 5268 (3+3310 sig, 3+1952 key) + 4 (nSequence)
  = 5311 B  →  21,244 WU
```

Witness (segwit v0 keyhash) Dilithium input — same two elements, moved into the
witness where they are discounted 4:1:

```
non-witness 36 + 1 (empty scriptSig) + 4  = 41 B  → 164 WU
witness     1 (stack count) + 3+3310 + 3+1952 = 5269 B → 5269 WU
                                                 total 5433 WU  (1359 vB)
```

Measured 1-in-1-out transactions: 21,320 WU and 5,511 WU, consistent. The ratio
is **3.91x**, i.e. the witness form is the efficient one and by close to the full
4x. Both figures are pinned by `dilithium_size_tests`, which measures real signed
transactions rather than restating the constants.

```
⌊4,000,000 / 21,244⌋ = 188 bare Dilithium verifications per block   (8.2 ms)
⌊4,000,000 /  5,433⌋ = 736 witness verifications per block          (31.9 ms)
```

For scale, a full Bitcoin block performs roughly 10,000 ECDSA verifications
(~500 ms). **CPU DoS from Dilithium verification is a non-issue** — the signature
size is itself the rate limiter, and it limits far harder than CPU ever would.
Capacity and fee accounting, not CPU, are what these numbers have to get right.

The canonical constants live in `policy/policy.h`
(`DILITHIUM_P2PKH_INPUT_*`, `DILITHIUM_P2WPKH_INPUT_*`) and everything that needs
a spend size — dust, the relay bound, wallet fee estimation, the GUI's coin
control — derives from them rather than carrying its own copy.

### 4.2 `DILITHIUM_VERIFY_SIGOP_COST = 5` — PASS on value, NEEDS ATTENTION on effect

At 43.4 µs (≈1.3–1.4× ECDSA), a factor of 5 leaves ~3.5× margin for slower
hardware. The value is defensible.

**But the constant never binds.** Worst-case bare-P2PKH block:
`188 × 4 × 5 = 3,760` against `MAX_BLOCK_SIGOPS_COST` 80,000 — 4.7% of the budget.
A standard transaction at the input cap: `15 × 20 = 300` against
`MAX_STANDARD_TX_SIGOPS_COST` 16,000 — 1.9%. Even at the previous value of 50 it
was 37,600/80,000, still non-binding. The binding constraint is, and always was,
**block weight**. The sigop surcharge is currently decorative.

Note for the record: the 50 → 5 change is a **consensus relaxation** — blocks
previously invalid become valid. Acceptable only because the chain has not
launched. It must be frozen before genesis.

**Accounting hole.** `GetTransactionSigOpCost` (`tx_verify.cpp:171`) applies the
surcharge only to CHECKSIGs found in the *prevout scriptPubKey*. Measured cost for
one identical ML-DSA verification:

| Spend shape | Sigop cost charged |
| --- | --- |
| bare P2PKH | 20 |
| P2WPKH | 1 |
| P2SH | 4 |

The justifying comment at `tx_verify.cpp:166-170` — "on this bare-P2PKH-only
chain" — is false at consensus level, as 4.3 shows.

### 4.3 The 15-input cap was bypassable and mis-shaped — both fixed at relay

Two consensus-valid alternative spend shapes, both newly proven:

- **Dilithium P2WPKH.** Because `EvalChecksigPreTapscript` no longer calls
  `CheckPubKeyEncoding`, `SCRIPT_VERIFY_WITNESS_PUBKEYTYPE` never runs.
  `VerifyWitnessProgram` builds the implied P2PKH script and executes it at
  `SigVersion::WITNESS_V0`, which the Dilithium checker accepts. `VerifyScript`
  returns true under `STANDARD_SCRIPT_VERIFY_FLAGS`.
- **P2SH(`<pubkey> OP_CHECKSIG`).** The redeemScript is 1955 B, under
  `MAX_SCRIPT_ELEMENT_SIZE` 4096. `VerifyScript` returns true.

The old heuristic `ScriptSigLooksLikeDilithiumSpend` scanned the scriptSig for a
push of exactly 1952 bytes, so it missed both: a witness spend has an *empty*
scriptSig, and P2SH nests the key inside a 1955-byte push. Measured before the
fix: a 20-input witness-shaped transaction was **standard**, five over the cap.

**Fix 1, counting (policy only).** `InputLooksLikeDilithiumSpend`
(`policy/policy.cpp`) now scans scriptSig pushes *and* witness stack items,
recursing one level into any element larger than the key size to catch
redeemScript / witnessScript nesting. One level suffices — P2SH and P2WSH cannot
nest further. It is exposed as `CountDilithiumSpendInputs` so the counting can be
tested directly rather than only through a standardness verdict.

**Fix 2, the bound itself (policy only).** A hand-picked count of 15 was the wrong
shape once both spend forms are priced honestly: it was drawn from bare-P2PKH
intuition, and applying it to the witness form would have discarded most of that
form's 4× weight advantage. `MAX_STANDARD_DILITHIUM_INPUTS` is now derived —
`MAX_STANDARD_TX_WEIGHT / MIN_STANDARD_DILITHIUM_VERIFY_WEIGHT` = 73, where the
minimum verify weight is the cheapest standard shape that can demand a
verification (witness P2WPKH, 5,433 WU). Two properties follow:

- **Form-neutral.** Weight is what binds for both real shapes: 18 bare inputs or
  73 witness ones. Neither is rejected by the count.
- **Unbypassable.** Any shape paying at least the minimum verify weight is bounded
  by `MAX_STANDARD_TX_WEIGHT`; anything cheaper is bounded by the count. There is
  no gap between the two, and the count follows automatically if either the weight
  ceiling or the Dilithium sizes change.

Note this is a relay **relaxation** for consolidations (15 → 18 bare, 15 → 73
witness), justified by the CPU figures in 4.1: 73 verifications is ~3.2 ms.
`policy_dilithium_input_limit_covers_all_spend_shapes` walks each shape up to its
largest standard input count and asserts which rule stopped it;
`dilithium_size_tests` pins the derivation and shows the count actually firing for
a shape cheaper than a real witness spend.

**The consensus gap remains.** A miner can still fill a block with witness
Dilithium spends: 5,433 WU versus 21,244 WU for the bare form, 3.91× cheaper,
giving ~736 verifications per block ≈ 31.9 ms. Still not a CPU problem, and relay
now prices both forms correctly, but `GetTransactionSigOpCost` still charges the
Dilithium surcharge only for CHECKSIGs in the prevout scriptPubKey, so a witness
verification is charged 1 sigop where a bare one is charged 20.

- **S7 (DECISION REQUIRED)** — resolve deliberately, do not leave ambiguous. Either
  (a) **adopt** Dilithium P2WPKH as the standard spend type — it cuts fees ~4× and,
  being segwit, eliminates the txid malleability of 2.3 — and fix
  `GetTransactionSigOpCost` to charge witness Dilithium verifications; or
  (b) reject 1952-byte keys under `SigVersion::WITNESS_V0` at consensus, closing the
  path. Option (a) appears strictly better for this chain.

  Relay and the economic model now assume (a): dust, the input bound and wallet
  fee estimation all price the witness form at its real 5,433 WU. What is still
  missing for (a) is a wallet-facing witness Dilithium address type (the wallet
  hands out bare `DilithiumPKHash` only) and the sigop accounting fix. Neither is
  a relay concern; both are consensus/UX work.

### 4.4 Dust and fee estimation were priced for ECDSA — FIXED

Dust is the amount below which an output costs more to spend than it carries, so
it is a direct function of input size. `GetDustThreshold` had inherited Bitcoin's
hardcoded input estimates: 148 vB for a P2PKH output and 67 vB for a witness one.
Both are ECDSA figures and both are off by more than an order of magnitude here.
The witness case was the worse of the two — a Dilithium P2WPKH output was dust
only below 294 sat while actually costing ~4,170 sat to spend, i.e. an attacker
could create outputs at 1/14th of their spend cost and the UTXO set would absorb
the difference permanently.

Both now derive from the canonical constants, selected on the output's actual
`TxoutType`:

| Output | Input vsize | Dust at 3000 sat/kvB | Was |
| --- | --- | --- | --- |
| Bare Dilithium P2PKH | 5311 vB | 16,035 sat | 546 sat |
| Witness Dilithium P2WPKH | 1359 vB | 4,170 sat | 294 sat |

Other output types keep their upstream estimates: they are either unspendable on
this chain (Taproot, since only 1952-byte keys verify) or their spend size is not
knowable from the scriptPubKey alone (P2SH, P2WSH). `dilithium_size_tests`
asserts each threshold against the fee for a real signed spend of that output
rather than against a restated constant.

**Wallet and GUI estimation.** The same ECDSA leftovers appeared wherever the
wallet predicted a size. `CalculateMaximumSignedInputSize` now returns the true
per-form size, and the transaction-level path detects witness inputs from the
scriptPubKey directly instead of relying on descriptor inference, so a witness
input is never estimated as bare. The change-spend-cost fallback and Qt's coin
control both use the Dilithium constants. Under-estimating here would mean
under-paying fees and producing transactions that cannot relay, which is why
`dilithium_wallet_tests` checks the estimate against the weight of an actually
signed transaction rather than against another estimate.

---

## 5. Red flags

- **5.1 Undomain-separated 32-byte signing — FIXED.** liboqs prepends the FIPS 204
  pure-mode prefix `0x00 ‖ 0x00` (empty context), which is constant and not
  QubitCoin-specific, so the domain had to come from the message. It now does: the
  message is the BIP143 sighash under the tag `"QBTC-ML-DSA-65-SIGHASH"` (2.2, S4).
  Separately, `signmessage` being ECDSA-only means it is non-functional for
  Dilithium wallets — a functional gap worth tracking, and one that would now need
  its own domain tag rather than reusing the spend one.
- **5.2 Non-constant-time comparison on secrets — PASS.** None found. Public-key
  equality uses `std::vector::operator==` on public data, which is fine.
- **5.3 Residual ECDSA assumptions — PASS.** No nonce, low-S, DER or compressed-key
  logic touches a Dilithium path. ML-DSA's hedging value is not a nonce in the
  ECDSA sense (see 1.2).
- **5.4 Serialization edge cases — PASS (note).** Key and signature lengths are
  fixed and re-checked at runtime; walletdb records are length-checked on load. The
  one consensus-relevant encoding issue is non-minimal push encoding (2.3), which is
  a script-encoding rather than a serialization concern.
- **5.5 Script interpreter regression coverage — NEEDS ATTENTION.** Large parts of
  the upstream test corpus are permanently red on this fork:
  `script_tests` 1,662 assertions (908 `script_json_test`, 684 `script_build`, plus
  CHECKMULTISIG and combineSigs) and `script_p2sh_tests` 23 (`SignSignature` with
  ECDSA keys). These failures are *expected* — the corpus signs with secp256k1,
  which can no longer verify — but with them permanently red the interpreter has
  effectively lost its regression net: a genuine bug would be indistinguishable
  from expected deadness. **S8 (LOW)** — port the corpus to Dilithium or
  explicitly quarantine it so the remainder can go green.

- **5.6 Mainnet Dilithium addresses do not all decode — FIXED (was high).** Found while
  running the suites for S4: `dilithium_wallet_tests` is intermittently red, at a
  rate that depends only on the random key it generates. `DecodeDestination`
  (`key_io.cpp`) decides between base58 and bech32 up front with

  ```cpp
  bool is_bech32 = (ToLower(str.substr(0, params.Bech32HRP().size())) == params.Bech32HRP());
  if (!is_bech32 && DecodeBase58Check(str, data, 21)) { ... }
  ```

  On mainnet the Dilithium version byte is 58, so **every** mainnet Dilithium address
  begins with `Q`, and the bech32 HRP is `qc`. An address whose second character is
  `c` therefore matches the HRP case-insensitively, the base58 branch is skipped, the
  bech32 branch fails, and a perfectly good address decodes to `CNoDestination`.

  Measured on a mainnet daemon: **10 of 300** wallet-issued addresses
  (`getnewaddress "" dilithium`) fail to decode — 3.3%, and exactly the 10 that begin
  `Qc`, e.g. `QcwbU5XnsBGcW1TeLgi9NcjMo7dbeMkYYn`. For those, `validateaddress`
  reports `isvalid: false` and every send RPC refuses them as an invalid address, so
  roughly one in thirty addresses the wallet hands out cannot be paid — by this
  implementation or, since the check is in shared code, by any wallet built from it.
  Upstream does not have this because Bitcoin's base58 addresses start with `1` or
  `3` and its HRP is `bc`; the collision is a consequence of choosing 58 and `qc`
  together.

  The address is otherwise well-formed: its base58 checksum is valid and the same
  string decodes correctly if the branch is not skipped. Unaffected: testnet, signet
  and regtest, where the Dilithium version byte 120/121 puts addresses under `q` and
  the HRPs are `tq` / `sq` / `trq` / `qcrt`, so a collision needs 3–4 specific
  characters rather than 1.

  **Fix applied.** `DecodeDestination` now settles the encoding by decoding rather
  than by guessing from the prefix: Base58Check is attempted first, and only if it
  does not yield a known version prefix does the string go to the Bech32 branch. This
  is unambiguous because Base58Check carries its own 4-byte checksum, which a Bech32
  string cannot satisfy. Error reporting is unchanged — a string that is not Bech32
  for this network still gets the base58 diagnostics, and a malformed Bech32 address
  still gets Bech32 ones, which the regression test checks so the fix cannot be
  mistaken for making everything look like base58.

  Re-measured after the fix: **400 of 400** mainnet addresses decode, including the
  13 beginning `Qc`, all reporting `ispostquantum: true`.
  `dilithium_addresses_decode_even_when_they_look_like_bech32` searches for a
  colliding key hash against the live chain parameters rather than hardcoding one, so
  it keeps testing the real thing if the version byte or the HRP changes, and it skips
  cleanly on networks where no collision exists. Reverting the fix makes it fail on
  three assertions; `dilithium_wallet_tests`, previously red about one run in six, is
  now 0 failures in 30 runs.

  Separately, `miner_tests` (111) and `txvalidationcache_tests` (2) fail for reasons
  upstream of any signature code — `bad-txns-inputs-missingorspent` from
  `CheckTxInputs` and `time-too-new` from the block-header timestamp check
  respectively — i.e. fork-wide test-fixture drift from the modified chainparams,
  not a cryptographic issue. Worth fixing so the suite can gate changes.

---

## Recommended fixes, ranked

| ID | Severity | Status | Fix |
| --- | --- | --- | --- |
| S1 | HIGH | **DONE** | Seed → key mapping documented normatively; pinned by a KAT that `GenerateKeyPairFromSeed` gates on and that `AppInitSanityChecks` enforces at startup. Residual: pin the liboqs version in the build and publish the derivation in a recovery doc. |
| S2 | HIGH | **DONE** | `dilithium::Verify` requires exactly `SIGNATURE_MAX_SIZE`; `Sign` refuses to emit any other length; `SelfTest()` checks all size constants against the runtime library. |
| S3 | MEDIUM | **DONE** | `CDilithiumKey::VerifyPubKey()` proves the secret matches the claimed public key by sign+verify round trip (~150 µs), and `DecryptDilithiumKey` calls it. The plaintext `dkey` load path does too when no `Hash(pubkey \|\| secret)` checksum is present. |
| S4 | MEDIUM | **DONE** | Dilithium signs `TaggedHash("QBTC-ML-DSA-65-SIGHASH", bip143_sighash)`, computed by one shared `DilithiumSignatureMessage()` that both the signer and the verifier call. Hard-forking, hence pre-launch. |
| S5 | MEDIUM | **DONE** | Non-Dilithium destinations are refused wherever an address string becomes an output (send RPCs, `change_address`, Qt), and reported as unspendable by `validateaddress` / `getaddressinfo`. Residual: multisig address creation and `bitcoin-tx`. |
| S6 | LOW | **DONE** | Only `0x01`, `0x02`, `0x03`, `0x81`, `0x82`, `0x83` are signable or verifiable, via one shared `IsDefinedDilithiumHashtype()` allow-list; enforced as consensus, not policy. Hard-forking, hence pre-launch. |
| S7 | DECISION | relay hole closed | Adopt or close the witness Dilithium spend path at consensus; align `GetTransactionSigOpCost` either way. |
| S8 | LOW | open | Restore script interpreter regression coverage. |
| S9 | HIGH | **DONE** | ~3.3% of mainnet Dilithium addresses (those starting `Qc`) failed to decode, because the bech32 HRP `qc` shadowed the base58 branch in `DecodeDestination`. Discovered during S4; fixed by attempting Base58Check before falling back to bech32. See 5.6. |

---

## Risk summary — "peaceful mainnet" readiness

**The core cryptography is sound.** ML-DSA-65 is correctly wired: sizes are
right and re-validated at runtime, signatures are canonical and strongly
unforgeable, the sighash commits to hashtype and amount, signer and verifier agree
on the algorithm, ECDSA and Schnorr are genuinely unreachable, and the signature
cache is domain-separated with an unambiguously parseable preimage. Secrets live in
cleansing storage and nothing compares them in variable time. The scheme is also
structurally more forgiving than ECDSA: there is no nonce whose reuse extracts the
key.

**The DoS story is better than assumed, but for a different reason than documented.**
Worst-case Dilithium verification is 8.2 ms per block (31.9 ms via the witness
path). Signature size, not CPU, is the binding constraint —
`DILITHIUM_VERIFY_SIGOP_COST` never actually binds at either 5 or 50. Capacity, not
CPU exhaustion, is the real design pressure.

**The two launch blockers are closed.** S1 — the seed → key mapping was an unpinned
liboqs implementation detail, and getting it wrong loses funds permanently rather
than causing an outage; it is now documented normatively, pinned by a known-answer
vector that seeded derivation refuses to run without, and enforced at node startup.
S2 — consensus was inheriting signature canonicality from a third-party library
rather than asserting it, the classic shape of a future consensus split; the exact
length is now a QubitCoin rule on both the signing and verifying side. What remains
of S1 is process, not code: pin the liboqs version in the build and publish the
derivation in a user-facing recovery document.

**One thing needs a decision, not a patch.** S7 — witness-shaped Dilithium spends
are consensus-valid, 3.91× cheaper by weight, under-charged 20× on sigops, and were
until this audit invisible to the relay cap. The relay hole is closed, and relay
now prices both forms at their real cost (4.1, 4.3, 4.4) — which is to say relay
already behaves as though the witness form is adopted. What remains is a design
choice, and adopting it looks like the better one: it would cut fees ~4× and
eliminate the third-party txid malleability that currently affects every spend on
the chain (2.3). Its remaining cost is a wallet-facing witness address type and the
sigop fix; deciding against it instead means a consensus rule rejecting 1952-byte
keys under `SigVersion::WITNESS_V0`, and reverting the witness half of 4.4.

**One finding came from the test suite rather than from reading the code.** S9 — one
mainnet Dilithium address in thirty could not be decoded, so it could not be paid by
any wallet built from this code, because the bech32 HRP `qc` shadowed the base58
branch for addresses beginning `Qc`. It surfaced as an intermittent unit-test
failure while verifying S4, at a rate that looked like flakiness rather than a bug.
Worth noting for what it says about the remaining risk: the audit's reading of the
crypto found nothing of this severity, and the thing that did was a red test nobody
had chased. That is an argument for S8 — while large parts of the corpus are
permanently red, a genuine failure is indistinguishable from expected deadness.

With S1, S2, S3, S4, S5, S6 and S9 landed, the remaining gate is S7 — a design
decision rather than a patch. S8 matters indirectly: until the script corpus is
green, regressions in the interpreter are hard to detect, which raises the cost of
every subsequent change.

Note that S4 and S6 both changed what verifies, so the pre-launch window is now the
only cheap moment for anything else of that kind — S7's consensus half included.

# QubitBible — run a QubitCoin node

This is the operator guide for joining QubitCoin mainnet: build the node, add
peers, create a Dilithium wallet, optionally run under systemd, and (if you
want) solo-mine. Ubuntu is the primary path. macOS and Windows (WSL) are
summarized at the end of the build section.

If you already know Bitcoin Core, the binaries are `qbitcoind` and
`qbitcoin-cli`. The data directory is `~/.qubitcoin/` and the config file is
`qubitcoin.conf`.

> **QubitCoin mainnet is experimental. Do not store significant value on it.**
>
> There has been no professional third-party audit — only the internal review
> in [dilithium-crypto-audit.md](dilithium-crypto-audit.md). Bugs are still
> possible, including bugs that lose coins. Consensus or wallet changes may
> still be required. Read the full warning in the
> [README](../README.md#read-this-before-using-mainnet).

QubitCoin is a **pure Dilithium (ML-DSA-65) UTXO chain**. ECDSA and Schnorr
are consensus-invalid. Receive addresses are Dilithium P2PKH (`Q…` on
mainnet). There is no seed phrase: `backupwallet` (the wallet file) is the
only backup. See [qubitcoin-recovery.md](qubitcoin-recovery.md).

---

## Contents

1. [What you need](#what-you-need)
2. [Build (Ubuntu)](#build-ubuntu)
3. [macOS and Windows (WSL)](#macos-and-windows-wsl)
4. [Join mainnet](#join-mainnet)
5. [Wallet and backup](#wallet-and-backup)
6. [VPS and systemd](#vps-and-systemd)
7. [Solo mining](#solo-mining)
8. [Troubleshooting](#troubleshooting)
9. [Further reading](#further-reading)

---

## What you need

- A 64-bit x86_64 (or similar) machine. A small VPS is enough for a node.
- Several GB of RAM for compiling (1.5 GB minimum; 4 GB is comfortable).
- Disk for the chain (grows with the network; start with tens of GB free).
- Outbound TCP to the seeds on port **2096**. For incoming peers, also open
  **2096/tcp** on your firewall. RPC (**2095**) stays on localhost by default
  — do not expose it.

Mainnet facts used below (do not invent others; these match the README):

| | |
|---|---|
| P2P port | **2096** |
| RPC port | **2095** |
| Genesis hash | `000000002f4fcc60ef61353d1767c691562dd380f240c1fcf47bf0e1c655d011` |
| Magic bytes | `0x51 0x42 0x54 0x43` (`QBTC`) |
| Dilithium addresses | version byte 58, `Q…` |
| Datadir | `~/.qubitcoin/` |
| Public seeds | `137.184.152.223:2096`, `68.183.115.209:2096` |

Mainnet has **no DNS seeds and no compiled-in fixed seeds**. You must add the
public seeds with `-addnode` (or `addnode=` in the config). That is expected,
not a bug.

---

## Build (Ubuntu)

The current tree is built and tested against **liboqs 0.14.1-dev**. Pass
`--with-liboqs=yes` so a missing library is a configure error instead of a
binary that dies at startup. Full dependency notes:
[build-unix.md](build-unix.md).

### 1. Packages

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential libtool autotools-dev automake pkg-config bsdmainutils \
  python3 cmake ninja-build libssl-dev git \
  libevent-dev libboost-dev libsqlite3-dev
```

Dilithium keys live in the **legacy** wallet, which needs Berkeley DB. Ubuntu's
`libdb-dev` is newer than 4.8; that is fine for a new experimental chain:

```bash
sudo apt-get install -y libdb-dev libdb++-dev
```

Skip the GUI unless you want it (`qtbase5-dev qttools5-dev qttools5-dev-tools`).
The commands below pass `--without-gui`.

### 2. liboqs

```bash
git clone https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build --parallel
sudo cmake --install liboqs/build
sudo ldconfig
pkg-config --modversion liboqs
# Record this version (and `git -C liboqs rev-parse HEAD`) next to your wallet backup.
```

Default install prefix is `/usr/local`. If `pkg-config --modversion liboqs`
fails:

```bash
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:${PKG_CONFIG_PATH}
pkg-config --modversion liboqs
```

### 3. QubitCoin

```bash
git clone <repository-url>   # see https://qubitcoin.org
cd QubitCoin-L1
./autogen.sh
./configure --with-liboqs=yes --with-incompatible-bdb --without-gui
make -j$(nproc)
```

Binaries land in `src/`:

```bash
ls src/qbitcoind src/qbitcoin-cli
./src/qbitcoind --version
```

Optional: `sudo make install` puts them in `/usr/local/bin`.

If configure cannot see liboqs, retry with the `PKG_CONFIG_PATH` export above.
If the node later fails with `liboqs.so` not found, see
[Shared library: liboqs.so](#shared-library-liboqsso).

---

## macOS and Windows (WSL)

### macOS

Install Xcode CLT and Homebrew, then:

```bash
xcode-select --install
brew install automake libtool boost pkg-config libevent cmake ninja openssl@3
```

Build liboqs as in the Ubuntu section (cmake/ninja). On Apple Silicon, if
pkg-config cannot find it, point at Homebrew's prefix:

```bash
export PKG_CONFIG_PATH="$(brew --prefix)/lib/pkgconfig:${PKG_CONFIG_PATH}"
```

Then `./autogen.sh` and `./configure --with-liboqs=yes --without-gui` from the
QubitCoin tree. Details: [build-osx.md](build-osx.md).

Datadir on macOS: `~/Library/Application Support/QubitCoin/`.

### Windows

Build **inside WSL2 (Ubuntu)** and follow the Ubuntu section above. Keep the
source tree on the Linux filesystem (for example `~/QubitCoin-L1`), not under
`/mnt/c/`. Native MSVC and MinGW cross-builds exist for upstream Bitcoin Core
([build-windows.md](build-windows.md)) but WSL is the supported way to run a
node day-to-day.

Datadir on native Windows: `%LOCALAPPDATA%\QubitCoin\`. Under WSL it is still
`~/.qubitcoin/`.

---

## Join mainnet

### Config (recommended)

```bash
mkdir -p ~/.qubitcoin
cat >> ~/.qubitcoin/qubitcoin.conf << 'EOF'
# QubitCoin mainnet (default chain — no testnet/regtest flag)
server=1
listen=1
daemon=1

# Public seed nodes. Mainnet has no DNS / compiled-in seeds.
addnode=137.184.152.223:2096
addnode=68.183.115.209:2096

# RPC stays on localhost (port 2095). Do not bind this to 0.0.0.0.
# rpcallowip=127.0.0.1
EOF
```

A longer template lives at
[share/examples/qubitcoin.conf](../share/examples/qubitcoin.conf).

### Start and confirm the chain

From the source tree, or from anywhere if you ran `make install`:

```bash
qbitcoind
# or: ./src/qbitcoind

qbitcoin-cli getblockchaininfo
```

Check:

- `"chain": "main"`
- `"bestblockhash"` starts at genesis
  `000000002f4fcc60ef61353d1767c691562dd380f240c1fcf47bf0e1c655d011`
  until more blocks arrive

```bash
qbitcoin-cli getconnectioncount
qbitcoin-cli getpeerinfo
qbitcoin-cli getnetworkinfo
```

`getconnectioncount` should become greater than 0 within a minute. If it
stays at 0, jump to [No peers](#no-peers).

You can add the same seeds at runtime (idempotent if they are already in
conf):

```bash
qbitcoin-cli addnode "137.184.152.223:2096" "add"
qbitcoin-cli addnode "68.183.115.209:2096" "add"
```

Or start without a conf file:

```bash
qbitcoind -daemon \
  -addnode=137.184.152.223:2096 \
  -addnode=68.183.115.209:2096
```

`-connect=` pins you to *only* those peers (no further outbound discovery).
Prefer `-addnode=` unless you are debugging.

### Stop

```bash
qbitcoin-cli stop
```

Prefer that over `kill`. Sync can take a while; `getblockchaininfo` shows
`headers` vs `blocks` and `initialblockdownload`.

---

## Wallet and backup

Create a **legacy** wallet (the default). Descriptor wallets cannot hold
spendable Dilithium keys on this chain.

```bash
qbitcoin-cli createwallet mywallet
qbitcoin-cli -rpcwallet=mywallet getnewaddress
# Mainnet: a Q… Dilithium address. ispostquantum is true.
qbitcoin-cli -rpcwallet=mywallet getaddressinfo "$(qbitcoin-cli -rpcwallet=mywallet getnewaddress)"
```

`validateaddress` on a leftover Bitcoin-shaped string (`D…`, `qc1…`, etc.)
reports `"ispostquantum": false` and a burn warning. The wallet refuses to
pay those destinations. Only send to `Q…` Dilithium addresses issued by this
software (or another QubitCoin Dilithium wallet).

**Back up immediately**, and again after encryption and after handing out new
addresses:

```bash
qbitcoin-cli -rpcwallet=mywallet backupwallet ~/qbtc-wallet.bak
```

There is **no seed phrase**, no `dumpprivkey` for Dilithium, and `dumpwallet`
writes a file with **no keys**. Lose the wallet file and the coins are gone.
Keep the liboqs version you built against next to the backup.

Encrypt (the wallet unloads; load it again afterwards):

```bash
qbitcoin-cli -rpcwallet=mywallet encryptwallet "a strong passphrase"
qbitcoin-cli loadwallet mywallet
qbitcoin-cli -rpcwallet=mywallet backupwallet ~/qbtc-wallet-encrypted.bak
```

Unlock for sends (`walletpassphrase`, timeout in seconds), then `walletlock`.
Full restore procedure: [qubitcoin-recovery.md](qubitcoin-recovery.md).

---

## VPS and systemd

Use a dedicated OS user. Do not run the node as root. Open **2096/tcp** for
P2P; leave **2095** closed to the world.

### Firewall (UFW)

```bash
sudo ufw allow 2096/tcp comment 'QubitCoin P2P'
sudo ufw enable
sudo ufw status
```

### User, directories, binaries

```bash
sudo useradd --system --home /var/lib/qubitcoin --shell /usr/sbin/nologin qubitcoin
sudo mkdir -p /var/lib/qubitcoin /etc/qubitcoin
sudo chown -R qubitcoin:qubitcoin /var/lib/qubitcoin /etc/qubitcoin
sudo chmod 710 /var/lib/qubitcoin /etc/qubitcoin
```

Install the binaries if you have not already (`sudo make install` from the
build tree), or copy `src/qbitcoind` and `src/qbitcoin-cli` to
`/usr/local/bin` and run `sudo ldconfig`.

```bash
sudo tee /etc/qubitcoin/qubitcoin.conf >/dev/null << 'EOF'
server=1
listen=1
# no daemon= here: systemd Type=simple wants a foreground process

addnode=137.184.152.223:2096
addnode=68.183.115.209:2096
EOF
sudo chown qubitcoin:qubitcoin /etc/qubitcoin/qubitcoin.conf
sudo chmod 640 /etc/qubitcoin/qubitcoin.conf
```

### Unit file

```bash
sudo tee /etc/systemd/system/qbitcoind.service >/dev/null << 'EOF'
[Unit]
Description=QubitCoin daemon
Documentation=https://qubitcoin.org
After=network-online.target
Wants=network-online.target

[Service]
User=qubitcoin
Group=qubitcoin
Type=simple
ExecStart=/usr/local/bin/qbitcoind -conf=/etc/qubitcoin/qubitcoin.conf -datadir=/var/lib/qubitcoin -printtoconsole
Restart=on-failure
TimeoutStopSec=600
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now qbitcoind
sudo systemctl status qbitcoind
```

Talk to it with an explicit datadir (the cookie file lives there):

```bash
sudo -u qubitcoin qbitcoin-cli -datadir=/var/lib/qubitcoin getblockchaininfo
sudo -u qubitcoin qbitcoin-cli -datadir=/var/lib/qubitcoin getconnectioncount
```

Logs: `journalctl -u qbitcoind -f` and
`/var/lib/qubitcoin/debug.log`.

Create the wallet the same way, then back it up **off the VPS**:

```bash
sudo -u qubitcoin qbitcoin-cli -datadir=/var/lib/qubitcoin createwallet mywallet
sudo -u qubitcoin qbitcoin-cli -datadir=/var/lib/qubitcoin -rpcwallet=mywallet backupwallet /tmp/qbtc-wallet.bak
# copy /tmp/qbtc-wallet.bak somewhere you control, then shred the copy on the VPS
```

Sample init files also exist in `contrib/init/` (still named for upstream
`bitcoind`); the unit above is the QubitCoin-shaped version to copy.

---

## Solo mining

QubitCoin uses Bitcoin-style proof of work (10-minute target, retarget every
2016 blocks). Coinbase outputs mature after **100 blocks**. Pay a Dilithium
address (`getnewaddress`); paying a leftover ECDSA-shaped address would burn
the subsidy.

### Built-in CPU miner (regtest / experiments)

`generatetoaddress` is a hidden RPC. On **regtest** it is instant:

```bash
qbitcoind -regtest -daemon
qbitcoin-cli -regtest createwallet dev
ADDR=$(qbitcoin-cli -regtest -rpcwallet=dev getnewaddress)
qbitcoin-cli -regtest generatetoaddress 101 "$ADDR"
qbitcoin-cli -regtest -rpcwallet=dev getbalance
```

On **mainnet** the same RPC will try up to 1,000,000 hashes per call
(`maxtries`). That is enough only while difficulty is trivial. Raise the
third argument if you insist on CPU mining, and expect it to fail with
`Failed to find a valid proof-of-work within maxtries` once the network has
real hashrate:

```bash
ADDR=$(qbitcoin-cli -rpcwallet=mywallet getnewaddress)
qbitcoin-cli generatetoaddress 1 "$ADDR"
# optional: qbitcoin-cli generatetoaddress 1 "$ADDR" 100000000
qbitcoin-cli getmininginfo
```

`getmininginfo` reports difficulty, network hashrate, and whether mining is
active. Do not depend on unconfirmed coinbase.

### External miners (`getblocktemplate`)

Any Bitcoin-style getblocktemplate miner can in principle be pointed at
QubitCoin RPC (**2095** on localhost) once the node is synced:

```bash
qbitcoin-cli getblocktemplate '{"rules": ["segwit"]}'
```

The coinbase must pay a **Dilithium** script (a `Q…` address from this
wallet). This guide does not ship or endorse a particular external miner.

Testnet notes (min-difficulty after a 20-minute gap on testnet4):
[testnet.md](testnet.md#mining--getting-coins).

---

## Troubleshooting

### Shared library: `liboqs.so`

```
error while loading shared libraries: liboqs.so.8: cannot open shared object file
```

liboqs was built as a shared library and the dynamic linker cannot see it
(common when it installed to `/usr/local/lib`).

```bash
ldd "$(command -v qbitcoind || echo ./src/qbitcoind)" | grep -i oqs
sudo ldconfig
# If it still fails:
echo /usr/local/lib | sudo tee /etc/ld.so.conf.d/liboqs.conf
sudo ldconfig
export LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}
```

Confirm with `ldd` again; `liboqs.so` should resolve. Then restart the node.

### Startup self-test failed

```
Post-quantum (ML-DSA-65) cryptography sanity check failure
```

The node **refuses to start** if liboqs is missing, the wrong algorithm is
linked, or the pinned seed→key known-answer test does not match. Rebuild with
`./configure --with-liboqs=yes`, record `pkg-config --modversion liboqs`, and
do not mix binaries against a different liboqs than the one you tested.
Details: [qubitcoin-recovery.md](qubitcoin-recovery.md).

### No peers

1. Confirm you are on mainnet: `qbitcoin-cli getblockchaininfo` → `"chain": "main"`.
2. Add the public seeds explicitly:

   ```bash
   qbitcoin-cli addnode "137.184.152.223:2096" "add"
   qbitcoin-cli addnode "68.183.115.209:2096" "add"
   qbitcoin-cli getpeerinfo
   ```

3. Check the local listen port: `ss -ltnp | grep 2096` (or `netstat -ltnp`).
4. Outbound firewall / VPS security group must allow TCP **2096** to the
   seeds. Incoming peers also need **2096/tcp** open and `listen=1`.
5. `debug.log` (in the datadir) will say `connection refused`, `timeout`, or
   `No addresses` if the seeds are unreachable.
6. Do not use `-connect` unless you intend to talk to *only* those hosts.
7. Wrong network: `-testnet` / `-testnet4` / `-regtest` use different ports
   (12096 / 42096 / 21096) and will never sync mainnet.

### `createwallet` / empty keypool

Logs showing `Legacy Wallet Keys: 0` and `"keypoolsize": 0` are expected.
Dilithium keys are counted separately. `getnewaddress` still returns a `Q…`
address. Do not pass `descriptors=true`.

### `sendtoaddress` refused (“would burn the funds”)

You pasted a leftover ECDSA / SegWit / Taproot address. On this chain those
outputs are unspendable. Use a Dilithium `Q…` address from `getnewaddress`.
`listunspent` and `gettransaction` should show the same `Q…` encoding.

### RPC connection refused

The daemon is not running, you passed the wrong chain flag, or you are not
pointing at the datadir that holds `.cookie`. With systemd:

```bash
qbitcoin-cli -datadir=/var/lib/qubitcoin getblockchaininfo
```

RPC port is **2095** on mainnet and bound to 127.0.0.1 by default.

---

## Further reading

| Doc | Contents |
|-----|----------|
| [README.md](../README.md) | Positioning, parameters, limitations, warnings |
| [testnet.md](testnet.md) | Full RPC command reference; testnet3/4 and regtest |
| [qubitcoin-recovery.md](qubitcoin-recovery.md) | Backup, derivation, restore |
| [dilithium-crypto-audit.md](dilithium-crypto-audit.md) | Internal crypto/consensus review |
| [build-unix.md](build-unix.md) | Unix build details |
| [contrib/explorer/README.md](../contrib/explorer/README.md) | Self-hosted block explorer |
| [share/examples/qubitcoin.conf](../share/examples/qubitcoin.conf) | Config template |

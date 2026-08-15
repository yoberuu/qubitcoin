# QubitCoin Block Explorer (btc-rpc-explorer)

Self-hosted blockchain explorer for QubitCoin ($QBTC), based on
[janoside/btc-rpc-explorer](https://github.com/janoside/btc-rpc-explorer) with
QubitCoin-specific patches for Dilithium addresses and network parameters.

Supports **regtest**, **testnet3**, **testnet4**, and **mainnet** via Docker
Compose profiles — switch networks with one command.

---

## Prerequisites

1. **Docker** and **Docker Compose** v2
2. **qbitcoind** running on the target network with RPC enabled:

```ini
# In qubitcoin.conf (or per-network section)
server=1
# Recommended for full tx/address lookup:
txindex=1
```

3. RPC cookie file readable by Docker (default: `~/.qubitcoin/<network>/.cookie`)

---

## Quick start

### 1. Start qbitcoind (example: testnet4)

```bash
qbitcoind -testnet4 -daemon
qbitcoin-cli -testnet4 getblockchaininfo   # verify RPC works
```

### 2. Build and start the explorer

```bash
cd contrib/explorer
chmod +x scripts/explorer.sh

# Testnet4 (recommended) — UI at http://127.0.0.1:3004
./scripts/explorer.sh testnet4 up -d --build
```

### 3. Open the UI

| Network   | Default URL              | qbitcoind RPC port |
|-----------|--------------------------|--------------------|
| regtest   | http://127.0.0.1:3002    | 21095              |
| testnet3  | http://127.0.0.1:3003    | 12095              |
| testnet4  | http://127.0.0.1:3004    | 42095              |
| mainnet   | http://127.0.0.1:3005    | 2095               |

---

## Switching networks

Only one profile needs to run at a time for casual use:

```bash
# Stop testnet4 explorer
./scripts/explorer.sh testnet4 down

# Start regtest explorer
./scripts/explorer.sh regtest up -d
```

Or use docker compose directly:

```bash
docker compose --profile testnet4 up -d --build
docker compose --profile regtest down
```

### Run multiple explorers simultaneously

Each profile binds a different host port (3002–3005). Start more than one:

```bash
./scripts/explorer.sh regtest up -d
./scripts/explorer.sh testnet4 up -d
# regtest → :3002, testnet4 → :3004
```

---

## Configuration

### Environment files

```
env/
├── common.env      # Shared BTCEXP_* settings (coin=QBTC, no rates, etc.)
├── regtest.env     # RPC host/port for regtest
├── testnet3.env    # RPC for testnet3
├── testnet4.env    # RPC for testnet4
└── mainnet.env     # RPC for mainnet
```

### Cookie authentication (default)

The compose file mounts your qbitcoind data directory read-only at `/cookie`
and sets `BTCEXP_BITCOIND_COOKIE=/cookie/.cookie`.

Override paths in `.env` (copy from `.env.example`):

```bash
TESTNET4_COOKIE_DIR=/home/you/.qubitcoin/testnet4
```

### RPC user/password (alternative)

Edit the network env file and replace cookie auth:

```ini
# BTCEXP_BITCOIND_COOKIE=/cookie/.cookie
BTCEXP_BITCOIND_USER=myuser
BTCEXP_BITCOIND_PASS=mysecurepassword
```

### qbitcoind on another machine

Edit `env/<network>.env`:

```ini
BTCEXP_BITCOIND_HOST=192.168.1.50
BTCEXP_BITCOIND_PORT=42095
```

Remove the cookie volume mount and use `BTCEXP_BITCOIND_USER`/`PASS`, or mount
the remote cookie file locally.

### qbitcoind in Docker

If qbitcoind runs in another container on the same Docker network, set
`BTCEXP_BITCOIND_HOST` to the container service name (e.g. `qbitcoind`) instead
of `host.docker.internal`.

---

## File structure

```
contrib/explorer/
├── docker-compose.yml       # Multi-profile compose (regtest/testnet3/testnet4/mainnet)
├── Dockerfile               # Builds btc-rpc-explorer + QubitCoin patches
├── apply-patches.sh         # Injects coin config and address parsing patch
├── .env.example             # Optional port/cookie overrides
├── env/
│   ├── common.env
│   ├── regtest.env
│   ├── testnet3.env
│   ├── testnet4.env
│   └── mainnet.env
├── overlay/
│   ├── app/coins/qbtc.js    # QubitCoin network/currency definitions
│   ├── app/coins.js         # Registers QBTC coin
│   └── patches/
│       └── tryParseAddress.js.snippet  # Dilithium address search support
├── scripts/
│   └── explorer.sh          # Helper: ./scripts/explorer.sh <network> up -d
└── README.md                # This file
```

---

## What works / limitations

### Works well

- Block and transaction browsing via RPC
- Mempool summary, network info, RPC terminal
- Dilithium addresses **displayed** in transaction outputs (from `scriptPubKey.address`)
- Address **search** for Dilithium `q...` / `r...` base58 addresses (patched)
- `validateaddress` integration for address detail pages

### Limitations

| Topic | Detail |
|-------|--------|
| **Address history** | Without `txindex=1` or an Electrum indexer, address tx lists are shallow (`BTCEXP_NOTXINDEX_SEARCH_DEPTH`). Enable `txindex=1` on qbitcoind for best results. |
| **No Electrum yet** | `BTCEXP_ADDRESS_API` is unset; no external indexer for QubitCoin. |
| **Exchange rates** | Disabled (`BTCEXP_NO_RATES=true`) — no QBTC/USD feed. |
| **Mining pools** | Bitcoin pool lists don't apply; miner identification is address-only. |
| **Bitcoin fun facts** | Historical trivia items are empty for QBTC. |
| **testnet4 chain key** | Explorer reads `chain=testnet4` from RPC; coin config includes testnet4-specific genesis and titles. |
| **Large PQ txs** | Transaction pages may be slow for multi-input Dilithium transactions. |
| **bech32 Dilithium** | If used, HRPs `qc`/`tq`/`trq`/`sq`/`qcrt` are recognized in search; primary addresses are base58. |

### Dilithium address display

Stock btc-rpc-explorer only recognizes Bitcoin address prefixes (`1`/`3`/`bc1`
on mainnet, `m`/`n`/`2`/`tb1` on testnet). QubitCoin Dilithium P2PKH uses
custom base58 version bytes:

| Network   | Prefix | Example |
|-----------|--------|---------|
| mainnet   | varies | base58, non-Bitcoin version byte 58 |
| testnet3  | `q...` | e.g. `qNYLNChuWUyQhrayz2Y2PMs6gbhj7zdE3U` |
| testnet4  | `r...` | e.g. `r2TzdQ98nTZvUZQahsEt6SMGijhXVQAiUw` |
| regtest   | `q...` | same encoding as testnet3 |

Our patch adds these patterns to the explorer search router. Addresses in block/
tx views come directly from qbitcoind RPC and display correctly regardless.

---

## Troubleshooting

**"Unable to connect to RPC"**

- Confirm qbitcoind is running: `qbitcoin-cli -testnet4 getblockchaininfo`
- Check RPC port matches `env/<network>.env`
- On Linux, `host.docker.internal` requires Docker 20.10+ (compose adds `host-gateway`)

**"Cookie file not found"**

- Ensure `TESTNET4_COOKIE_DIR` (or equivalent) points to the datadir containing `.cookie`
- qbitcoind creates `.cookie` only when started with `-server=1`

**Address page shows no transactions**

- Enable `txindex=1` in qubitcoin.conf and restart (or reindex)
- Without txindex, only recent blocks are scanned

**Rebuild after patch changes**

```bash
./scripts/explorer.sh testnet4 build
./scripts/explorer.sh testnet4 up -d
```

---

## Development

The Docker image pins btc-rpc-explorer to **v3.5.1**. To upgrade:

1. Bump `BTC_RPC_EXPLORER_VERSION` in `Dockerfile`
2. Verify `apply-patches.sh` still matches `utils.js` structure
3. Rebuild: `docker compose --profile regtest build --no-cache`

---

## See also

- [doc/testnet.md](../../doc/testnet.md) — QubitCoin testnet operator guide
- [share/examples/qubitcoin.conf](../../share/examples/qubitcoin.conf) — node configuration
- [btc-rpc-explorer docs](https://github.com/janoside/btc-rpc-explorer) — upstream project

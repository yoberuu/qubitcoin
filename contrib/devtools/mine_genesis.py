#!/usr/bin/env python3
"""Mine a QubitCoin genesis block matching CreateGenesisBlock() in chainparams.cpp."""

import hashlib
import struct
import sys
from multiprocessing import Pool

COIN = 100_000_000
GENESIS_PUBKEY = bytes.fromhex(
    "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
)


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def encode_script_num(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    neg = n < 0
    abs_n = abs(n)
    result = bytearray()
    while abs_n:
        result.append(abs_n & 0xFF)
        abs_n >>= 8
    if result[-1] & 0x80:
        result.append(0x80 if neg else 0x00)
    elif neg:
        result[-1] |= 0x80
    return bytes(result)


def push_data(data: bytes) -> bytes:
    length = len(data)
    if length < 76:
        return bytes([length]) + data
    if length < 256:
        return b"\x4c" + bytes([length]) + data
    if length < 65536:
        return b"\x4d" + struct.pack("<H", length) + data
    return b"\x4e" + struct.pack("<I", length) + data


def compact_size(n: int) -> bytes:
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def build_coinbase_tx(timestamp: str, reward: int) -> bytes:
    ts_bytes = timestamp.encode("ascii")
    script_sig = (
        push_data(struct.pack("<I", 0x1D00FFFF))
        + push_data(encode_script_num(4))
        + push_data(ts_bytes)
    )
    script_pubkey = bytes([len(GENESIS_PUBKEY)]) + GENESIS_PUBKEY + b"\xac"

    tx = b""
    tx += struct.pack("<I", 1)  # version
    tx += compact_size(1)  # vin count
    tx += b"\x00" * 32  # prev txid
    tx += struct.pack("<I", 0xFFFFFFFF)  # prev index
    tx += compact_size(len(script_sig)) + script_sig
    tx += struct.pack("<I", 0xFFFFFFFF)  # sequence
    tx += compact_size(1)  # vout count
    tx += struct.pack("<Q", reward)
    tx += compact_size(len(script_pubkey)) + script_pubkey
    tx += struct.pack("<I", 0)  # locktime
    return tx


def merkle_root(coinbase_tx: bytes) -> bytes:
    return sha256d(coinbase_tx)


def compact_to_target(bits: int) -> int:
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def check_proof_of_work(hash_bytes: bytes, bits: int) -> bool:
    target = compact_to_target(bits)
    hash_int = int.from_bytes(hash_bytes[::-1], "big")
    return hash_int <= target


def mine_genesis(timestamp: str, reward: int, n_time: int, n_bits: int, version: int = 1, start_nonce: int = 0, workers: int = 8):
    coinbase = build_coinbase_tx(timestamp, reward)
    root = merkle_root(coinbase)

    header_prefix = struct.pack("<I", version) + b"\x00" * 32 + root + struct.pack("<III", n_time, n_bits, 0)

    chunk = 1_000_000
    nonce = start_nonce
    while nonce < 0x100000000:
        with Pool(workers) as pool:
            ranges = [(header_prefix, n_bits, nonce + i * chunk, min(nonce + (i + 1) * chunk, 0x100000000)) for i in range(workers)]
            for result in pool.starmap(_mine_range, ranges):
                if result is not None:
                    found_nonce, block_hash = result
                    return {
                        "timestamp": timestamp,
                        "nTime": n_time,
                        "nNonce": found_nonce,
                        "nBits": n_bits,
                        "merkle_root": root[::-1].hex(),
                        "txid": sha256d(coinbase)[::-1].hex(),
                        "block_hash": block_hash[::-1].hex(),
                    }
        nonce += workers * chunk
        if nonce % (workers * chunk * 10) == 0:
            print(f"  tried {nonce} nonces...", file=sys.stderr)

    return None


def _mine_range(header_prefix: bytes, n_bits: int, start: int, end: int):
    for nonce in range(start, end):
        header = header_prefix[:-4] + struct.pack("<I", nonce)
        block_hash = sha256d(header)
        if check_proof_of_work(block_hash, n_bits):
            return nonce, block_hash
    return None


CHAIN_CONFIG = {
    "mainnet": {
        "timestamp": "Yelpful Technologies launches QubitCoin ($QBTC) 06/Jul/2026",
        "n_time": 1783296000,
        "n_bits": 0x1D00FFFF,
    },
    "regtest": {
        "timestamp": "QubitCoin regtest genesis 06/Jul/2026",
        "n_time": 1783296001,
        "n_bits": 0x207FFFFF,
    },
    "testnet3": {
        "timestamp": "QubitCoin Testnet3 09/Jul/2026",
        "n_time": 1783555200,  # 2026-07-09 00:00:00 UTC
        "n_bits": 0x1D00FFFF,
    },
    "testnet4": {
        "timestamp": "QubitCoin Testnet4 09/Jul/2026",
        "n_time": 1783555201,
        "n_bits": 0x1D00FFFF,
    },
    "signet": {
        "timestamp": "QubitCoin Signet genesis 09/Jul/2026",
        "n_time": 1783555202,
        "n_bits": 0x1E0377AE,
    },
}


def main():
    if len(sys.argv) < 2:
        print("Usage: mine_genesis.py [mainnet|regtest|testnet3|testnet4|signet]")
        sys.exit(1)

    chain = sys.argv[1]
    reward = 500 * COIN

    if chain not in CHAIN_CONFIG:
        print(f"Unknown chain: {chain}")
        print(f"Valid chains: {', '.join(CHAIN_CONFIG)}")
        sys.exit(1)

    cfg = CHAIN_CONFIG[chain]
    print(f"Mining {chain} genesis (bits=0x{cfg['n_bits']:08x})...")
    n_time = cfg["n_time"]
    for attempt in range(3600):
        result = mine_genesis(cfg["timestamp"], reward, n_time, cfg["n_bits"])
        if result is not None:
            break
        n_time += 1
        print(f"  no solution at nTime={n_time - 1}, retrying with nTime={n_time}...", file=sys.stderr)
    else:
        print("Failed to mine genesis within time search range", file=sys.stderr)
        sys.exit(1)

    for k, v in result.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()

# QubitCoin L1 ($QBTC) - Bitcoin Fork Plan

## Project Info
- Name: QubitCoin ($QBTC)
- Tone: Satirical / meme about quantum computing fears + real tech
- Signature Scheme: Pure Dilithium (ML-DSA) — no hybrid
- Supply: 210,000,000 with halvings
- Genesis: Fresh genesis block
- Branding: QubitCoin by Yelpful Technologies
- Relationship to Solana: Separate but related (Solana memecoin already live)

## Goals
- Keep changes as minimal as possible
- Replace ECDSA with pure Dilithium
- Rebrand everything to QubitCoin / $QBTC / Yelpful Technologies
- Fresh genesis + 210M supply with halvings
- Good test coverage before testnet

## Priority Order
1. Rebranding (names, strings, magic bytes, ports, etc.)
2. Fresh genesis block + chain parameters
3. Supply change to 210,000,000 with halvings
4. Pure Dilithium integration (using liboqs)
5. Wallet & address updates
6. Testing & testnet launch

## Rules for Changes
- Only change what is necessary for Dilithium + rebranding + supply
- Keep everything else as close to Bitcoin Core as possible

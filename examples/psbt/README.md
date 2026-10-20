# PSBT Examples for Testnet4

Educational examples demonstrating the complete PSBT (BIP-174) workflow on
Bitcoin Testnet4. Each script walks through every BIP-174 role and produces
a fully signed transaction ready for broadcast.

## Compatibility Matrix

| Feature             | Status |
|---------------------|--------|
| BIP-174 Core PSBT   | ✅      |
| BIP-371 Key-path    | ✅      |
| BIP-371 Script-path | ❌      |
| BIP-370 (PSBTv2)    | ❌      |
| P2PKH               | ✅      |
| P2WPKH              | ✅      |
| P2WSH (multisig)    | ✅      |
| P2SH-P2WPKH         | ✅      |
| P2TR Key-path       | ✅      |
| P2TR Script-path    | ❌      |

## Prerequisites

### 1. Get Testnet4 Coins

Fund your address using one of these faucets:

- https://faucet.testnet4.dev
- https://mempool.space/testnet4/faucet

### 2. Wait for Confirmation

Check that your funding transaction has at least one confirmation:

- https://mempool.space/testnet4

### 3. Update the Example Scripts

Each script has a clearly marked section at the top:

```python
# ======================================================================
# FILL THESE VALUES after funding your address on testnet4
# ======================================================================
UTXO_TXID = "your_funding_txid_here"
UTXO_VOUT = 0
UTXO_AMOUNT = 0.001  # BTC received from faucet
```

Replace these with the actual values from your funding transaction.

## Examples

### `psbt_p2wpkh_testnet4.py` — Native SegWit (P2WPKH)

Single-signature SegWit transaction through the full PSBT lifecycle:

```
Creator → Updater → Signer → Finalizer → Extractor
```

```bash
python examples/psbt/psbt_p2wpkh_testnet4.py
```

### `psbt_multisig_testnet4.py` — 2-of-3 P2WSH Multisig

Multi-party signing workflow with two independent signers:

```
Creator → Updater → Signer A → Signer B → Combiner → Finalizer → Extractor
```

```bash
python examples/psbt/psbt_multisig_testnet4.py
```

### `psbt_p2tr_testnet4.py` — Taproot Key-Path (P2TR)

Taproot key-path spending using Schnorr signatures and BIP-371 PSBT fields:

```
Creator → Updater (tap_internal_key) → Signer (tap_key_sig) → Finalizer → Extractor
```

```bash
python examples/psbt/psbt_p2tr_testnet4.py
```

### `psbt_p2tr_hd_testnet4.py` — Taproot HD Wallet

Deterministic Taproot key-path spending using standard BIP-32/BIP-86 derivations from a mnemonic seed. 

```bash
python examples/psbt/psbt_p2tr_hd_testnet4.py
```

### `verify_testnet4.py` — Live Verification

An interactive manual verification script that fetches live UTXOs, constructs a PSBT, signs, and broadcasts it to the network.

```bash
python examples/verify_testnet4.py
```

## PSBT Workflow

### Standard PSBT Flow (BIP-174)

```
Unsigned Transaction
        │
        ▼
    ┌────────┐
    │Creator │  Wraps raw tx in PSBT container
    └────┬───┘
         │
         ▼
    ┌────────┐
    │Updater │  Adds UTXOs, scripts, derivation paths
    └────┬───┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌────────┐ ┌────────┐
│Signer A│ │Signer B│  Each adds partial signatures
└────┬───┘ └────┬───┘
     │         │
     └────┬────┘
          │
          ▼
    ┌──────────┐
    │ Combiner │  Merges signed PSBTs
    └────┬─────┘
         │
         ▼
    ┌──────────┐
    │Finalizer │  Converts signatures → scriptSig / witness
    └────┬─────┘
         │
         ▼
    ┌──────────┐
    │Extractor │  Produces network-ready transaction
    └────┬─────┘
         │
         ▼
    Broadcast
```

### Taproot Key-Path Flow (BIP-371)

```
Unsigned Transaction
        │
        ▼
    ┌────────┐
    │Creator │  Wraps raw tx in PSBT
    └────┬───┘
         │
         ▼
    ┌────────┐
    │Updater │  Sets witness_utxo + tap_internal_key
    └────┬───┘
         │
         ▼
    ┌────────┐
    │ Signer │  Schnorr sign → tap_key_sig (64 bytes)
    └────┬───┘
         │
         ▼
    ┌──────────┐
    │Finalizer │  witness = [tap_key_sig]
    └────┬─────┘
         │
         ▼
    ┌──────────┐
    │Extractor │  Signed transaction
    └──────────┘
```

## Broadcasting

The example scripts do **not** broadcast automatically. Instead, they print
the raw signed transaction hex and instructions for manual broadcast.

### Option 1: Bitcoin Core RPC

```bash
bitcoin-cli -testnet4 sendrawtransaction <raw_tx_hex>
```

### Option 2: Mempool.space API

```bash
curl -X POST https://mempool.space/testnet4/api/tx -d '<raw_tx_hex>'
```

### Option 3: Blockstream API

```bash
curl -X POST https://blockstream.info/testnet/api/tx -d '<raw_tx_hex>'
```

After broadcasting, check the transaction at:

```
https://mempool.space/testnet4/tx/<txid>
```

## Regtest Examples

For regtest-based examples that use a local Bitcoin Core node, see:

- [PSBT_2of3_MULTISIG.md](PSBT_2of3_MULTISIG.md) — 2-of-3 P2SH multisig on regtest
- [psbt_2of3_create.py](psbt_2of3_create.py) — Creator + Updater
- [psbt_2of3_sign1.py](psbt_2of3_sign1.py) — Signer 1
- [psbt_2of3_sign2.py](psbt_2of3_sign2.py) — Signer 2 + Combiner + Finalizer + Extractor

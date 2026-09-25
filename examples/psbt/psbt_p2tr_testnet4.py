# Copyright (C) 2018-2025 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.


"""PSBT Taproot Key-Path (P2TR) — Testnet4 Educational Example.

Demonstrates Taproot key-path spending using the PSBT workflow on Bitcoin
Testnet4. This uses BIP-371 Taproot-specific PSBT fields (tap_key_sig,
tap_internal_key).

BIP-174 / BIP-371 roles exercised:
    Creator   — builds the unsigned transaction and wraps it in a PSBT
    Updater   — attaches witness UTXO and tap_internal_key
    Signer    — Schnorr-signs the input (produces tap_key_sig)
    Finalizer — converts tap_key_sig into a witness stack
    Extractor — pulls out the fully signed transaction

Taproot key-path spending uses:
    - x-only public keys (32 bytes, BIP-340)
    - Schnorr signatures (64 bytes for default sighash, BIP-340)
    - Tweaked private keys (BIP-341)
    - Taproot-specific sighash computation (BIP-341)

Prerequisites:
    1. Fund the Taproot address using a testnet4 faucet.
    2. Fill in UTXO_TXID, UTXO_VOUT, and UTXO_AMOUNT below.

The script prints the raw signed transaction hex and broadcast instructions.
It does NOT broadcast automatically.
"""

from bitcoinutils.setup import setup
from bitcoinutils.utils import to_satoshis, h_to_b, b_to_h
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.keys import PrivateKey, P2pkhAddress
from bitcoinutils.script import Script
from bitcoinutils.psbt import PSBT


# ======================================================================
# FILL THESE VALUES after funding your Taproot address on testnet4
# ======================================================================
UTXO_TXID = "replace_with_your_funding_txid"
UTXO_VOUT = 0
UTXO_AMOUNT = 0.001  # BTC received from faucet
# ======================================================================

SEND_AMOUNT = 0.0005   # BTC to send
FEE = 0.00001          # BTC miner fee

# The sender's private key (testnet WIF format).
# The corresponding Taproot address is derived from the tweaked x-only pubkey.
SENDER_WIF = "cV3R88re3AZSBnWhBBNdiCKTfwpMKkYYjdiR13HQzsU7zoRNX7JL"

# Configurable explorer endpoint for broadcast instructions
API_ENDPOINT = "https://mempool.space/testnet4/api"


def main():
    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------
    setup("testnet4")

    sender_key = PrivateKey.from_wif(SENDER_WIF)
    sender_pubkey = sender_key.get_public_key()
    sender_taproot_addr = sender_pubkey.get_taproot_address()

    # The x-only public key (32 bytes) and the tweaked version
    x_only_hex = sender_pubkey.to_x_only_hex()
    tweaked_hex, _ = sender_pubkey.to_taproot_hex()

    print("=" * 70)
    print("PSBT Taproot Key-Path (P2TR) — Testnet4 Example")
    print("=" * 70)
    print(f"\nTaproot address (P2TR): {sender_taproot_addr.to_string()}")
    print(f"Internal key (x-only): {x_only_hex}")
    print(f"Tweaked key:           {tweaked_hex}")
    print(f"Fund this address, then update UTXO_TXID and UTXO_VOUT.\n")

    if UTXO_TXID == "replace_with_your_funding_txid":
        print("ERROR: Please update UTXO_TXID with your funding transaction ID.")
        print("       See examples/psbt/README.md for instructions.")
        return

    change_amount = UTXO_AMOUNT - SEND_AMOUNT - FEE

    # ------------------------------------------------------------------
    # Creator role: build the unsigned transaction
    # ------------------------------------------------------------------
    print("-" * 70)
    print("Step 1: Creator — Build unsigned transaction")
    print("-" * 70)

    txin = TxInput(UTXO_TXID, UTXO_VOUT)

    # The Taproot scriptPubKey: OP_1 <32-byte-tweaked-pubkey>
    sender_script_pubkey = sender_taproot_addr.to_script_pub_key()

    # Send to a P2PKH destination for demonstration
    dest_addr = P2pkhAddress("mtVHHCqCECGwiMbMoZe8ayhJHuTdDbYWdJ")
    txout_send = TxOutput(
        to_satoshis(SEND_AMOUNT),
        dest_addr.to_script_pub_key(),
    )

    # Change back to Taproot address
    txout_change = TxOutput(
        to_satoshis(change_amount),
        sender_script_pubkey,
    )

    tx = Transaction([txin], [txout_send, txout_change], has_segwit=True)

    print(f"  Inputs:  1 (from Taproot address)")
    print(f"  Outputs: 2 (send + change)")
    print(f"  Send:    {SEND_AMOUNT} BTC → {dest_addr.to_string()}")
    print(f"  Change:  {change_amount} BTC → Taproot")
    print(f"  Fee:     {FEE} BTC")

    # ------------------------------------------------------------------
    # Creator: wrap in PSBT
    # ------------------------------------------------------------------
    psbt = PSBT(tx)

    # ------------------------------------------------------------------
    # Updater role: attach witness UTXO and Taproot metadata
    # ------------------------------------------------------------------
    print(f"\n{'-' * 70}")
    print("Step 2: Updater — Attach witness UTXO and Taproot metadata")
    print("-" * 70)

    witness_utxo = TxOutput(
        to_satoshis(UTXO_AMOUNT),
        sender_script_pubkey,
    )
    psbt.update_input(0, witness_utxo=witness_utxo)

    # BIP-371: set the internal key (x-only, 32 bytes)
    # This tells the signer which key to use for Taproot signing.
    psbt.inputs[0].tap_internal_key = h_to_b(x_only_hex)

    unsigned_b64 = psbt.to_base64()
    print(f"  Witness UTXO: {UTXO_AMOUNT} BTC")
    print(f"  tap_internal_key: {x_only_hex}")
    print(f"\nUnsigned PSBT (base64):\n{unsigned_b64}")

    # ------------------------------------------------------------------
    # Signer role: Taproot key-path signing (Schnorr / BIP-340)
    # ------------------------------------------------------------------
    print(f"\n{'-' * 70}")
    print("Step 3: Signer — Schnorr sign (Taproot key-path)")
    print("-" * 70)

    # For Taproot signing, we need ALL input amounts and scriptPubKeys
    # (required by BIP-341 sighash computation)
    amounts = [to_satoshis(UTXO_AMOUNT)]
    utxo_scripts = [sender_script_pubkey]

    sig_hex = sender_key.sign_taproot_input(
        psbt.tx, 0, utxo_scripts, amounts,
        script_path=False,
        tweak=True,
    )

    # BIP-371: store as tap_key_sig (NOT partial_sigs)
    psbt.inputs[0].tap_key_sig = h_to_b(sig_hex)

    print(f"  Schnorr signature: {sig_hex[:32]}...")
    print(f"  Signature length:  {len(h_to_b(sig_hex))} bytes")
    print(f"  tap_key_sig set:   yes")

    signed_b64 = psbt.to_base64()
    print(f"\nSigned PSBT (base64):\n{signed_b64}")

    # ------------------------------------------------------------------
    # Finalizer role: convert tap_key_sig → witness stack
    # ------------------------------------------------------------------
    print(f"\n{'-' * 70}")
    print("Step 4: Finalizer — Build witness from tap_key_sig")
    print("-" * 70)

    # For Taproot key-path: witness = [signature]
    psi = psbt.inputs[0]
    psi.final_scriptwitness = [psi.tap_key_sig]
    psi.final_scriptsig = Script([])

    # Clear non-final Taproot fields
    psi.tap_key_sig = None
    psi.tap_internal_key = None

    print(f"  Final witness items: {len(psi.final_scriptwitness)}")
    print(f"  Witness[0] (sig):   {b_to_h(psi.final_scriptwitness[0])[:32]}...")

    # ------------------------------------------------------------------
    # Extractor role: pull out the signed transaction
    # ------------------------------------------------------------------
    print(f"\n{'-' * 70}")
    print("Step 5: Extractor — Extract signed transaction")
    print("-" * 70)

    final_tx = psbt.extract_transaction()
    raw_hex = final_tx.serialize()
    txid = final_tx.get_txid()

    print(f"\nRaw signed transaction:\n{raw_hex}")
    print(f"\nTransaction ID:\n{txid}")

    # Verify witness structure
    print(f"\n  Witness stack:")
    for i, wit in enumerate(final_tx.witnesses):
        for j, item in enumerate(wit.stack):
            print(f"    [{j}] {item}")

    # ------------------------------------------------------------------
    # Broadcast instructions
    # ------------------------------------------------------------------
    print(f"\n{'=' * 70}")
    print("Broadcast Instructions")
    print("=" * 70)
    print(f"\nOption 1 — Bitcoin Core RPC:")
    print(f"  bitcoin-cli -testnet4 sendrawtransaction {raw_hex}")
    print(f"\nOption 2 — Mempool.space API:")
    print(f"  curl -X POST {API_ENDPOINT}/tx -d '{raw_hex}'")
    print(f"\nAfter broadcasting, view at:")
    print(f"  https://mempool.space/testnet4/tx/{txid}")


if __name__ == "__main__":
    main()

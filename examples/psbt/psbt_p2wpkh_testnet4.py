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


"""PSBT P2WPKH — Testnet4 Educational Example.

Demonstrates the complete BIP-174 PSBT lifecycle for a native SegWit
(P2WPKH) transaction on Bitcoin Testnet4.

BIP-174 roles exercised:
    Creator   — builds the unsigned transaction and wraps it in a PSBT
    Updater   — attaches the witness UTXO
    Signer    — signs the input with the private key
    Finalizer — converts the partial signature into a witness stack
    Extractor — pulls out the fully signed transaction

Prerequisites:
    1. Fund the sender address using a testnet4 faucet:
       - https://faucet.testnet4.dev
       - https://mempool.space/testnet4/faucet
    2. Wait for at least one confirmation.
    3. Fill in UTXO_TXID, UTXO_VOUT, and UTXO_AMOUNT below.

The script prints the raw signed transaction hex and broadcast instructions.
It does NOT broadcast automatically.
"""

from bitcoinutils.setup import setup
from bitcoinutils.utils import to_satoshis
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import PrivateKey
from bitcoinutils.psbt import PSBT


# ======================================================================
# FILL THESE VALUES after funding your address on testnet4
# ======================================================================
UTXO_TXID = "replace_with_your_funding_txid"
UTXO_VOUT = 0
UTXO_AMOUNT = 0.001  # BTC received from faucet
# ======================================================================

# Destination: send most of the funds to this address.
# Change goes back to the sender. Difference is the miner fee.
SEND_AMOUNT = 0.0005   # BTC to send
FEE = 0.00001          # BTC miner fee

# The sender's private key (testnet WIF format).
# This corresponds to a P2WPKH (native SegWit) address on testnet4.
SENDER_WIF = "cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo"

# Configurable explorer endpoint for broadcast instructions
API_ENDPOINT = "https://mempool.space/testnet4/api"


def main():
    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------
    setup("testnet4")

    sender_key = PrivateKey.from_wif(SENDER_WIF)
    sender_pubkey = sender_key.get_public_key()
    sender_addr = sender_pubkey.get_segwit_address()

    print("=" * 70)
    print("PSBT P2WPKH — Testnet4 Example")
    print("=" * 70)
    print(f"\nSender address (P2WPKH): {sender_addr.to_string()}")
    print(f"Fund this address, then update UTXO_TXID and UTXO_VOUT.\n")

    if UTXO_TXID == "replace_with_your_funding_txid":
        print("ERROR: Please update UTXO_TXID with your funding transaction ID.")
        print("       See examples/psbt/README.md for instructions.")
        return

    change_amount = UTXO_AMOUNT - SEND_AMOUNT - FEE

    # ------------------------------------------------------------------
    # Creator role: build the unsigned transaction and wrap in PSBT
    # ------------------------------------------------------------------
    print("-" * 70)
    print("Step 1: Creator — Build unsigned transaction")
    print("-" * 70)

    txin = TxInput(UTXO_TXID, UTXO_VOUT)

    # Send to a P2WPKH destination (here we use the same address for demo)
    destination_addr = sender_addr
    txout_send = TxOutput(
        to_satoshis(SEND_AMOUNT),
        destination_addr.to_script_pub_key(),
    )

    # Change output back to sender
    txout_change = TxOutput(
        to_satoshis(change_amount),
        sender_addr.to_script_pub_key(),
    )

    tx = Transaction([txin], [txout_send, txout_change], has_segwit=True)
    psbt = PSBT(tx)

    print(f"  Transaction inputs:  1")
    print(f"  Transaction outputs: 2 (send + change)")
    print(f"  Send:   {SEND_AMOUNT} BTC")
    print(f"  Change: {change_amount} BTC")
    print(f"  Fee:    {FEE} BTC")

    # ------------------------------------------------------------------
    # Updater role: attach the witness UTXO
    # ------------------------------------------------------------------
    print(f"\n{'-' * 70}")
    print("Step 2: Updater — Attach witness UTXO metadata")
    print("-" * 70)

    witness_utxo = TxOutput(
        to_satoshis(UTXO_AMOUNT),
        sender_addr.to_script_pub_key(),
    )
    psbt.update_input(0, witness_utxo=witness_utxo)

    unsigned_b64 = psbt.to_base64()
    print(f"  Witness UTXO amount: {UTXO_AMOUNT} BTC")
    print(f"\nUnsigned PSBT (base64):\n{unsigned_b64}")

    # ------------------------------------------------------------------
    # Signer role: sign the input
    # ------------------------------------------------------------------
    print(f"\n{'-' * 70}")
    print("Step 3: Signer — Sign input with private key")
    print("-" * 70)

    signed = psbt.sign_input(0, sender_key)
    print(f"  Signature produced: {signed}")
    print(f"  Partial signatures: {len(psbt.inputs[0].partial_sigs)}")

    signed_b64 = psbt.to_base64()
    print(f"\nSigned PSBT (base64):\n{signed_b64}")

    # ------------------------------------------------------------------
    # Finalizer role: convert partial sig → witness stack
    # ------------------------------------------------------------------
    print(f"\n{'-' * 70}")
    print("Step 4: Finalizer — Convert signature to witness")
    print("-" * 70)

    psbt.finalize_input(0)
    psi = psbt.inputs[0]
    print(f"  Final witness items: {len(psi.final_scriptwitness)}")

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

    # ------------------------------------------------------------------
    # Broadcast instructions (no automatic network calls)
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

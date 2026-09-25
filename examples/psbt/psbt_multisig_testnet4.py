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


"""PSBT 2-of-3 Multisig P2WSH — Testnet4 Educational Example.

Demonstrates the complete BIP-174 PSBT lifecycle for a 2-of-3 multisig
P2WSH transaction on Bitcoin Testnet4. This is the canonical multi-party
signing use case for PSBT.

BIP-174 roles exercised:
    Creator   — builds the unsigned transaction and wraps it in a PSBT
    Updater   — attaches witness UTXO and witness script metadata
    Signer A  — signs with private key 1
    Signer B  — signs with private key 2 (independently)
    Combiner  — merges the two partially signed PSBTs
    Finalizer — converts partial signatures into a witness stack
    Extractor — pulls out the fully signed transaction

Prerequisites:
    1. Run the script once to see the multisig address.
    2. Fund the multisig address using a testnet4 faucet.
    3. Fill in UTXO_TXID, UTXO_VOUT, and UTXO_AMOUNT below.

The script prints the raw signed transaction hex and broadcast instructions.
It does NOT broadcast automatically.
"""

from bitcoinutils.setup import setup
from bitcoinutils.utils import to_satoshis
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import PrivateKey, P2pkhAddress
from bitcoinutils.script import Script
from bitcoinutils.psbt import PSBT


# ======================================================================
# FILL THESE VALUES after funding the multisig address on testnet4
# ======================================================================
UTXO_TXID = "replace_with_your_funding_txid"
UTXO_VOUT = 0
UTXO_AMOUNT = 0.001  # BTC received from faucet
# ======================================================================

SEND_AMOUNT = 0.0005   # BTC to send to destination
FEE = 0.00001          # BTC miner fee

# Three private keys for the 2-of-3 multisig (testnet WIF format).
# In production, these would be held by different parties on separate devices.
SIGNER_1_WIF = "cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo"
SIGNER_2_WIF = "cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9"
SIGNER_3_WIF = "cNxX8M7XU8VNa5ofd8yk1eiZxaxNrQQyb7xNpwAmsrzEhcVwtCjs"

# Configurable explorer endpoint for broadcast instructions
API_ENDPOINT = "https://mempool.space/testnet4/api"


def main():
    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------
    setup("testnet4")

    sk1 = PrivateKey.from_wif(SIGNER_1_WIF)
    sk2 = PrivateKey.from_wif(SIGNER_2_WIF)
    sk3 = PrivateKey.from_wif(SIGNER_3_WIF)

    pk1 = sk1.get_public_key()
    pk2 = sk2.get_public_key()
    pk3 = sk3.get_public_key()

    # ------------------------------------------------------------------
    # Build the 2-of-3 witness script and P2WSH address
    # ------------------------------------------------------------------
    witness_script = Script([
        "OP_2",
        pk1.to_hex(),
        pk2.to_hex(),
        pk3.to_hex(),
        "OP_3",
        "OP_CHECKMULTISIG",
    ])

    p2wsh_script = witness_script.to_p2wsh_script_pub_key()

    # Derive the P2WSH address for display
    # P2WSH uses OP_0 <32-byte-hash> — bech32 encoded
    from bitcoinutils.keys import P2wshAddress
    p2wsh_addr = P2wshAddress(script=witness_script)

    print("=" * 70)
    print("PSBT 2-of-3 Multisig P2WSH — Testnet4 Example")
    print("=" * 70)
    print(f"\nMultisig address (P2WSH): {p2wsh_addr.to_string()}")
    print(f"Fund this address, then update UTXO_TXID and UTXO_VOUT.\n")
    print(f"Signer 1 pubkey: {pk1.to_hex()}")
    print(f"Signer 2 pubkey: {pk2.to_hex()}")
    print(f"Signer 3 pubkey: {pk3.to_hex()}")
    print(f"Witness script:  {witness_script.to_hex()}")

    if UTXO_TXID == "replace_with_your_funding_txid":
        print("\nERROR: Please update UTXO_TXID with your funding transaction ID.")
        print("       See examples/psbt/README.md for instructions.")
        return

    change_amount = UTXO_AMOUNT - SEND_AMOUNT - FEE

    # ------------------------------------------------------------------
    # Creator role: build the unsigned transaction
    # ------------------------------------------------------------------
    print(f"\n{'-' * 70}")
    print("Step 1: Creator — Build unsigned transaction")
    print("-" * 70)

    txin = TxInput(UTXO_TXID, UTXO_VOUT)

    # Send to a simple P2PKH destination for demonstration
    dest_addr = pk1.get_address()
    txout_send = TxOutput(
        to_satoshis(SEND_AMOUNT),
        dest_addr.to_script_pub_key(),
    )

    txout_change = TxOutput(
        to_satoshis(change_amount),
        p2wsh_script,  # change back to the multisig
    )

    tx = Transaction([txin], [txout_send, txout_change], has_segwit=True)

    print(f"  Inputs:  1 (from multisig)")
    print(f"  Outputs: 2 (send + change)")
    print(f"  Send:    {SEND_AMOUNT} BTC → {dest_addr.to_string()}")
    print(f"  Change:  {change_amount} BTC → multisig")
    print(f"  Fee:     {FEE} BTC")

    # ------------------------------------------------------------------
    # Updater role: attach UTXO and script metadata
    # ------------------------------------------------------------------
    print(f"\n{'-' * 70}")
    print("Step 2: Updater — Attach witness UTXO and witness script")
    print("-" * 70)

    # Create the PSBT and distribute to signers
    psbt_base = PSBT(tx)
    witness_utxo = TxOutput(to_satoshis(UTXO_AMOUNT), p2wsh_script)
    psbt_base.update_input(
        0,
        witness_utxo=witness_utxo,
        witness_script=witness_script,
    )

    unsigned_b64 = psbt_base.to_base64()
    print(f"  Witness UTXO amount: {UTXO_AMOUNT} BTC")
    print(f"  Witness script attached: yes")
    print(f"\nUnsigned PSBT (base64):\n{unsigned_b64}")

    # ------------------------------------------------------------------
    # Signer A: sign independently
    # ------------------------------------------------------------------
    print(f"\n{'-' * 70}")
    print("Step 3: Signer A — Sign with key 1")
    print("-" * 70)

    # In production, Signer A receives the unsigned PSBT via file/QR/NFC.
    # Here we simulate by deserializing from the base64 string.
    psbt_a = PSBT.from_base64(unsigned_b64)
    signed_a = psbt_a.sign_input(0, sk1)
    print(f"  Signature produced: {signed_a}")
    print(f"  Partial sigs: {len(psbt_a.inputs[0].partial_sigs)}")

    signed_a_b64 = psbt_a.to_base64()
    print(f"\nSigner A PSBT (base64):\n{signed_a_b64}")

    # ------------------------------------------------------------------
    # Signer B: sign independently
    # ------------------------------------------------------------------
    print(f"\n{'-' * 70}")
    print("Step 4: Signer B — Sign with key 2")
    print("-" * 70)

    # Signer B also starts from the unsigned PSBT (independent of Signer A)
    psbt_b = PSBT.from_base64(unsigned_b64)
    signed_b = psbt_b.sign_input(0, sk2)
    print(f"  Signature produced: {signed_b}")
    print(f"  Partial sigs: {len(psbt_b.inputs[0].partial_sigs)}")

    signed_b_b64 = psbt_b.to_base64()
    print(f"\nSigner B PSBT (base64):\n{signed_b_b64}")

    # ------------------------------------------------------------------
    # Combiner role: merge the two signed PSBTs
    # ------------------------------------------------------------------
    print(f"\n{'-' * 70}")
    print("Step 5: Combiner — Merge signed PSBTs")
    print("-" * 70)

    combined = psbt_a.combine(psbt_b)
    print(f"  Combined partial sigs: {len(combined.inputs[0].partial_sigs)}")

    combined_b64 = combined.to_base64()
    print(f"\nCombined PSBT (base64):\n{combined_b64}")

    # ------------------------------------------------------------------
    # Finalizer role: convert partial sigs → witness stack
    # ------------------------------------------------------------------
    print(f"\n{'-' * 70}")
    print("Step 6: Finalizer — Build witness stack from partial signatures")
    print("-" * 70)

    combined.finalize_input(0)
    psi = combined.inputs[0]
    print(f"  Final witness items: {len(psi.final_scriptwitness)}")
    # For 2-of-3 multisig: OP_0, sig1, sig2, witnessScript = 4 items

    # ------------------------------------------------------------------
    # Extractor role: pull out the signed transaction
    # ------------------------------------------------------------------
    print(f"\n{'-' * 70}")
    print("Step 7: Extractor — Extract signed transaction")
    print("-" * 70)

    final_tx = combined.extract_transaction()
    raw_hex = final_tx.serialize()
    txid = final_tx.get_txid()

    print(f"\nRaw signed transaction:\n{raw_hex}")
    print(f"\nTransaction ID:\n{txid}")

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

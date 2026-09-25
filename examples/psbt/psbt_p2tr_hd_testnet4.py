#!/usr/bin/env python3
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


"""PSBT P2TR (Taproot) — Deterministic HD Wallet Example.

Demonstrates creating a Taproot key-path spending PSBT using standard
BIP-32 / BIP-86 HD wallet derivations from a known seed phrase.

Standard test mnemonic:
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
"""

from bitcoinutils.setup import setup
from bitcoinutils.hdwallet import HDWallet
from bitcoinutils.keys import P2trAddress
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.psbt import PSBT
from bitcoinutils.utils import to_satoshis

def main():
    setup("testnet")

    # 1. Initialize HD Wallet from standard test seed
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    hdw = HDWallet(mnemonic=mnemonic, path="m/86'/1'/0'/0/0")
    
    priv = hdw.get_private_key()
    pub = priv.get_public_key()
    
    address = pub.get_taproot_address()
    print(f"Deterministic Taproot Address: {address.to_string()}")

    # 2. Create the raw transaction
    # (Using dummy UTXO data)
    txin = TxInput("1111111111111111111111111111111111111111111111111111111111111111", 0)
    txout = TxOutput(to_satoshis(0.0005), address.to_script_pub_key())
    tx = Transaction([txin], [txout], has_segwit=True)

    # 3. Create PSBT
    psbt = PSBT(tx)

    # 4. Populate Taproot fields
    psbt.inputs[0].witness_utxo = TxOutput(to_satoshis(0.001), address.to_script_pub_key())
    from bitcoinutils.utils import h_to_b
    # BIP-86 dummy internal key
    psbt.inputs[0].tap_internal_key = h_to_b(pub.to_x_only_hex())

    print("\n--- Unsigned PSBT ---")
    print(psbt.to_base64())

    # 5. Sign the PSBT
    print("\nSigning PSBT with HD derived key...")
    psbt.sign_input(0, priv)
    
    print("\n--- Signed PSBT ---")
    print(psbt.to_base64())

    # 6. Finalize and extract
    psbt.finalize_input(0)
    final_tx = psbt.extract_transaction()

    print("\n--- Final Extracted Transaction ---")
    print(final_tx.serialize())

if __name__ == "__main__":
    main()

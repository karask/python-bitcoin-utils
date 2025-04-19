#!/usr/bin/env python3
"""
Example creating a basic PSBT (initial implementation)
"""
# Add parent directory to import path for running directly
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import P2pkhAddress
from bitcoinutils.script import Script
from bitcoinutils.psbt import PSBT

def main():
    # Setup the network
    setup('testnet')

    # Create a transaction input
    prev_tx_id = "6ecd66d88b1a976cde70ebbef1909edec5db80cdd7bc3d6b6d451b91715bb919"
    prev_output_index = 0
    tx_in = TxInput(prev_tx_id, prev_output_index)

    # Create a transaction output (20000 satoshis to a dummy address)
    dummy_addr = P2pkhAddress('n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR')
    tx_out = TxOutput(20000, dummy_addr.to_script_pub_key())

    # Create an unsigned transaction
    tx = Transaction([tx_in], [tx_out])

    # Create a PSBT from the unsigned transaction
    psbt = PSBT(tx)

    # Print information about the PSBT
    print("\nPSBT Information:")
    print(f"Number of inputs: {len(psbt.inputs)}")
    print(f"Number of outputs: {len(psbt.outputs)}")
    print(f"PSBT version: {psbt.version}")

    print("\nPSBT Input Information:")
    for i, psbt_in in enumerate(psbt.inputs):
        print(f"Input #{i}:")
        print(f"  Transaction ID: {psbt_in.tx_input.txid}")
        # Use the stored previous output index from when we created the input
        print(f"  Output Index: {prev_output_index}")
        print(f"  Has UTXO data: {psbt_in.utxo is not None}")
        print(f"  Has partial signatures: {len(psbt_in.partial_sigs) > 0}")

    print("\nPSBT Output Information:")
    for i, psbt_out in enumerate(psbt.outputs):
        print(f"Output #{i}:")
        print(f"  Amount: {psbt_out.tx_output.amount}")
        print(f"  Script type: {psbt_out.tx_output.script_pubkey}")

    print("\nNote: Serialization and additional functionality coming in future updates")

if __name__ == "__main__":
    main()
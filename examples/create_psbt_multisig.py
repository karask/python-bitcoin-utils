#!/usr/bin/env python3
"""
Example of creating a PSBT for spending from a P2WSH multisig address.

This example demonstrates how to:
1. Create a 2-of-3 multisig witness script
2. Build a transaction spending from a P2WSH multisig
3. Create a PSBT with witness script information

The PSBT can then be distributed to signers for partial signing.

Run this first to create the initial PSBT, then use sign_psbt.py
to add signatures from each participant.

Example usage:
    python create_psbt_multisig.py

Note: Uses testnet. Replace the UTXO with a real funded transaction.
"""

from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import PrivateKey, P2wshAddress
from bitcoinutils.script import Script
from bitcoinutils.psbt import PSBT

def main():
    """Create a PSBT for a 2-of-3 multisig P2WSH transaction."""
    
    # Always set the network first
    setup('testnet')
    
    print("=" * 60)
    print("Create P2WSH Multisig PSBT Example")
    print("=" * 60)
    
    # Example testnet UTXO - replace with your funded transaction
    # You can get testnet coins from a faucet and create a P2WSH multisig
    # transaction to fund this address
    utxo = {
        "txid": "6316f4f8dbf842f6982ed09c48df50cef58ee3dbf752eeb73187f2373ef23536",
        "vout": 1,
        "amount": 500000  # 0.005 BTC in satoshis
    }
    
    # Three private keys for the multisig participants
    # In practice, each participant would only have their own key
    alice_key = PrivateKey.from_wif('cTcFkAJtFvyPKjQhPkijgyv4ZRQTau6wQgd1M87Y221zm1sMTRFT')
    bob_key = PrivateKey.from_wif('cUygdGhxnZfjyQZc5ugQY6su6qFgRndqh6JyQK4RN7ry6UUs1Rcj')
    charlie_key = PrivateKey.from_wif('cTbY2V12VRvgLxvBJmd3iq3kN8bZHWGzYYHhG9T6bsisgHjjHCgu')
    
    # Get public keys and sort them (BIP67 - lexicographic ordering)
    pubkeys = sorted(
        [alice_key.get_public_key(), bob_key.get_public_key(), charlie_key.get_public_key()],
        key=lambda p: p.to_hex()
    )
    
    # Create the 2-of-3 witness script
    witness_script = Script([
        'OP_2',
        pubkeys[0].to_hex(),
        pubkeys[1].to_hex(),
        pubkeys[2].to_hex(),
        'OP_3',
        'OP_CHECKMULTISIG'
    ])
    
    # Create the P2WSH address from the witness script
    p2wsh_address = P2wshAddress.from_script(witness_script)
    print(f"\n1. Multisig P2WSH Address: {p2wsh_address.to_string()}")
    print(f"   Witness Script: {witness_script.to_hex()}")
    
    # Create a simple transaction spending the UTXO
    # Send to Alice's individual segwit address (minus fee)
    recipient = alice_key.get_public_key().get_segwit_address()
    fee = 500  # 500 satoshis fee
    
    # Build the transaction
    tx_input = TxInput(utxo['txid'], utxo['vout'])
    tx_output = TxOutput(utxo['amount'] - fee, recipient.to_script_pub_key())
    tx = Transaction([tx_input], [tx_output], has_segwit=True)
    
    print(f"\n2. Created Transaction:")
    print(f"   TXID: {tx.get_txid()}")
    print(f"   Spending: {utxo['amount']} satoshis")
    print(f"   Sending: {utxo['amount'] - fee} satoshis to {recipient.to_string()}")
    
    # Create the PSBT
    psbt = PSBT(tx)
    
    # Add witness script information for the input
    # This tells signers how to sign this P2WSH input
    psbt.inputs[0].witness_script = witness_script
    
    # Add witness UTXO information
    # This provides the amount and script needed for signing
    psbt.inputs[0].witness_utxo = TxOutput(
        utxo['amount'],
        p2wsh_address.to_script_pub_key()
    )
    
    # Serialize to base64 for distribution
    psbt_b64 = psbt.to_base64()
    
    print(f"\n3. PSBT Created Successfully!")
    print(f"   Base64 PSBT:\n   {psbt_b64}")
    
    print(f"\n4. Next Steps:")
    print(f"   - Distribute this PSBT to the multisig participants")
    print(f"   - Each participant signs using: python sign_psbt.py <psbt> <private_key_wif> 0")
    print(f"   - After 2 signatures, combine using: python combine_psbt.py <psbt1> <psbt2>")
    print(f"   - Finalize using: python finalize_psbt.py <combined_psbt>")
    print(f"   - Broadcast the final transaction to the network")
    
    print(f"\n5. Example signing commands:")
    print(f"   # Alice signs:")
    print(f"   python sign_psbt.py {psbt_b64[:50]}... cTcFkAJtFvyPKjQhPkijgyv4ZRQTau6wQgd1M87Y221zm1sMTRFT 0")
    print(f"   # Bob signs:")  
    print(f"   python sign_psbt.py {psbt_b64[:50]}... cUygdGhxnZfjyQZc5ugQY6su6qFgRndqh6JyQK4RN7ry6UUs1Rcj 0")

if __name__ == "__main__":
    main()
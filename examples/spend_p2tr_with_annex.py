#!/usr/bin/env python3

# Example showing how to use Taproot annex with key path spending
# This example demonstrates creating and signing a Taproot transaction with annex data

from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.keys import PrivateKey, PublicKey
from bitcoinutils.script import Script
from bitcoinutils.constants import SIGHASH_ALL

def main():
    # Setup the network to use
    setup('testnet')

    # Create private key and get the corresponding public key
    # Using a valid testnet private key
    priv_key = PrivateKey('cVdte9ei2xsVjmZSPtyucG43YZgNkmKTqhwiUA8M4Fc3LdPJxPmZ')
    pub_key = priv_key.get_public_key()
    
    # Get the x-only public key needed for Taproot
    x_only_pub_key = pub_key.to_x_only_hex()
    
    # Create a P2TR script (key path spending)
    p2tr_script = Script(['OP_1', x_only_pub_key])
    
    # Create a transaction input from a previous transaction
    # Replace with your own transaction ID and output index
    prev_tx_id = '6ecd66d88b1a976cde70ebbef69e903c5bc8c46f0d3e0fb546b216dbba720e0e'
    prev_output_index = 0
    txin = TxInput(prev_tx_id, prev_output_index)
    
    # Define the output: send to another P2TR address 
    # For example purposes, we're sending back to the same taproot address
    output_amount = 90000  # Amount minus fees (in satoshis)
    txout = TxOutput(output_amount, p2tr_script)
    
    # Create the transaction
    tx = Transaction([txin], [txout], has_segwit=True)
    
    # Create annex data (must start with 0x50)
    # This can contain any arbitrary data needed for your application
    annex = bytes([0x50, 0x01, 0x02, 0x03, 0x04])
    
    # Amount of the input being spent (in satoshis)
    input_amount = 100000
    
    # Get the transaction digest for signing, including the annex
    # (key path spending, so script_path=False)
    tx_digest = tx.get_transaction_taproot_digest(
        0,  # input index
        False,  # script_path (False for key path spending)
        p2tr_script.to_bytes(),  # scriptPubkey of the input (now works with a single script)
        input_amount,  # amount of the input (now works with a single amount)
        0,  # ext_flag
        None,  # script
        0xc0,  # leaf_ver
        SIGHASH_ALL,  # sighash type
        annex  # include annex data
    )
    
    # Sign the transaction digest
    signature = priv_key.sign_schnorr(tx_digest)
    
    # Set the witness for the transaction input (signature and annex for key path)
    # For key path spending with annex, the witness stack is [signature, annex]
    tx.witnesses = [TxWitnessInput([signature, annex.hex()])]
    
    # Serialize the transaction
    signed_tx = tx.serialize()
    
    print("\nRaw signed transaction with annex data:")
    print(signed_tx)
    print("\nTransaction ID:", tx.get_txid())
    
    print("\nWitness data:")
    for i, witness in enumerate(tx.witnesses):
        print(f"Input {i} witness: {witness}")
    
    print("\nExplanation of annex usage:")
    print("1. We created an annex starting with 0x50 byte (required prefix for annex)")
    print("2. We included the annex in signature hash calculation")
    print("3. We added both the signature and annex to the witness stack")
    print("4. When this transaction is broadcast, nodes that support BIP 341 will")
    print("   validate it correctly, recognizing the annex data in the witness")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3

# Example: Creating a PSBT from a transaction

from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import PrivateKey, P2pkhAddress
from bitcoinutils.psbt import PSBT

def main():
    # Setup the network
    setup('testnet')
    
    # Create keys and address
    private_key = PrivateKey('cVwfreZB3r8vUkSnaoeZJ4Ux9W8YMqYM5XRV4zJo6ThcYs1MYiXj')
    public_key = private_key.get_public_key()
    address = P2pkhAddress.from_public_key(public_key)
    
    print(f"Address: {address.to_string()}")
    
    # Create an unsigned transaction
    # Replace with your own transaction details
    txid = '339e9f3ff9aeb6bb75cfed89b397994663c9aa3458dd5ed6e710626a36ee9dfc'
    vout = 0
    amount = 1000000  # 0.01 BTC in satoshis
    
    # Create transaction input
    txin = TxInput(txid, vout)
    
    # Create transaction output (sending to same address for this example)
    txout = TxOutput(amount, address.to_script_pub_key())
    
    # Create the transaction
    tx = Transaction([txin], [txout])
    
    print("\nUnsigned Transaction:")
    print(f"Txid: {tx.get_txid()}")
    print(f"Hex: {tx.serialize()}")
    
    # Create a PSBT from the transaction
    psbt = tx.to_psbt()
    
    print("\nEmpty PSBT (Base64):")
    print(psbt.to_base64())
    
    # Add UTXO information
    # In a real scenario, you would get this from your wallet or a blockchain explorer
    # For this example, we create a dummy previous transaction
    prev_tx_hex = '0200000001f3dc9c924e7813c81cfb218fdad0603a76fdd37a4ad9622d475d11741940bfbc000000006a47304402201fad9a9735a3182e76e6ae47ebfd23784bd142384a73146c7f7f277dbd399b22022032f2a086d4ebac27398f6896298a2d3ce7e6b50afd934302c873133442b1c8c8012102653c8de9f4854ca4da358d8403b6e0ce61c621d37f9c1bf2384d9e3d6b9a59b5feffffff01102700000000000017a914a36f0f7839deeac8755c1c1ad9b3d877e99ed77a8700000000'
    prev_tx = Transaction.from_raw(prev_tx_hex)
    
    # Add the previous transaction to the PSBT
    psbt.add_input_utxo(0, utxo_tx=prev_tx)
    
    print("\nPSBT with UTXO information (Base64):")
    print(psbt.to_base64())
    
    # Save the PSBT for later use (in a real application)
    psbt_base64 = psbt.to_base64()
    
    print("\nThis PSBT can now be shared with signers (e.g., hardware wallets)")

if __name__ == "__main__":
    main()
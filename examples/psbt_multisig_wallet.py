#!/usr/bin/env python3

# Example: Using PSBTs for multisignature wallet operations

from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import PrivateKey, P2shAddress, P2pkhAddress
from bitcoinutils.script import Script
from bitcoinutils.psbt import PSBT
from bitcoinutils.utils import to_satoshis

def main():
    # Setup the network
    setup('testnet')
    
    # Create keys for a 2-of-3 multisignature wallet
    private_key1 = PrivateKey('cVwfreZB3r8vUkSnaoeZJ4Ux9W8YMqYM5XRV4zJo6ThcYs1MYiXj')
    private_key2 = PrivateKey('cRfdEQqXxqRRKzZLgVroL5qwXGHjzuC65LdJ6xhYzQHiFB2FjmC1')
    private_key3 = PrivateKey('cNL727W9uKMGM5UWj3cYA3HbButUH2h17y4iqtLPXChNr6eFXNBw')
    
    public_key1 = private_key1.get_public_key()
    public_key2 = private_key2.get_public_key()
    public_key3 = private_key3.get_public_key()
    
    # Create a 2-of-3 multisignature redeem script
    redeem_script = Script([
        'OP_2',
        public_key1.to_hex(),
        public_key2.to_hex(),
        public_key3.to_hex(),
        'OP_3',
        'OP_CHECKMULTISIG'
    ])
    
    # Create P2SH address from the redeem script
    multisig_address = P2shAddress.from_script(redeem_script)
    
    print(f"2-of-3 Multisignature Address: {multisig_address.to_string()}")
    
    # Step 1: Create a transaction spending from the multisig address
    # Replace with your own transaction details
    txid = '339e9f3ff9aeb6bb75cfed89b397994663c9aa3458dd5ed6e710626a36ee9dfc'
    vout = 0
    
    # Create transaction input
    txin = TxInput(txid, vout)
    
    # Create transaction output (sending to a P2PKH address)
    dest_address = P2pkhAddress.from_string('myP2PKHaddress')  # Replace with your address
    txout = TxOutput(to_satoshis(0.009), dest_address.to_script_pub_key())  # 0.009 BTC
    
    # Create the transaction
    tx = Transaction([txin], [txout])
    
    print("\nUnsigned Transaction:")
    print(f"Txid: {tx.get_txid()}")
    
    # Step 2: Create a PSBT from the transaction
    psbt = tx.to_psbt()
    
    # Step 3: Add redeem script and UTXO information
    # In a real scenario, you would get UTXO info from your wallet or a blockchain explorer
    prev_tx_hex = '0200000001f3dc9c924e7813c81cfb218fdad0603a76fdd37a4ad9622d475d11741940bfbc000000006a47304402201fad9a9735a3182e76e6ae47ebfd23784bd142384a73146c7f7f277dbd399b22022032f2a086d4ebac27398f6896298a2d3ce7e6b50afd934302c873133442b1c8c8012102653c8de9f4854ca4da358d8403b6e0ce61c621d37f9c1bf2384d9e3d6b9a59b5feffffff01102700000000000017a914a36f0f7839deeac8755c1c1ad9b3d877e99ed77a8700000000'
    prev_tx = Transaction.from_raw(prev_tx_hex)
    
    psbt.add_input_utxo(0, utxo_tx=prev_tx)
    psbt.add_input_redeem_script(0, redeem_script)
    
    # Serialize PSBT for sharing with signers
    initial_psbt_base64 = psbt.to_base64()
    
    print("\nInitial PSBT (Base64):")
    print(initial_psbt_base64)
    
    # Step 4: Signer 1 signs the PSBT
    print("\nSigner 1 signing...")
    psbt_signer1 = PSBT.from_base64(initial_psbt_base64)
    psbt_signer1.sign_input(private_key1, 0)
    psbt_signer1_base64 = psbt_signer1.to_base64()
    
    # Step 5: Signer 2 signs the PSBT
    print("Signer 2 signing...")
    psbt_signer2 = PSBT.from_base64(initial_psbt_base64)
    psbt_signer2.sign_input(private_key2, 0)
    psbt_signer2_base64 = psbt_signer2.to_base64()
    
    # Step 6: Combine the signed PSBTs
    print("Combining PSBTs...")
    combined_psbt = PSBT.combine([psbt_signer1, psbt_signer2])
    
    # Step 7: Finalize the PSBT
    print("Finalizing PSBT...")
    if combined_psbt.finalize():
        print("PSBT successfully finalized")
    else:
        print("Failed to finalize PSBT")
        return
    
    # Step 8: Extract the final transaction
    final_tx = combined_psbt.extract_transaction()
    tx_hex = final_tx.serialize()
    
    print("\nFinal Transaction Hex:")
    print(tx_hex)
    
    print(f"\nTransaction ID: {final_tx.get_txid()}")
    
    print("\nThis transaction can now be broadcast to the Bitcoin network")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Create a PSBT for spending from a P2WSH (Pay-to-Witness-Script-Hash) multisig address.
This creates a 2-of-3 multisig setup using witness version 0.
"""
from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import PrivateKey, PublicKey, P2wshAddress
from bitcoinutils.script import Script
from bitcoinutils.utils import to_satoshis
from bitcoinutils.psbt import PSBT

def get_p2wsh_utxo():
    """Funded P2WSH UTXO"""
    return {
        "txid": "98520ec27732c27ba15cdeed00f73f313864b61d765b6e7687adbaaf8bb823c4",
        "vout": 0,  
        "address": "tb1qqxxqgs5nlpgw86ws4uhfcarj9808g4e439pwgsh8tax2rnqgvutsqdur3g",
        "amount": 500000
    }


def main():
    setup('testnet')
    
    # Your private keys for the multisig
    wif1 = 'cVVJMEAzugqginoFL5Qu8WkWmD3KLarXoKJZMe8XTbbkL9N5e1bG'
    wif2 = 'cSCuWoLorXsQ2fzWrPJnXEicFPJh4SrDwpzEpJKvz5aWPamnU9Ep'
    wif3 = 'cSMW2qpL6vE32KrGiTJj3Ez8fVLgJseNfQmyiZqG8achRX1j8AAb'
    
    priv1 = PrivateKey.from_wif(wif1)
    priv2 = PrivateKey.from_wif(wif2)
    priv3 = PrivateKey.from_wif(wif3)
    
    pub1 = priv1.get_public_key()
    pub2 = priv2.get_public_key()
    pub3 = priv3.get_public_key()
    
    # Sort public keys for consistent script generation
    pubkeys = sorted([pub1, pub2, pub3], key=lambda k: k.to_hex())
    
    print("\n Public keys (sorted):")
    for i, pk in enumerate(pubkeys, 1):
        print(f"   PubKey {i}: {pk.to_hex()}")
    
    # Create 2-of-3 multisig witness script
    # IMPORTANT: Use hex strings for pubkeys, not raw bytes
    # The Script class will handle the proper encoding
    witness_script = Script([
        'OP_2',  # Use opcode name
        pubkeys[0].to_hex(),  # pubkey as hex string
        pubkeys[1].to_hex(),
        pubkeys[2].to_hex(),
        'OP_3',  # Use opcode name
        'OP_CHECKMULTISIG'  # Use opcode name
    ])
    
    print(f"\n Witness script hex: {witness_script.to_hex()}")
    
    # Generate P2WSH address from witness script
    p2wsh_address = P2wshAddress.from_script(witness_script)
    print(f" Multisig P2WSH Address: {p2wsh_address.to_string()}")
    
    # Verify the script hash
    import hashlib
    script_hash = hashlib.sha256(witness_script.to_bytes()).digest()
    print(f" Script hash (SHA256): {script_hash.hex()}")
    
    # Create funding transaction to send funds to this address first
    print("\n To fund this address, send testnet coins to:", p2wsh_address.to_string())
    print("   You can use: https://bitcoinfaucet.uo1.net/ or https://testnet-faucet.com/btc-testnet/")
    
    # If you already have a funded UTXO, update get_p2wsh_utxo() with the details
    utxo = get_p2wsh_utxo()
    
    # Verify the UTXO address matches our generated address
    if utxo['address'] != p2wsh_address.to_string():
        print(f"\n  WARNING: UTXO address mismatch!")
        print(f"   Expected: {p2wsh_address.to_string()}")
        print(f"   Got: {utxo['address']}")
        print("   The witness script used to create the UTXO must match exactly!")
        
    if utxo['txid'] == "replace_with_your_funded_txid":
        print("\n  Please fund the P2WSH address first and update the UTXO details in get_p2wsh_utxo()")
        print("   Then run this script again to create the spending PSBT")
        return
    
    # Create transaction input
    txin = TxInput(utxo['txid'], utxo['vout'])
    
    # Calculate fee (P2WSH is more efficient than P2SH)
    fee = 500  # Lower fee due to witness discount
    sending_amount = utxo['amount'] - fee
    
    if sending_amount <= 0:
        raise ValueError("UTXO amount too small to cover fee!")
    
    # Send to a simple P2WPKH address for testing
    recipient_address = priv1.get_public_key().get_segwit_address()
    txout = TxOutput(sending_amount, recipient_address.to_script_pub_key())
    
    # Create transaction with witness flag
    tx = Transaction([txin], [txout], has_segwit=True)
    psbt = PSBT(tx)
    
    # For P2WSH, we need:
    # 1. witness_script (the actual script)
    # 2. witness_utxo (the output being spent)
    
    # Set the witness script
    psbt.inputs[0].witness_script = witness_script
    
    # Create the witness UTXO (the output we're spending)
    witness_utxo = TxOutput(utxo['amount'], p2wsh_address.to_script_pub_key())
    print(f"Debug - Witness UTXO amount: {witness_utxo.amount}")
    print(f"Debug - Witness UTXO script: {witness_utxo.script_pubkey.to_hex()}")    
    psbt.inputs[0].witness_utxo = witness_utxo
    
    print("\n PSBT for P2WSH Spend Created Successfully")
    
    try:
        base64_psbt = psbt.to_base64()
        print("\nBase64 PSBT:\n", base64_psbt)
        
        # Save to file for convenience
        with open('p2wsh_unsigned.psbt', 'w') as f:
            f.write(base64_psbt)
        print("\n PSBT saved to: p2wsh_unsigned.psbt")
        
        print("\n Transaction Summary:")
        print(f"   Input: {utxo['txid']}:{utxo['vout']} ({utxo['amount']} sats)")
        print(f"   Output: {recipient_address.to_string()} ({sending_amount} sats)")
        print(f"   Fee: {fee} satoshis")
        print(f"   Witness Script Type: 2-of-3 multisig")
        
        print("\n Next steps:")
        print("   1. Sign with at least 2 keys: python examples/sign_psbt.py p2wsh_unsigned.psbt <wif1> 0")
        print("   2. Sign with the 2nd key: python examples/sign_psbt.py p2wsh_signed_1.psbt <wif2> 0")
        print("   3. Finalize: python examples/finalize_psbt.py p2wsh_signed_2.psbt")
        
    except Exception as e:
        print(f" Error creating PSBT: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
# Copyright (C) 2025 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

"""
Example of creating a 2-of-3 multisig PSBT that can be signed by multiple parties using REAL TESTNET UTXOs.

This example demonstrates:
1. Creating a 2-of-3 multisig P2WSH address (Segwit multisig)
2. Creating a PSBT for spending from that address using real testnet UTXOs
3. Setting up the PSBT with proper input information for signing

IMPORTANT: This uses REAL TESTNET transactions that can be verified on:
https://blockstream.info/testnet/

Before running this example:
1. Get testnet coins from a faucet (e.g., https://coinfaucet.eu/en/btc-testnet/)
2. Create the multisig address shown below
3. Send testnet coins to that address
4. Update the UTXO details below with your real transaction
"""

from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, Locktime
from bitcoinutils.keys import PrivateKey, PublicKey
from bitcoinutils.script import Script
from bitcoinutils.utils import to_satoshis
from bitcoinutils.psbt import PSBT
from bitcoinutils.constants import TYPE_RELATIVE_TIMELOCK


def get_real_testnet_utxo():
    """
    STEP-BY-STEP GUIDE TO GET REAL TESTNET UTXO:
    
    1. Visit https://blockstream.info/testnet/tx/recent
    2. Find any recent transaction with outputs
    3. Click on a transaction, copy its TXID
    4. Replace the values below with real data
    5. Verify the TXID works: https://blockstream.info/testnet/tx/YOUR_TXID
    
    EXAMPLE OF HOW TO FIND REAL DATA:
    - Go to https://blockstream.info/testnet/
    - Click "Recent Transactions"
    - Pick any transaction (e.g. click on a TXID)
    - Copy the TXID from the URL
    - Check the outputs for amount and vout index
    """
    
    # METHOD 1: Use a funding transaction you create yourself
    # (Recommended - you control the UTXO)
    create_own_funding = True
    
    if create_own_funding:
        # TODO: After running this script once:
        # 1. Note the multisig address printed below
        # 2. Get testnet coins from faucet
        # 3. Send coins to the multisig address
        # 4. Update these values with YOUR funding transaction
        utxo_details = {
            'txid': 'YOUR_FUNDING_TXID_HERE',  # ← Replace with your funding TXID
            'vout': 0,  # ← Usually 0, but check the transaction
            'amount': to_satoshis(0.001),  # ← Replace with actual amount sent
            'address': None,  # Will be set to multisig address
            'is_placeholder': True  # Set to False when using real data
        }
    else:
        # METHOD 2: Use any existing testnet UTXO (not recommended for production)
        # This is just for demonstration - don't spend other people's UTXOs!
        utxo_details = {
            'txid': 'SOME_EXISTING_TESTNET_TXID',
            'vout': 0,
            'amount': to_satoshis(0.001),
            'address': None,
            'is_placeholder': True
        }
    
    # Validation
    if utxo_details['is_placeholder']:
        print(" PLACEHOLDER DATA DETECTED!")
        print("   This PSBT uses placeholder data and won't work on testnet.")
        print("   Follow these steps to use real testnet data:")
        print()
        print("   STEP 1: Get testnet coins")
        print("   • Visit: https://coinfaucet.eu/en/btc-testnet/")
        print("   • Request coins to any address you control")
        print()
        print("   STEP 2: Fund the multisig (run this script first to get address)")
        print("   • Send testnet coins to the multisig address")
        print("   • Wait for confirmation")
        print()
        print("   STEP 3: Update this function")
        print("   • Copy the funding transaction TXID")
        print("   • Set utxo_details['txid'] = 'your_real_txid'")
        print("   • Set utxo_details['amount'] = to_satoshis(your_real_amount)")
        print("   • Set utxo_details['is_placeholder'] = False")
        print()
        print("   STEP 4: Verify")
        print("   • Check: https://blockstream.info/testnet/tx/your_real_txid")
        print("   • Confirm the UTXO exists and amount is correct")
        print()
    
    return utxo_details


def main():
    # Always call setup() first - using testnet for real transactions
    setup('testnet')
    
    print("=" * 70)
    print("Creating 2-of-3 Multisig PSBT with REAL TESTNET UTXOs")
    print("=" * 70)
    
    # Step 1: Create three private keys (representing Alice, Bob, and Charlie)
    print("\n1. Creating private keys for Alice, Bob, and Charlie...")
    
    # Using deterministic keys for consistency (in production, generate securely)
    alice_private_key = PrivateKey.from_wif("cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo")
    alice_public_key = alice_private_key.get_public_key()
    print(f"Alice's public key: {alice_public_key.to_hex()}")
    
    # Bob's key  
    bob_private_key = PrivateKey.from_wif("cVf3kGh6552jU2rLaKwXTKq5APHPoZqCP4GQzQirWGHFoHQ9rEVt")
    bob_public_key = bob_private_key.get_public_key()
    print(f"Bob's public key: {bob_public_key.to_hex()}")
    
    # Charlie's key
    charlie_private_key = PrivateKey.from_wif("cQDvVP5VhYsV3dtHQwQ5dCbL54WuJcvsUgr3LXwhf6vD5mPp9nVy")
    charlie_public_key = charlie_private_key.get_public_key()
    print(f"Charlie's public key: {charlie_public_key.to_hex()}")
    
    # Step 2: Create 2-of-3 multisig P2WSH script (Segwit version)
    print("\n2. Creating 2-of-3 multisig P2WSH script...")
    
    # Create the multisig witness script (2 of 3) - sorted keys for deterministic addresses
    public_keys = sorted([alice_public_key, bob_public_key, charlie_public_key], 
                        key=lambda k: k.to_hex())
    
    witness_script = Script([
        2,  # Required signatures
        public_keys[0].to_hex(),
        public_keys[1].to_hex(), 
        public_keys[2].to_hex(),
        3,  # Total public keys
        'OP_CHECKMULTISIG'
    ])
    
    print(f"Witness script: {witness_script.to_hex()}")
    
    # Create P2WSH address from the witness script
    p2wsh_address = witness_script.to_p2wsh_script_pub_key().to_address()
    print(f"P2WSH Multisig Address: {p2wsh_address}")
    print(f" Check this address on: https://blockstream.info/testnet/address/{p2wsh_address}")
    
    # Step 3: Get real testnet UTXO details
    print("\n3. Getting real testnet UTXO details...")
    utxo = get_real_testnet_utxo()
    utxo['address'] = p2wsh_address
    
    print(f"Using UTXO:")
    print(f"  TXID: {utxo['txid']}")
    print(f"  Vout: {utxo['vout']}")
    print(f"  Amount: {utxo['amount']} satoshis ({utxo['amount'] / 100000000:.8f} BTC)")
    print(f"  Address: {utxo['address']}")
    
    if utxo['is_placeholder']:
        print(f" PLACEHOLDER: https://blockstream.info/testnet/tx/{utxo['txid']}")
        print(f"   This TXID won't verify - it's just an example format")
    else:
        print(f" VERIFY: https://blockstream.info/testnet/tx/{utxo['txid']}")
        print(f"   This should show a real testnet transaction")
    
    # Step 4: Create transaction inputs and outputs
    print("\n4. Setting up transaction...")
    
    # Input: Real testnet UTXO
    txin = TxInput(utxo['txid'], utxo['vout'])
    
    # Output: Send to Charlie's P2WPKH address (modern Segwit address)
    charlie_p2wpkh_address = charlie_public_key.get_segwit_address()
    
    # Calculate output amount (leaving some for fees)
    fee_amount = to_satoshis(0.0001)  # 0.0001 BTC fee
    send_amount = utxo['amount'] - fee_amount
    
    if send_amount <= 0:
        raise ValueError("UTXO amount too small to cover fees!")
    
    txout = TxOutput(send_amount, charlie_p2wpkh_address.to_script_pub_key())
    
    # Create the transaction
    tx = Transaction([txin], [txout], Locktime(0))
    print(f"Unsigned transaction: {tx.serialize()}")
    
    # Step 5: Create PSBT
    print("\n5. Creating PSBT...")
    
    # Create PSBT from the unsigned transaction
    psbt = PSBT(tx)
    
    # Add input information needed for signing P2WSH
    # For P2WSH inputs, we need the witness script and witness UTXO info
    psbt.add_input_witness_script(0, witness_script)
    psbt.add_input_witness_utxo(0, utxo['amount'], p2wsh_address.to_script_pub_key())
    
    print(f"PSBT created successfully!")
    print(f"PSBT base64: {psbt.to_base64()}")
    
    # Step 6: Display verification information
    print("\n6. TESTNET VERIFICATION")
    print("=" * 50)
    
    if utxo['is_placeholder']:
        print(" USING PLACEHOLDER DATA - NOT VERIFIABLE")
        print("   Current TXID is fake and won't verify on explorer")
        print("   To fix this:")
        print("   1. Get real testnet coins from faucet")
        print("   2. Send to the multisig address above")
        print("   3. Update get_real_testnet_utxo() with real data")
        print()
        print(" When ready, verify with:")
        print(f"   https://blockstream.info/testnet/tx/YOUR_REAL_TXID")
    else:
        print(" REAL TESTNET DATA - VERIFIABLE")
        print(" Verify input transaction:")
        print(f"   https://blockstream.info/testnet/tx/{utxo['txid']}")
        
    print(f" Check multisig address balance:")
    print(f"   https://blockstream.info/testnet/address/{p2wsh_address}")
    print(f" After signing and broadcasting, check output:")
    print(f"   https://blockstream.info/testnet/address/{charlie_p2wpkh_address}")
    
    # Step 7: Display signing workflow
    print("\n7. SIGNING WORKFLOW")
    print("=" * 50)
    print("This PSBT is ready for the 2-of-3 multisig signing process:")
    print()
    print("1.  Alice signs:")
    print("   - Import PSBT")
    print("   - Sign with Alice's private key")
    print("   - Export partial signature")
    print()
    print("2.  Bob signs:")
    print("   - Import PSBT (with Alice's signature)")
    print("   - Sign with Bob's private key") 
    print("   - Export complete signature")
    print()
    print("3.  Finalize and broadcast:")
    print("   - Combine signatures (2 of 3 threshold met)")
    print("   - Finalize PSBT to create broadcastable transaction")
    print("   - Broadcast to testnet")
    print("   - Monitor on blockstream.info/testnet")
    
    # Step 8: Show the structure for educational purposes
    print("\n8. PSBT STRUCTURE ANALYSIS")
    print("=" * 50)
    print(f"Global data:")
    print(f"  - Unsigned transaction: {tx.serialize()}")
    print(f"  - Version: {psbt.version}")
    print(f"  - Transaction type: P2WSH (Segwit multisig)")
    
    print(f"\nInput 0 data:")
    print(f"  - Previous TXID: {utxo['txid']}")
    print(f"  - Previous Vout: {utxo['vout']}")
    print(f"  - Witness Script: {witness_script.to_hex()}")
    print(f"  - Amount: {utxo['amount']} satoshis")
    print(f"  - Script type: P2WSH")
    print(f"  - Required signatures: 2 of 3")
    
    print(f"\nOutput 0 data:")
    print(f"  - Amount: {send_amount} satoshis")
    print(f"  - Fee: {fee_amount} satoshis")
    print(f"  - Recipient: {charlie_p2wpkh_address}")
    print(f"  - Script type: P2WPKH")
    
    # Step 9: How to get real testnet coins
    print("\n9. HOW TO GET REAL TESTNET COINS & TXID")
    print("=" * 50)
    print("COMPLETE WORKFLOW FOR REAL TESTNET DATA:")
    print()
    print("PHASE 1: Setup")
    print("1.  Run this script AS-IS to get your multisig address")
    print("2.  Copy the P2WSH address from the output above")
    print()
    print("PHASE 2: Get testnet coins")
    print("3.  Visit testnet faucet:")
    print("   • https://coinfaucet.eu/en/btc-testnet/")
    print("   • https://testnet.help/en/btcfaucet/testnet")
    print("   • Request 0.001+ BTC to any address you control")
    print()
    print("PHASE 3: Fund multisig")
    print("4.  Send testnet coins to your multisig address:")
    print(f"   • Send to: {p2wsh_address}")
    print("   • Amount: 0.001 BTC (or whatever you got from faucet)")
    print("   • Wait for 1+ confirmations")
    print()
    print("PHASE 4: Get real TXID")
    print("5.  Find your funding transaction:")
    print("   • Go to: https://blockstream.info/testnet/")
    print("   • Search for your multisig address")
    print("   • Click on the funding transaction")
    print("   • Copy the TXID from the URL")
    print()
    print("PHASE 5: Update code")
    print("6.   Edit get_real_testnet_utxo() function:")
    print("   • Set txid = 'your_real_txid_here'")
    print("   • Set amount = to_satoshis(your_actual_amount)")
    print("   • Set is_placeholder = False")
    print()
    print("PHASE 6: Verify & test")
    print("7.  Re-run this script")
    print("   • Should show  REAL TESTNET DATA")
    print("   • TXID link should work in browser")
    print("   • PSBT should be ready for signing")
    print()
    print("EXAMPLE of real testnet TXID format:")
    print("b4c1a58d7f8e9a2b3c4d5e6f1234567890abcdef1234567890abcdef12345678")
    print("(64 hex characters - yours will look similar)")
    print()
    print(" Your mentor can then verify:")
    print("• Paste your TXID into testnet explorer")
    print("• See real transaction with real UTXOs") 
    print("• Confirm PSBT references actual blockchain data")
    
    return psbt, {
        'multisig_address': p2wsh_address,
        'witness_script': witness_script.to_hex(),
        'recipient_address': charlie_p2wpkh_address,
        'utxo': utxo
    }


if __name__ == "__main__":
    created_psbt, info = main()
    
    print(f"\n" + "=" * 70)
    print(" PSBT CREATION COMPLETED!")
    print("=" * 70)
    print(f" PSBT (base64): {created_psbt.to_base64()}")
    print()
    print(" NEXT STEPS:")
    print("1. Fund the multisig address with real testnet coins")
    print("2. Update the UTXO details in get_real_testnet_utxo()")
    print("3. Re-run this script")
    print("4. Sign the PSBT with 2 of the 3 private keys")
    print("5. Broadcast to testnet and verify on blockstream.info")
    print()
    print(f" Multisig address: {info['multisig_address']}")
    print(f" Check balance: https://blockstream.info/testnet/address/{info['multisig_address']}")


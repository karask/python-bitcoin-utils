#!/usr/bin/env python3
"""
Example of signing a PSBT with a private key.

This example demonstrates how to:
1. Load a PSBT from base64
2. Sign a specific input with a private key
3. Output the signed PSBT

The PSBT signing logic automatically detects the script type
(P2PKH, P2WPKH, P2SH, P2WSH, etc.) and signs appropriately.

Usage:
    python sign_psbt.py <psbt_base64> <private_key_wif> <input_index>

Example:
    # Alice signs input 0
    python sign_psbt.py cHNidP8B... cTcFkAJtFvyPKjQh... 0
    
    # Bob signs input 0  
    python sign_psbt.py cHNidP8B... cUygdGhxnZfjyQZ... 0

Note: The input_index parameter is required to specify which input to sign.
      In a multisig scenario, multiple parties sign the same input.
"""

import sys
from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey
from bitcoinutils.psbt import PSBT

def main():
    """Sign a PSBT input with a private key."""
    
    # Always set the network first
    setup('testnet')
    
    if len(sys.argv) != 4:
        print("Usage: python sign_psbt.py <psbt_base64> <private_key_wif> <input_index>")
        return
    
    # Load PSBT and private key
    psbt = PSBT.from_base64(sys.argv[1])
    private_key = PrivateKey.from_wif(sys.argv[2])
    input_index = int(sys.argv[3])
    
    # Sign the specified input
    if psbt.sign_input(input_index, private_key):
        print(psbt.to_base64())
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
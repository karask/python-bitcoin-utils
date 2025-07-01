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
Sign a specific input of a PSBT (Partially Signed Bitcoin Transaction) using a WIF private key.

This script allows targeted signing of one input in a PSBT, which is useful for multisig setups,
hardware wallet integrations, or step-by-step signing processes.

Features:
- Loads a PSBT from a base64-encoded string
- Signs a specified input using a provided WIF-formatted private key
- Supports multiple script types: P2PKH, P2SH, P2WPKH, P2WSH, P2TR
- Allows optional SIGHASH type customization (default: SIGHASH_ALL)

Usage:
    python sign_psbt.py <psbt_base64> <private_key_wif> <input_index> [sighash_type]

Arguments:
    psbt_base64       The PSBT in base64 encoding
    private_key_wif   The private key in Wallet Import Format (WIF)
    input_index       Index of the input to sign (0-based)
    sighash_type      (Optional) Bitcoin SIGHASH flag (e.g., SIGHASH_ALL, SIGHASH_SINGLE)

Returns:
    Updated PSBT with the input partially signed and printed as base64
"""


import sys
from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey
from bitcoinutils.psbt import PSBT
from bitcoinutils.constants import SIGHASH_ALL


def main():
    """Main function for signing PSBT example."""
    # Always call setup() first
    setup('testnet')
    
    # Parse command line arguments
    if len(sys.argv) < 4:
        print("Usage: python sign_psbt.py <psbt_base64> <private_key_wif> <input_index> [sighash_type]")
        print("\nExample:")
        print("python sign_psbt.py <psbt> cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo 0")
        sys.exit(1)
    
    psbt_base64 = sys.argv[1]
    private_key_wif = sys.argv[2]
    input_index = int(sys.argv[3])
    sighash_type = int(sys.argv[4]) if len(sys.argv) > 4 else SIGHASH_ALL
    
    try:
        # Load PSBT from base64
        psbt = PSBT.from_base64(psbt_base64)
        
        # Load private key
        private_key = PrivateKey.from_wif(private_key_wif)
        
        # Sign the specified input
        success = psbt.sign_input(input_index, private_key, sighash_type)
        
        if success:
            # Output the updated PSBT
            print(psbt.to_base64())
        else:
            print("Failed to sign input", file=sys.stderr)
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3

"""
Combine multiple PSBTs (Partially Signed Bitcoin Transactions) into a single PSBT with merged signatures and metadata.

This script performs the combiner role defined in BIP-174, allowing multiple signers to contribute signatures separately,
and then merge their PSBTs into one unified transaction.

Features:
- Loads multiple base64-encoded PSBTs
- Merges all inputs, outputs, and partial signatures
- Validates consistency across PSBTs before combining
- Outputs a single combined PSBT in base64 format

Usage:
    python combine_psbt.py <psbt1_base64> <psbt2_base64> [<psbt3_base64> ...]

Returns:
    Combined PSBT with merged data from all inputs
"""

import sys
from bitcoinutils.setup import setup
from bitcoinutils.psbt import PSBT

def main():
    setup('testnet')
    
    if len(sys.argv) < 3:
        print("Usage: python combine_psbt.py <psbt1_base64> <psbt2_base64> [psbt3_base64] ...")
        return
    
    # Load PSBTs from command line arguments
    psbts = [PSBT.from_base64(psbt_base64) for psbt_base64 in sys.argv[1:]]
    
    # Combine all PSBTs using the first one as base
    combined_psbt = psbts[0].combine_psbts(psbts[1:])
    
    # Output the combined PSBT
    print(combined_psbt.to_base64())

if __name__ == "__main__":
    main()

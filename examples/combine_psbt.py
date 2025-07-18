#!/usr/bin/env python3
"""
Example of combining multiple PSBTs into a single PSBT.

This example demonstrates how to:
1. Load multiple PSBTs that contain partial signatures
2. Combine them into a single PSBT with all signatures
3. Output the combined PSBT

This is typically used in multisig scenarios where different
participants sign the same transaction independently and then
combine their signatures.

Usage:
    python combine_psbt.py <psbt1_base64> <psbt2_base64> [<psbt3_base64> ...]

Example:
    # Combine Alice's and Bob's signed PSBTs
    python combine_psbt.py cHNidP8BAH... cHNidP8BAH...

Note: All PSBTs must be for the same transaction. The combine
      operation merges all partial signatures and other data.
"""

import sys
from bitcoinutils.setup import setup
from bitcoinutils.psbt import PSBT

def main():
    """Combine multiple PSBTs into one."""
    
    # Always set the network first
    setup('testnet')
    
    if len(sys.argv) < 3:
        print("Usage: python combine_psbt.py <psbt1_base64> <psbt2_base64> [<psbt3_base64> ...]")
        return
    
    # Load first PSBT
    psbt = PSBT.from_base64(sys.argv[1])
    
    # Load and combine with remaining PSBTs
    other_psbts = [PSBT.from_base64(base64_str) for base64_str in sys.argv[2:]]
    combined = psbt.combine_psbts(other_psbts)
    
    print(combined.to_base64())

if __name__ == "__main__":
    main()
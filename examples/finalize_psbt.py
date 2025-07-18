#!/usr/bin/env python3
"""
Example of finalizing a PSBT into a complete transaction.

This example demonstrates how to:
1. Load a PSBT that has all required signatures
2. Finalize it into a complete transaction
3. Optionally validate the transaction
4. Output the hex transaction ready for broadcast

The finalization process extracts all signatures from the PSBT
and constructs the final scriptSig and/or witness data.

Usage:
    python finalize_psbt.py <psbt_base64> [--validate]

Example:
    # Basic finalization
    python finalize_psbt.py cHNidP8BAH...
    
    # With validation
    python finalize_psbt.py cHNidP8BAH... --validate

Note: The PSBT must have all required signatures before finalization.
      Use --validate to perform additional transaction validation.
"""

import sys
from bitcoinutils.setup import setup
from bitcoinutils.psbt import PSBT

def main():
    """Finalize a PSBT into a complete transaction."""
    
    # Always set the network first
    setup('testnet')
    
    if len(sys.argv) < 2:
        print("Usage: python finalize_psbt.py <psbt_base64> [--validate]")
        return
    
    # Load PSBT
    psbt = PSBT.from_base64(sys.argv[1])
    
    # Check if validation requested
    validate = '--validate' in sys.argv
    
    # Finalize the PSBT
    if validate:
        final_tx, validation_info = psbt.finalize(validate=True)
        if validation_info['valid']:
            print(f"\nFinalized Transaction (hex):")
            print(final_tx.to_hex())
            print(f"\nTransaction ID: {final_tx.get_txid()}")
            print(f"Size: {validation_info['size']} bytes")
            print(f"Virtual Size: {validation_info['vsize']} vbytes")
            
            print(f"\nTo broadcast:")
            print(f"  bitcoin-cli -testnet sendrawtransaction {final_tx.to_hex()[:50]}...")
        else:
            print("Finalization failed - validation errors found")
            sys.exit(1)
    else:
        final_tx = psbt.finalize(validate=False)
        if final_tx:
            print(final_tx.to_hex())
            print(f"\nTransaction ID: {final_tx.get_txid()}")
            print(f"\nTo broadcast:")
            print(f"  bitcoin-cli -testnet sendrawtransaction {final_tx.to_hex()[:50]}...")
        else:
            print("Finalization failed - missing signatures or invalid PSBT")
            sys.exit(1)

if __name__ == "__main__":
    main()
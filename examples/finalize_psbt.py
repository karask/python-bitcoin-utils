#!/usr/bin/env python3
"""
Finalize a PSBT (Partially Signed Bitcoin Transaction) to produce a broadcastable Bitcoin transaction.

This script serves as the finalizer step (as defined in BIP-174), assembling signatures and scripts
into a complete transaction ready for broadcast.

Features:
- Loads a base64-encoded PSBT from string or file
- Finalizes all inputs by constructing scriptSig/scriptWitness
- Optionally validates that all inputs are fully signed before finalization
- Outputs the raw hex-encoded Bitcoin transaction

Usage:
    python finalize_psbt.py <psbt_base64_string>
    python finalize_psbt.py --file <psbt_file.txt>
    python finalize_psbt.py --file <psbt_file.txt> --validate

Arguments:
    <psbt_base64_string>        PSBT data as a base64-encoded string
    --file <psbt_file.txt>      Load PSBT from a file
    --validate                  (Optional) Enforce validation before finalizing

Returns:
    Hex-encoded, fully signed Bitcoin transaction ready for broadcast
"""


import argparse
import base64
import sys
from bitcoinutils.setup import setup
from bitcoinutils.psbt import PSBT


def main():
    """
    Main function for PSBT finalization.
    
    Usage:
        python finalize_psbt.py <psbt_base64_string>
        python finalize_psbt.py --file <psbt_file.txt>
        python finalize_psbt.py --file <psbt_file.txt> --validate
    """
    parser = argparse.ArgumentParser(description='Finalize a PSBT and create a transaction.')
    parser.add_argument('psbt', nargs='?', help='Base64-encoded PSBT string')
    parser.add_argument('--file', help='Text file containing base64 PSBT')
    parser.add_argument('--validate', action='store_true', help='Validate finalized transaction')
    parser.add_argument('--network', choices=['mainnet', 'testnet'], default='testnet', 
                       help='Bitcoin network (default: testnet)')
    
    args = parser.parse_args()
    
    # Setup the library for specified network
    setup(args.network)
    
    try:
        # Load PSBT from input
        if args.file:
            with open(args.file, 'r') as f:
                psbt_b64 = f.read().strip()
        elif args.psbt:
            psbt_b64 = args.psbt
        else:
            print("Error: Provide either base64 string or --file option.")
            print("Use --help for usage information.")
            return 1
        
        # Create PSBT object
        psbt = PSBT.from_base64(psbt_b64)
        
        # Finalize the PSBT
        if args.validate:
            final_tx, validation = psbt.finalize(validate=True)
            
            print("Finalized Transaction (Hex):")
            print(final_tx.serialize())
            
            print("\nValidation Report:")
            print(f"Valid: {validation['valid']}")
            print(f"Transaction ID: {validation['txid']}")
            print(f"Size: {validation['size']} bytes")
            print(f"Virtual Size: {validation['vsize']} vbytes")
            
            if validation['errors']:
                print("Errors:")
                for error in validation['errors']:
                    print(f"  - {error}")
            
            if validation['warnings']:
                print("Warnings:")
                for warning in validation['warnings']:
                    print(f"  - {warning}")
                    
        else:
            final_tx = psbt.finalize(validate=False)
            print("Finalized Transaction (Hex):")
            print(final_tx.serialize())
            
        print(f"\nTransaction ready to broadcast!")
        print(f"Use 'bitcoin-cli sendrawtransaction {final_tx.serialize()}' to broadcast")
        
        return 0
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
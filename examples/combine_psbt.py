#!/usr/bin/env python3
"""
Combine multiple partially signed PSBTs into a single PSBT.

This is useful in multisig scenarios where different signers create separate
PSBTs with their signatures, which then need to be combined before finalizing.

Usage:
    python examples/combine_psbt.py <psbt1_file> <psbt2_file> [<psbt3_file> ...]
    
Example:
    python examples/combine_psbt.py p2wsh_signed_1.psbt p2wsh_signed_2.psbt
"""
import sys
from bitcoinutils.setup import setup
from bitcoinutils.psbt import PSBT

def main():
    if len(sys.argv) < 3:
        print("Usage: python examples/combine_psbt.py <psbt1_file> <psbt2_file> [<psbt3_file> ...]")
        print("\nExample:")
        print("  python examples/combine_psbt.py p2wsh_signed_1.psbt p2wsh_signed_2.psbt")
        print("\nThis combines multiple PSBTs that have different signatures for the same transaction.")
        sys.exit(1)
    
    setup('testnet')
    
    try:
        # Load all PSBTs
        psbts = []
        for i, psbt_file in enumerate(sys.argv[1:], 1):
            try:
                # Try to load from file first
                with open(psbt_file, 'r') as f:
                    psbt_b64 = f.read().strip()
                print(f" Loaded PSBT {i} from: {psbt_file}")
            except FileNotFoundError:
                # If not a file, treat as base64 string
                psbt_b64 = psbt_file
                print(f" Using PSBT {i} from command line")
            
            psbt = PSBT.from_base64(psbt_b64)
            psbts.append(psbt)
            
            # Show info about this PSBT
            total_sigs = sum(len(inp.partial_sigs) if inp.partial_sigs else 0 
                           for inp in psbt.inputs)
            print(f"   - Inputs: {len(psbt.inputs)}")
            print(f"   - Total signatures: {total_sigs}")
        
        print(f"\n Combining {len(psbts)} PSBTs...")
        
        # Take the first PSBT as base
        combined = psbts[0]
        
        # Combine with the rest
        for i, other_psbt in enumerate(psbts[1:], 2):
            print(f"   Merging PSBT {i}...")
            combined = combined.combine(other_psbt)
        
        # Show combined result info
        print("\n Successfully combined PSBTs!")
        
        # Count signatures per input
        print("\n Combined PSBT Summary:")
        print(f"   Total inputs: {len(combined.inputs)}")
        
        for i, inp in enumerate(combined.inputs):
            sig_count = len(inp.partial_sigs) if inp.partial_sigs else 0
            print(f"   Input {i}: {sig_count} signature(s)")
            
            # Show which pubkeys have signed
            if inp.partial_sigs:
                for pubkey in inp.partial_sigs:
                    print(f"     - Signed by: {pubkey.hex()[:16]}...")
        
        # Check if ready to finalize
        ready_to_finalize = True
        for i, inp in enumerate(combined.inputs):
            if inp.witness_script:
                # For multisig, check if we have enough signatures
                witness_hex = inp.witness_script.to_hex()
                # Simple check for 2-of-3 multisig (you might need to adjust this)
                if "52" in witness_hex[:4] and "53ae" in witness_hex[-4:]:  # OP_2...OP_3 OP_CHECKMULTISIG
                    required_sigs = 2
                    current_sigs = len(inp.partial_sigs) if inp.partial_sigs else 0
                    if current_sigs < required_sigs:
                        ready_to_finalize = False
                        print(f"\n  Input {i} needs {required_sigs - current_sigs} more signature(s)")
        
        if ready_to_finalize:
            print("\n This PSBT has enough signatures and is ready to finalize!")
        else:
            print("\n  This PSBT needs more signatures before it can be finalized.")
        
        # Save combined PSBT
        combined_b64 = combined.to_base64()
        
        # Generate output filename
        total_sigs = sum(len(inp.partial_sigs) if inp.partial_sigs else 0 
                       for inp in combined.inputs)
        output_file = f'p2wsh_combined_{total_sigs}sigs.psbt'
        
        with open(output_file, 'w') as f:
            f.write(combined_b64)
        
        print(f"\n Saved combined PSBT to: {output_file}")
        print(f"   Base64 preview: {combined_b64[:80]}...")
        
        # Show next steps
        print("\n Next Steps:")
        if ready_to_finalize:
            print(f"   python examples/finalize_psbt.py {output_file}")
        else:
            print("   1. Get more signatures:")
            print(f"      python examples/sign_psbt.py {output_file} <private_key_wif> <input_index>")
            print("   2. Once you have enough signatures, finalize:")
            print(f"      python examples/finalize_psbt.py {output_file}")
        
        return 0
        
    except ValueError as e:
        print(f"\n Error: {e}")
        if "different transactions" in str(e).lower():
            print("   PSBTs must be for the same transaction to be combined.")
            print("   The PSBTs you're trying to combine appear to be for different transactions.")
        return 1
    except Exception as e:
        print(f"\n Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
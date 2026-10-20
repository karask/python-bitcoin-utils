#!/usr/bin/env python3
"""
Simple P2WSH PSBT signer that relies on bitcoinutils' native functionality.
"""
import sys
from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey
from bitcoinutils.psbt import PSBT
from bitcoinutils.constants import SIGHASH_ALL

def main():
    if len(sys.argv) < 4:
        print("Usage: python examples/sign_psbt.py <psbt_file> <private_key_wif> <input_index>")
        print("\nExample:")
        print("  python examples/sign_psbt.py p2wsh_unsigned.psbt cVVJMEAz... 0")
        sys.exit(1)
    
    psbt_input = sys.argv[1]
    private_key_wif = sys.argv[2]
    input_index = int(sys.argv[3])
    
    setup('testnet')
    
    try:
        # Load PSBT
        try:
            with open(psbt_input, 'r') as f:
                psbt_base64 = f.read().strip()
            print(f" Loaded PSBT from: {psbt_input}")
        except:
            psbt_base64 = psbt_input
            print(f" Using PSBT from command line")
        
        psbt = PSBT.from_base64(psbt_base64)
        
        # Load private key
        private_key = PrivateKey.from_wif(private_key_wif)
        pubkey = private_key.get_public_key()
        
        print(f"\n Signing Details:")
        print(f"   Private Key: {private_key_wif[:8]}...")
        print(f"   Public Key: {pubkey.to_hex()}")
        print(f"   Input Index: {input_index}")
        
        # Validate input
        if input_index >= len(psbt.inputs):
            raise ValueError(f"Input index {input_index} out of range")
        
        psbt_input_data = psbt.inputs[input_index]
        
        # Basic validation
        if not psbt_input_data.witness_script:
            raise ValueError("No witness script found - not a P2WSH input")
        
        if not psbt_input_data.witness_utxo:
            raise ValueError("No witness UTXO found")
        
        print(f"\n Input Validation:")
        print(f"    Witness script found ({len(psbt_input_data.witness_script.to_hex())//2} bytes)")
        print(f"    Witness UTXO found ({psbt_input_data.witness_utxo.amount:,} sats)")
        
        # Check existing signatures
        existing_sigs = len(psbt_input_data.partial_sigs) if psbt_input_data.partial_sigs else 0
        print(f"    Existing signatures: {existing_sigs}")
        
        # Check if already signed by this key
        pubkey_bytes = pubkey.to_bytes()
        if psbt_input_data.partial_sigs and pubkey_bytes in psbt_input_data.partial_sigs:
            print(f"     This key has already signed this input")
            return 0
        
        # Sign using bitcoinutils native method
        print(f"\n Signing input {input_index}...")
        
        # Try signing
        success = psbt.sign_input(input_index, private_key, SIGHASH_ALL)
        
        if success:
            new_sig_count = len(psbt.inputs[input_index].partial_sigs)
            print(f" Successfully signed! Signatures: {new_sig_count}")
            
            # Output signed PSBT
            signed_psbt = psbt.to_base64()
            output_file = f'p2wsh_signed_{new_sig_count}.psbt'
            
            with open(output_file, 'w') as f:
                f.write(signed_psbt)
            
            print(f"\n Saved to: {output_file}")
            print(f" First 100 chars: {signed_psbt[:100]}...")
            
            # Show next steps
            print(f"\n Next Steps:")
            print(f"   - To sign with another key:")
            print(f"     python examples/sign_psbt.py {output_file} <other_wif> {input_index}")
            print(f"   - When you have enough signatures, finalize:")
            print(f"     python examples/finalize_psbt.py {output_file}")
            
            return 0
        else:
            print(f" Failed to sign input {input_index}")
            return 1
    
    except Exception as e:
        print(f"\n Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
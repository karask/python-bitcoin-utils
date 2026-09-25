#!/usr/bin/env python3
"""
Fixed P2WSH PSBT finalizer with proper witness serialization
"""
import sys
from bitcoinutils.setup import setup
from bitcoinutils.psbt import PSBT
from bitcoinutils.transactions import Transaction, TxWitnessInput
from bitcoinutils.script import Script

def main():
    if len(sys.argv) < 2:
        print("Usage: python finalize_psbt.py <psbt_file>")
        sys.exit(1)
    
    setup('testnet')
    
    psbt_file = sys.argv[1]
    
    try:
        # Load PSBT
        with open(psbt_file, 'r') as f:
            psbt_b64 = f.read().strip()
        
        psbt = PSBT.from_base64(psbt_b64)
        print(f" Loaded PSBT: {len(psbt.inputs)} inputs")
        
        all_finalized = True
        
        for i, psbt_input in enumerate(psbt.inputs):
            print(f"\n Processing input {i}:")
            
            # Skip if already finalized
            if psbt_input.final_scriptwitness:
                print(f"    Already finalized")
                continue
            
            # Validate P2WSH
            if not psbt_input.witness_script:
                print(f"    No witness script")
                all_finalized = False
                continue
            
            if not psbt_input.witness_utxo:
                print(f"    No witness UTXO")
                all_finalized = False
                continue
            
            if not psbt_input.partial_sigs:
                print(f"    No partial signatures")
                all_finalized = False
                continue
            
            witness_script_hex = psbt_input.witness_script.to_hex()
            print(f"    Witness script: {len(witness_script_hex)//2} bytes")
            print(f"    UTXO amount: {psbt_input.witness_utxo.amount:,} sats")
            print(f"     Partial signatures: {len(psbt_input.partial_sigs)}")
            
            # For a 2-of-3 multisig, we need at least 2 signatures
            required_sigs = 2  # This is m in m-of-n
            
            if len(psbt_input.partial_sigs) < required_sigs:
                print(f"    Need {required_sigs} signatures, only have {len(psbt_input.partial_sigs)}")
                all_finalized = False
                continue
            
            # Get all available signatures and their corresponding pubkeys
            sig_items = list(psbt_input.partial_sigs.items())
            print(f"\n    Available signatures:")
            for pk, sig in sig_items:
                print(f"      - Pubkey: {pk.hex()}")
                print(f"        Sig: {sig.hex()[:32]}...")
            
            # Sort signatures by public key to ensure consistent ordering
            sorted_sig_items = sorted(sig_items, key=lambda x: x[0])
            
            # Build witness stack for P2WSH multisig
            # Format: [OP_0, sig1, sig2, witness_script]
            witness_stack = []
            
            # OP_0 for CHECKMULTISIG bug (empty hex string)
            witness_stack.append("")  # This will be an empty witness element
            
            # Add first m signatures (we need 2 for 2-of-3)
            sigs_added = 0
            for pk, sig in sorted_sig_items:
                if sigs_added < required_sigs:
                    # Convert signature bytes to hex string
                    witness_stack.append(sig.hex())
                    print(f"    Added signature {sigs_added + 1}")
                    sigs_added += 1
            
            # Add the witness script as hex string
            witness_stack.append(witness_script_hex)
            
            # Set final witness - store as list of hex strings
            psbt_input.final_scriptwitness = witness_stack
            
            # Clear partial sigs and witness script (they're not needed after finalization)
            psbt_input.partial_sigs = {}
            psbt_input.witness_script = None
            
            print(f"    Finalized with {required_sigs} signatures")
            print(f"    Witness stack has {len(witness_stack)} items:")
            print(f"      [0] OP_0 (empty)")
            for j in range(1, required_sigs + 1):
                print(f"      [{j}] Signature {j}")
            print(f"      [{required_sigs + 1}] Witness script")
        
        if not all_finalized:
            print("\n Not all inputs could be finalized")
            return 1
        
        # Extract final transaction
        print("\n Extracting final transaction...")
        
        try:
            # Create a new transaction with the same structure
            final_tx = Transaction(
                psbt.tx.inputs[:],
                psbt.tx.outputs[:],
                psbt.tx.locktime,
                psbt.tx.version,
                has_segwit=True  # IMPORTANT: Must be True for witness transactions
            )
            
            # Set up witnesses
            final_tx.witnesses = []
            for psbt_input in psbt.inputs:
                if psbt_input.final_scriptwitness:
                    # Create TxWitnessInput from the witness stack
                    witness = TxWitnessInput(psbt_input.final_scriptwitness)
                    final_tx.witnesses.append(witness)
                else:
                    # Empty witness for non-witness inputs
                    final_tx.witnesses.append(TxWitnessInput([]))
            
            # Serialize the transaction WITH witness data
            tx_hex = final_tx.to_hex()
            
            # Get transaction IDs
            txid = final_tx.get_txid()
            wtxid = final_tx.get_wtxid()
            
            print(f"\n Transaction Finalized Successfully!")
            print(f"   TXID: {txid}")
            print(f"   WTXID: {wtxid}")
            print(f"   Size: {len(tx_hex)//2} bytes")
            print(f"   vSize: {final_tx.get_vsize()} vbytes")
            
            # Verify witness data is present
            if "0001" in tx_hex[8:12]:  # Check for witness marker
                print(f"    Witness data present")
            else:
                print(f"    WARNING: No witness marker found!")
            
            print(f"\n Transaction hex preview:")
            print(f"   {tx_hex[:100]}...")
            if len(tx_hex) > 200:
                print(f"   ...{tx_hex[-100:]}")
            
            # Save transaction hex
            output_file = 'finalized_p2wsh_tx.hex'
            with open(output_file, 'w') as f:
                f.write(tx_hex)
            
            print(f"\n Transaction saved to: {output_file}")
            print(f"\n To broadcast on testnet:")
            print(f"   bitcoin-cli -testnet sendrawtransaction {tx_hex}")
            print(f"\n Or paste the hex at:")
            print(f"   https://blockstream.info/testnet/tx/push")
            
            # Save finalized PSBT
            try:
                finalized_psbt_b64 = psbt.to_base64()
                with open('finalized.psbt', 'w') as f:
                    f.write(finalized_psbt_b64)
                print(f"\n Finalized PSBT saved to: finalized.psbt")
            except Exception as e:
                print(f"\n  Warning: Could not save finalized PSBT: {e}")
                print("   This is OK - the transaction hex has been saved successfully!")
            
        except Exception as e:
            print(f"    Error during extraction: {e}")
            import traceback
            traceback.print_exc()
            return 1
        
        return 0
        
    except Exception as e:
        print(f"\n Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
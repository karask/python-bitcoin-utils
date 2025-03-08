#!/usr/bin/env python3

# Example: Combining PSBTs from multiple signers

from bitcoinutils.setup import setup
from bitcoinutils.psbt import PSBT

def main():
    # Setup the network
    setup('testnet')
    
    # Define PSBTs from different signers
    # Replace with your own PSBTs
    psbt1_base64 = "cHNidP8BAHUCAAAAAcgijGQXgR7MRl5Fx6g5dPgaVJfwhY4SK4M5I6pTLy9HAAAAAAD/////AoCWmAEAAAAAGXapFEPbU3M0+15UVo8nUXvQPVgvMQqziKwAAAAAAAAAGXapFC3J0f1e4DC1YgLFBzThoaj8jWWjiKwAAAAAAAEBIAhYmAEAAAAAFgAUfaLsJ5hKK8BLOXfgXHb0EbQnS3IiBgMC9D2zgHto4gyl4qbtdGuihjh7GzWk2n3LQ4iLzOA5QBjiJ015AAAA"
    psbt2_base64 = "cHNidP8BAHUCAAAAAcgijGQXgR7MRl5Fx6g5dPgaVJfwhY4SK4M5I6pTLy9HAAAAAAD/////AoCWmAEAAAAAGXapFEPbU3M0+15UVo8nUXvQPVgvMQqziKwAAAAAAAAAGXapFC3J0f1e4DC1YgLFBzThoaj8jWWjiKwAAAAAAAEBIAhYmAEAAAAAFgAUfaLsJ5hKK8BLOXfgXHb0EbQnS3IiBgLELw4bRrPuQpkHvEwxohfO3kLLKpfOqgzFLXNzOLXkfRitMgFjAAAA"
    
    # Parse the PSBTs
    psbt1 = PSBT.from_base64(psbt1_base64)
    psbt2 = PSBT.from_base64(psbt2_base64)
    
    print("PSBT 1 Information:")
    for i, psbt_input in enumerate(psbt1.inputs):
        print(f"Input {i} has {len(psbt_input.partial_sigs)} signature(s)")
    
    print("\nPSBT 2 Information:")
    for i, psbt_input in enumerate(psbt2.inputs):
        print(f"Input {i} has {len(psbt_input.partial_sigs)} signature(s)")
    
    # Combine the PSBTs
    combined_psbt = PSBT.combine([psbt1, psbt2])
    
    print("\nCombined PSBT Information:")
    for i, psbt_input in enumerate(combined_psbt.inputs):
        print(f"Input {i} has {len(psbt_input.partial_sigs)} signature(s)")
    
    # Serialize the combined PSBT
    combined_psbt_base64 = combined_psbt.to_base64()
    
    print("\nCombined PSBT (Base64):")
    print(combined_psbt_base64)
    
    print("\nThis combined PSBT can now be finalized and the transaction extracted")

if __name__ == "__main__":
    main()
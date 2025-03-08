#!/usr/bin/env python3

# Example: Finalizing a PSBT and extracting the transaction

from bitcoinutils.setup import setup
from bitcoinutils.psbt import PSBT

def main():
    # Setup the network
    setup('testnet')
    
    # Define a PSBT with all required signatures
    # Replace with your own PSBT
    psbt_base64 = "cHNidP8BAHUCAAAAAcgijGQXgR7MRl5Fx6g5dPgaVJfwhY4SK4M5I6pTLy9HAAAAAAD/////AoCWmAEAAAAAGXapFEPbU3M0+15UVo8nUXvQPVgvMQqziKwAAAAAAAAAGXapFC3J0f1e4DC1YgLFBzThoaj8jWWjiKwAAAAAAAEBIAhYmAEAAAAAFgAUfaLsJ5hKK8BLOXfgXHb0EbQnS3IiAgMC9D2zgHto4gyl4qbtdGuihjh7GzWk2n3LQ4iLzOA5QEcwRAIgcLsQZYL5GAmpk9GHYV0yQwAfRwL9kYoZ0dKB8tWBxCkCIBiQlz9HUeZ6gsXLgCHLVJk94+GaynYEQQTrZUHj63HHASECC+Ch0g8yJaMFvtJdT13DiKEqRxGwIzdUyF/YgfCiVpSsAAAAIgICxC8OG0az7kKZB7xMMaIXzt5CyyqXzqoMxS1zczS15H0YRzBEAiAufbU+MI/sVWzwB/r5+y4H9Vfa/PbWrXQfJYgDgW3cWQIgP9MsPMeAeN8Qw+l8nmF12Nj5XBcMmMSNURHwWB4rg2ABAQMEAQAAAAEFaVIhAvcqvE3jTj8r/CpKfhS8HI79yv5fJgeOhCaCRUrITQK5Ihjw+/pxLXcXG9JA+X5mQbHi+GPO4JGLKnHPqWVUnm8hA5XEW4M0wOepEHBa+/xw+lnbEwL//SZtWADcW0Igyo0wUq92U64AAQVpUiEDAvQ9s4B7aOIMpeKm7XRrooY4exs1pNp9y0OIi8zgOUAYGPD7+nEtdxcb0kD5fmZBseL4Y87gkYsqcc+pZVSebxsDlcRbgzTA56kQcFr7/HD6WdsTAv/9Jm1YANxbQiDKjTBSr3ZTrgAA"
    
    # Parse the PSBT
    psbt = PSBT.from_base64(psbt_base64)
    
    print("PSBT Information:")
    for i, psbt_input in enumerate(psbt.inputs):
        print(f"Input {i} has {len(psbt_input.partial_sigs)} signature(s)")
    
    # Finalize the PSBT
    if psbt.finalize():
        print("\nPSBT successfully finalized")
    else:
        print("\nFailed to finalize PSBT")
        return
    
    # Check if all inputs are finalized
    if psbt.is_finalized():
        print("All inputs are finalized")
    else:
        print("Not all inputs are finalized")
    
    # Extract the final transaction
    try:
        final_tx = psbt.extract_transaction()
        tx_hex = final_tx.serialize()
        
        print("\nFinal Transaction Hex:")
        print(tx_hex)
        
        print(f"\nTransaction ID: {final_tx.get_txid()}")
        
        print("\nThis transaction can now be broadcast to the Bitcoin network")
    except ValueError as e:
        print(f"\nError extracting transaction: {e}")

if __name__ == "__main__":
    main()
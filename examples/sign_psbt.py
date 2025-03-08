#!/usr/bin/env python3

# Example: Signing a PSBT

from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey
from bitcoinutils.psbt import PSBT

def main():
    # Setup the network
    setup('testnet')
    
    # Define the PSBT to sign (this would typically come from create_psbt.py)
    # Replace with your own PSBT
    psbt_base64 = "cHNidP8BAHUCAAAAAcgijGQXgR7MRl5Fx6g5dPgaVJfwhY4SK4M5I6pTLy9HAAAAAAD/////AoCWmAEAAAAAGXapFEPbU3M0+15UVo8nUXvQPVgvMQqziKwAAAAAAAAAGXapFC3J0f1e4DC1YgLFBzThoaj8jWWjiKwAAAAAAAEA3gIAAAAAAQH9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASEDDqBYtgVCQZX6hY6gcuJNfN4iZFZhO1EV45KxJMvFP0UAAAAAAQEfQsDaAAAAAAAWABR9qurSqqR3L3fGKrIZ/sD/OWRN3QAAAA=="
    
    # Parse the PSBT
    psbt = PSBT.from_base64(psbt_base64)
    
    print("Original PSBT Information:")
    print(psbt)
    
    # Create the signing key
    private_key = PrivateKey('cVwfreZB3r8vUkSnaoeZJ4Ux9W8YMqYM5XRV4zJo6ThcYs1MYiXj')
    
    # Sign the PSBT
    # In a real application, you would determine which inputs to sign
    # This example signs input 0
    if psbt.sign_input(private_key, 0):
        print("\nSuccessfully signed input 0")
    else:
        print("\nFailed to sign input 0")
    
    # Serialize the signed PSBT
    signed_psbt_base64 = psbt.to_base64()
    
    print("\nSigned PSBT (Base64):")
    print(signed_psbt_base64)
    
    print("\nThis signed PSBT can now be shared with other signers or finalized")

if __name__ == "__main__":
    main()
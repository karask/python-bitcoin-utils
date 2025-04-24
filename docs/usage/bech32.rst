Bech32 Module
============

The `bech32` module provides functions for encoding and decoding Bech32 and Bech32m addresses as specified in BIP173 and BIP350. This address format is used for native SegWit addresses in Bitcoin.

Overview
--------

Bech32 is an address format that includes error detection and is case insensitive. It is used for native SegWit addresses and has the following components:

- Human-readable part (HRP): e.g., "bc" for Bitcoin mainnet, "tb" for testnet
- Separator: Always "1"
- Data part: Encoded data that includes the witness version and witness program

Bech32m is an improved version of Bech32 (described in BIP350) that is used for SegWit version 1 and higher (e.g., Taproot addresses).

Basic Usage
----------

The module provides functions for encoding and decoding Bech32 addresses:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.bech32 import encode, decode

    # Setup the network
    setup('mainnet')

    # Encode a witness program
    hrp = "bc"  # Human-readable part for Bitcoin mainnet
    witness_version = 0  # SegWit version 0
    witness_program = [0, 14, 20, 15, ...]  # Witness program as list of integers
    
    address = encode(hrp, witness_version, witness_program)
    print(f"Bech32 address: {address}")

    # Decode a Bech32 address
    decoded_version, decoded_program = decode(hrp, address)
    print(f"Witness version: {decoded_version}")
    print(f"Witness program: {decoded_program}")

Encoding Addresses
----------------

To encode a witness program into a Bech32 address:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.bech32 import encode

    # Setup the network
    setup('testnet')

    # For SegWit v0 address on testnet
    hrp = "tb"
    witness_version = 0
    witness_program = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]
    
    address = encode(hrp, witness_version, witness_program)
    print(f"SegWit v0 address: {address}")

    # For SegWit v1 address (Taproot) on testnet
    witness_version = 1
    witness_program = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 
                      20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]
    
    taproot_address = encode(hrp, witness_version, witness_program)
    print(f"Taproot address: {taproot_address}")

Decoding Addresses
----------------

To decode a Bech32 or Bech32m address:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.bech32 import decode

    # Setup the network
    setup('mainnet')

    # Decode a SegWit v0 address
    segwit_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    hrp = "bc"
    
    witness_version, witness_program = decode(hrp, segwit_address)
    
    if witness_version is not None:
        print(f"Witness version: {witness_version}")
        print(f"Witness program: {witness_program}")
    else:
        print("Invalid address")

    # Decode a Taproot address
    taproot_address = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut"
    
    witness_version, witness_program = decode(hrp, taproot_address)
    
    if witness_version is not None:
        print(f"Witness version: {witness_version}")
        print(f"Witness program: {witness_program}")
    else:
        print("Invalid address")

Converting Between Data Formats
----------------------------

The module also provides utility functions for converting between different data formats:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.bech32 import convertbits
    from bitcoinutils.utils import h_to_b, b_to_h

    # Setup the network
    setup('testnet')

    # Convert a hex string to a list of 5-bit integers (for Bech32 encoding)
    hex_string = "751e76e8199196d454941c45d1b3a323f1433bd6"
    byte_data = h_to_b(hex_string)
    
    # Convert from 8-bit bytes to 5-bit integers for Bech32
    five_bit_data = convertbits(list(byte_data), 8, 5)
    
    # Convert back to 8-bit bytes
    eight_bit_data = convertbits(five_bit_data, 5, 8, False)
    
    # Convert back to hex
    recovered_hex = b_to_h(bytes(eight_bit_data))
    
    print(f"Original hex: {hex_string}")
    print(f"Recovered hex: {recovered_hex}")

Working with SegWit Addresses
---------------------------

The primary use case for Bech32 is encoding and decoding SegWit addresses:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PrivateKey
    from bitcoinutils.bech32 import encode, decode

    # Setup the network
    setup('testnet')

    # Create a private key and derive public key
    private_key = PrivateKey()
    public_key = private_key.get_public_key()
    
    # Get a SegWit v0 address
    segwit_address = public_key.get_segwit_address()
    print(f"SegWit v0 address: {segwit_address.to_string()}")
    
    # Get a Taproot (SegWit v1) address
    taproot_address = public_key.get_taproot_address()
    print(f"Taproot address: {taproot_address.to_string()}")
    
    # Decode the SegWit v0 address
    witness_version, witness_program = decode("tb", segwit_address.to_string())
    print(f"SegWit v0 witness version: {witness_version}")
    print(f"SegWit v0 witness program: {witness_program}")
    
    # Decode the Taproot address
    witness_version, witness_program = decode("tb", taproot_address.to_string())
    print(f"Taproot witness version: {witness_version}")
    print(f"Taproot witness program: {witness_program}")

Error Detection
-------------

Bech32 includes error detection and can help identify common mistakes:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.bech32 import decode

    # Setup the network
    setup('mainnet')

    # Valid address
    valid_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    
    # Address with a typo (v8f3t4 -> v8f3t5)
    typo_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"
    
    # Address with incorrect case (mixed case not allowed in Bech32)
    case_error_address = "bc1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"
    
    # Check valid address
    result = decode("bc", valid_address)
    print(f"Valid address check: {result[0] is not None}")
    
    # Check address with typo
    result = decode("bc", typo_address)
    print(f"Typo address check: {result[0] is not None}")
    
    # Check address with case error
    result = decode("bc", case_error_address)
    print(f"Case error address check: {result[0] is not None}")

Bech32 vs Bech32m
---------------

The module automatically handles both Bech32 (for witness version 0) and Bech32m (for witness version 1+):

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.bech32 import encode, decode

    # Setup the network
    setup('testnet')

    # SegWit v0 uses Bech32
    v0_program = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]
    v0_address = encode("tb", 0, v0_program)
    print(f"SegWit v0 address: {v0_address}")
    
    # SegWit v1 uses Bech32m
    v1_program = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 
                  20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]
    v1_address = encode("tb", 1, v1_program)
    print(f"SegWit v1 address: {v1_address}")
    
    # Decode both
    v0_result = decode("tb", v0_address)
    v1_result = decode("tb", v1_address)
    
    print(f"SegWit v0 decode: version={v0_result[0]}, program length={len(v0_result[1])}")
    print(f"SegWit v1 decode: version={v1_result[0]}, program length={len(v1_result[1])}")
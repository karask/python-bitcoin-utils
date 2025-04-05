Utils Module
===========

The `utils` module provides utility functions for various Bitcoin-related operations, including encoding and decoding data, cryptographic operations, and parameter handling for Taproot.

Overview
--------

The utility functions in this module handle:

- Conversion between different data formats (bytes, hex, int)
- Cryptographic parameters for SECP256k1
- Message signing and verification utilities
- Taproot-specific utilities (key tweaking, hashing)

Encoding and Decoding Functions
-----------------------------

These functions help convert between different data formats:

.. code-block:: python

    from bitcoinutils.utils import h_to_b, b_to_h, h_to_i, i_to_h, b_to_i, i_to_b32

    # Convert hex string to bytes
    hex_str = "1a2b3c4d"
    byte_data = h_to_b(hex_str)
    print(f"Hex to bytes: {byte_data}")

    # Convert bytes to hex string
    hex_str_back = b_to_h(byte_data)
    print(f"Bytes to hex: {hex_str_back}")

    # Convert hex string to integer
    hex_str = "1a2b3c4d"
    int_val = h_to_i(hex_str)
    print(f"Hex to int: {int_val}")

    # Convert integer to hex string
    int_val = 439041101
    hex_str = i_to_h(int_val)
    print(f"Int to hex: {hex_str}")

    # Convert bytes to integer
    int_val = b_to_i(byte_data)
    print(f"Bytes to int: {int_val}")

    # Convert integer to 32-byte representation
    int_val = 439041101
    bytes_32 = i_to_b32(int_val)
    print(f"Int to 32 bytes: {bytes_32.hex()}")

SECP256k1 Parameters
------------------

The module defines parameters for the SECP256k1 elliptic curve, which is used in Bitcoin:

.. code-block:: python

    from bitcoinutils.utils import Secp256k1Params

    # Display SECP256k1 parameters
    print(f"SECP256k1 Order: {Secp256k1Params._order}")
    print(f"SECP256k1 Field Size: {Secp256k1Params._p}")
    print(f"SECP256k1 A: {Secp256k1Params._a}")
    print(f"SECP256k1 B: {Secp256k1Params._b}")

Message Signing Utilities
----------------------

The module provides helper functions for message signing:

.. code-block:: python

    from bitcoinutils.utils import add_magic_prefix

    # Add Bitcoin message magic prefix to a message for signing
    message = "Hello, Bitcoin!"
    prefixed_message = add_magic_prefix(message)
    print(f"Original message: {message}")
    print(f"Prefixed message: {prefixed_message}")

Taproot Utilities
--------------

Functions for working with Taproot-specific operations:

.. code-block:: python

    from bitcoinutils.utils import calculate_tweak, tweak_taproot_pubkey, tweak_taproot_privkey
    from bitcoinutils.keys import PrivateKey, PublicKey
    from bitcoinutils.script import Script

    # Create a key pair
    private_key = PrivateKey()
    public_key = private_key.get_public_key()

    # Create a script for Taproot
    script = Script(['OP_CHECKSIG'])

    # Calculate tweak for Taproot
    tweak = calculate_tweak(public_key, script)
    print(f"Taproot tweak: {tweak}")

    # Tweak the public key for Taproot
    tweaked_pubkey, is_odd = tweak_taproot_pubkey(public_key.key.to_string(), tweak)
    print(f"Tweaked public key: {tweaked_pubkey.hex()}")
    print(f"Is Y-coordinate odd: {is_odd}")

    # Tweak the private key for Taproot
    tweaked_privkey = tweak_taproot_privkey(private_key.key.to_string(), tweak)
    print(f"Tweaked private key: {tweaked_privkey.hex()}")

Conversion Examples
----------------

Here are some practical examples of using the utility functions:

.. code-block:: python

    from bitcoinutils.utils import h_to_b, b_to_h, h_to_i, i_to_h, b_to_i

    # Convert a transaction ID (little-endian) to a byte order suitable for RPC calls
    txid_hex = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
    txid_bytes = h_to_b(txid_hex)
    txid_bytes_reversed = txid_bytes[::-1]  # Reverse the bytes
    txid_reversed_hex = b_to_h(txid_bytes_reversed)
    print(f"Original TXID: {txid_hex}")
    print(f"Reversed TXID: {txid_reversed_hex}")

    # Convert an amount in satoshis to bitcoin
    satoshis = 123456789
    bitcoin = satoshis / 100000000
    print(f"{satoshis} satoshis = {bitcoin} BTC")

    # Convert a hexadecimal script to its assembly representation
    script_hex = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
    script_bytes = h_to_b(script_hex)
    # In a real implementation, you would use the Script class to parse this

Practical Applications
-------------------

Here are some practical applications of these utility functions:

1. **Transaction Processing**:

.. code-block:: python

    from bitcoinutils.utils import h_to_b, b_to_h
    from bitcoinutils.transactions import Transaction

    # Parse a raw transaction hex
    raw_tx_hex = "0100000001..."
    tx = Transaction.from_hex(raw_tx_hex)

    # Serialize a transaction
    serialized_tx = tx.serialize()
    print(f"Serialized transaction: {serialized_tx}")

2. **Key Management**:

.. code-block:: python

    from bitcoinutils.utils import h_to_b
    from bitcoinutils.keys import PrivateKey

    # Create a private key from known bytes
    seed_hex = "000102030405060708090a0b0c0d0e0f"
    seed_bytes = h_to_b(seed_hex)
    private_key = PrivateKey.from_bytes(seed_bytes)
    
    # Get the WIF format
    wif = private_key.to_wif()
    print(f"WIF: {wif}")

3. **Taproot Address Creation**:

.. code-block:: python

    from bitcoinutils.utils import calculate_tweak, tweak_taproot_pubkey
    from bitcoinutils.keys import PrivateKey, PublicKey, P2trAddress

    # Create a key pair
    private_key = PrivateKey()
    public_key = private_key.get_public_key()

    # Calculate tweak for Taproot (with no script path)
    tweak = calculate_tweak(public_key, None)

    # Tweak the public key for Taproot
    tweaked_pubkey, is_odd = tweak_taproot_pubkey(public_key.key.to_string(), tweak)
    
    # Create a Taproot address
    p2tr_addr = P2trAddress(witness_program=tweaked_pubkey.hex(), is_odd=is_odd)
    print(f"Taproot address: {p2tr_addr.to_string()}")

Additional Utilities
-----------------

The module contains various other utility functions for specific Bitcoin operations:

- Hash functions (sha256, ripemd160)
- BIP-340 tagged hashes for Taproot
- Helper functions for variable-length integer encoding
- Script utility functions

These utilities form the foundation for many of the higher-level functions in the library and are essential for Bitcoin operations.
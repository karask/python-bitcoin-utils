Schnorr Module
=============

The `schnorr` module provides functionality for creating and verifying Schnorr signatures according to BIP340. Schnorr signatures are used in Taproot (SegWit v1) to provide more efficient, secure, and privacy-enhancing signature validation.

Overview
--------

Schnorr signatures offer several advantages over ECDSA signatures:

- **Linearity**: Schnorr signatures can be combined, enabling more efficient multisignature schemes
- **Simplicity**: The verification algorithm is simpler and more intuitive
- **Provable security**: Schnorr signatures have stronger security proofs than ECDSA
- **Smaller size**: No signature malleability means no need for extra data in the signature

This module implements the BIP340 specification for Schnorr signatures, which is used in Taproot transactions.

Basic Usage
----------

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.schnorr import sign, verify
    from bitcoinutils.keys import PrivateKey

    # Setup the network
    setup('testnet')

    # Create a private key
    private_key = PrivateKey()
    public_key = private_key.get_public_key()

    # Message to sign
    message = "Hello, Bitcoin!"
    message_bytes = message.encode('utf-8')

    # Sign the message using Schnorr
    signature = sign(private_key, message_bytes)
    print(f"Schnorr signature: {signature.hex()}")

    # Verify the signature
    is_valid = verify(public_key, message_bytes, signature)
    print(f"Signature valid: {is_valid}")

Signing with Schnorr
------------------

To create a Schnorr signature:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.schnorr import sign
    from bitcoinutils.keys import PrivateKey
    import hashlib

    # Setup the network
    setup('testnet')

    # Create a key
    private_key = PrivateKey()
    
    # Option 1: Sign a message directly
    message = "Hello, Bitcoin!"
    message_bytes = message.encode('utf-8')
    signature = sign(private_key, message_bytes)
    
    # Option 2: Sign a message digest
    digest = hashlib.sha256(message_bytes).digest()
    signature_from_digest = sign(private_key, digest)
    
    print(f"Schnorr signature: {signature.hex()}")

Verifying Schnorr Signatures
--------------------------

To verify a Schnorr signature:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.schnorr import verify
    from bitcoinutils.keys import PrivateKey, PublicKey
    import hashlib

    # Setup the network
    setup('testnet')

    # Create a key pair for testing
    private_key = PrivateKey()
    public_key = private_key.get_public_key()
    
    # Sign a message
    message = "Hello, Bitcoin!"
    message_bytes = message.encode('utf-8')
    signature = sign(private_key, message_bytes)
    
    # Verify the signature
    is_valid = verify(public_key, message_bytes, signature)
    print(f"Signature valid: {is_valid}")
    
    # Verify using a message digest
    digest = hashlib.sha256(message_bytes).digest()
    is_valid_digest = verify(public_key, digest, signature)
    print(f"Signature valid (using digest): {is_valid_digest}")
    
    # Verify an invalid signature
    modified_signature = bytearray(signature)
    modified_signature[0] ^= 1  # Flip a bit
    is_invalid = verify(public_key, message_bytes, bytes(modified_signature))
    print(f"Modified signature valid: {is_invalid}")  # Should be False

Working with Taproot
------------------

Schnorr signatures are primarily used in Taproot (SegWit v1) transactions. Here's how to use them with Taproot:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PrivateKey
    from bitcoinutils.transactions import Transaction, TxInput, TxOutput
    
    # Setup the network
    setup('testnet')
    
    # Create a transaction that spends from a Taproot output
    txin = TxInput('taproot_tx_id', 0)
    txout = TxOutput(0.001, recipient_script_pub_key)
    tx = Transaction([txin], [txout])
    
    # Sign the Taproot input (this uses Schnorr signatures internally)
    private_key = PrivateKey('your_private_key_wif')
    signature = private_key.sign_taproot_input(tx, 0, [{'value': 0.001, 'scriptPubKey': prev_script_pub_key}])
    
    # Set the witness data
    txin.witness = [signature]  # Key path spending - just the signature
    
    # Get the signed transaction
    signed_tx_hex = tx.serialize()
    print(f"Signed Taproot transaction: {signed_tx_hex}")

Batch Verification
---------------

One advantage of Schnorr signatures is that they can be efficiently batch verified. This is not directly implemented in the library, but here's a conceptual example:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.schnorr import verify
    
    # Setup the network
    setup('testnet')
    
    # Multiple signature-message-publickey tuples to verify
    verifications = [
        (signature1, message1, public_key1),
        (signature2, message2, public_key2),
        (signature3, message3, public_key3),
    ]
    
    # Verify all signatures
    all_valid = all(verify(pk, msg, sig) for sig, msg, pk in verifications)
    print(f"All signatures valid: {all_valid}")

Schnorr vs ECDSA
--------------

Here's a comparison between Schnorr and ECDSA signatures in the library:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PrivateKey
    from bitcoinutils.schnorr import sign as schnorr_sign
    import time
    
    # Setup the network
    setup('testnet')
    
    # Create a key pair
    private_key = PrivateKey()
    public_key = private_key.get_public_key()
    
    # Message to sign
    message = "Hello, Bitcoin!"
    message_bytes = message.encode('utf-8')
    
    # Sign with ECDSA
    start_time = time.time()
    ecdsa_signature = private_key.sign_message(message)
    ecdsa_time = time.time() - start_time
    print(f"ECDSA signature: {ecdsa_signature}")
    print(f"ECDSA signature time: {ecdsa_time:.6f} seconds")
    
    # Sign with Schnorr
    start_time = time.time()
    schnorr_signature = schnorr_sign(private_key, message_bytes)
    schnorr_time = time.time() - start_time
    print(f"Schnorr signature: {schnorr_signature.hex()}")
    print(f"Schnorr signature time: {schnorr_time:.6f} seconds")
    
    # Compare sizes
    print(f"ECDSA signature size: {len(ecdsa_signature)} bytes")
    print(f"Schnorr signature size: {len(schnorr_signature)} bytes")

Technical Details
--------------

The Schnorr signature implementation follows BIP340 and has these key characteristics:

1. **Deterministic Nonce Generation**: Uses a deterministic nonce to prevent catastrophic key leaks from poor randomness.

2. **Tagged Hashes**: Uses tagged hashes to ensure domain separation, preventing attacks that try to exploit signature schemes.

3. **x-only Public Keys**: Uses only the x-coordinate of public keys to save space.

4. **Single Verification Equation**: Has a simple, efficient verification equation.

5. **No Signature Malleability**: Prevents signature malleability issues that exist in ECDSA.

Security Considerations
--------------------

When using Schnorr signatures, keep in mind these security considerations:

1. **Key Management**: Protect private keys as they can derive all signatures.

2. **Nonce Reuse**: The library prevents nonce reuse, but custom implementations must ensure that a nonce is never reused with the same key for different messages.

3. **Implementation Security**: The library follows the BIP340 reference implementation for security.

4. **Batch Verification**: Be aware that batch verification can be faster but might mask individual signature failures.
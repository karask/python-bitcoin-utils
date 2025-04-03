Keys and Addresses
================

The ``keys`` module provides classes and methods for working with Bitcoin keys and addresses. It includes functionality for creating, managing, and using private keys, public keys, and various address types.

Overview
--------

This module implements the following classes:

- ``PrivateKey``: For managing ECDSA private keys
- ``PublicKey``: For managing ECDSA public keys
- ``Address``: Base class for Bitcoin addresses
- ``P2pkhAddress``: Pay-to-Public-Key-Hash (P2PKH) addresses
- ``P2shAddress``: Pay-to-Script-Hash (P2SH) addresses
- ``SegwitAddress``: Base class for Segregated Witness addresses
- ``P2wpkhAddress``: Pay-to-Witness-Public-Key-Hash (P2WPKH) addresses
- ``P2wshAddress``: Pay-to-Witness-Script-Hash (P2WSH) addresses
- ``P2trAddress``: Pay-to-Taproot (P2TR) addresses

Basic Usage
----------

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PrivateKey, PublicKey, P2pkhAddress

    # Always remember to setup the network
    setup('testnet')

    # Generate a new private key
    priv = PrivateKey()
    print(f"Private key (WIF): {priv.to_wif()}")

    # Get the corresponding public key
    pub = priv.get_public_key()
    print(f"Public key: {pub.to_hex()}")

    # Get the corresponding P2PKH address
    addr = pub.get_address()
    print(f"Address: {addr.to_string()}")

    # Create a specific private key from WIF
    priv2 = PrivateKey.from_wif("cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo")
    print(f"Address from WIF: {priv2.get_public_key().get_address().to_string()}")

Working with Private Keys
------------------------

The ``PrivateKey`` class provides methods for creating and managing private keys:

.. code-block:: python

    # Generate a random private key
    priv = PrivateKey()
    
    # Create from WIF
    priv = PrivateKey.from_wif("cVwfreZB3i8hCGcnZ8JeXAE3PQCgqpd2Yx1HscAUxN6XUfBFDGH3")
    
    # Create from raw bytes
    priv = PrivateKey.from_bytes(b'...')
    
    # Create from specific number (deterministic)
    priv = PrivateKey(secret_exponent=123456789)
    
    # Export to WIF (Wallet Import Format)
    wif = priv.to_wif(compressed=True)  # compressed by default
    
    # Sign a message
    signature = priv.sign_message("Hello, Bitcoin!")
    
    # Sign a transaction input
    from bitcoinutils.transactions import Transaction
    signature = priv.sign_input(tx, txin_index, script)
    
    # Get the corresponding public key
    pub = priv.get_public_key()

Working with Public Keys
----------------------

The ``PublicKey`` class provides methods for creating and managing public keys:

.. code-block:: python

    # Get a public key from a private key
    priv = PrivateKey()
    pub = priv.get_public_key()
    
    # Create from hex (SEC format)
    pub = PublicKey.from_hex("02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc")
    
    # Recover a public key from a message and signature
    pub = PublicKey.from_message_signature(message, signature)
    
    # Export to hex (SEC format)
    hex_compressed = pub.to_hex(compressed=True)
    hex_uncompressed = pub.to_hex(compressed=False)
    
    # For taproot (x-only pubkeys)
    x_only_hex = pub.to_x_only_hex()
    
    # Verify a message signature
    is_valid = pub.verify(signature, message)
    
    # Convert to hash160 (used in address creation)
    hash160 = pub.to_hash160(compressed=True)
    
    # Get different address types
    p2pkh_addr = pub.get_address(compressed=True)
    p2wpkh_addr = pub.get_segwit_address()
    p2tr_addr = pub.get_taproot_address()

Working with Addresses
--------------------

The module provides several address types, each with specific methods:

.. code-block:: python

    # Create a P2PKH address from a public key
    pub = PrivateKey().get_public_key()
    p2pkh = pub.get_address()
    print(f"P2PKH address: {p2pkh.to_string()}")
    
    # Create from an existing address string
    p2pkh = P2pkhAddress.from_address("mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2")
    
    # Create from hash160
    p2pkh = P2pkhAddress.from_hash160("751e76e8199196d454941c45d1b3a323f1433bd6")
    
    # Get scriptPubKey for use in transactions
    script = p2pkh.to_script_pub_key()
    
    # P2SH address from a redeem script
    from bitcoinutils.script import Script
    redeem_script = Script(['OP_2', pub1.to_hex(), pub2.to_hex(), 'OP_2', 'OP_CHECKMULTISIG'])
    p2sh = P2shAddress.from_script(redeem_script)
    print(f"P2SH address: {p2sh.to_string()}")

SegWit Addresses
--------------

SegWit addresses are special address types that use Segregated Witness:

.. code-block:: python

    # P2WPKH address (SegWit version 0)
    pub = PrivateKey().get_public_key()
    p2wpkh = pub.get_segwit_address()
    print(f"P2WPKH address: {p2wpkh.to_string()}")
    
    # P2WSH address (SegWit version 0)
    witness_script = Script(['OP_2', pub1.to_hex(), pub2.to_hex(), 'OP_2', 'OP_CHECKMULTISIG'])
    p2wsh = P2wshAddress.from_script(witness_script)
    print(f"P2WSH address: {p2wsh.to_string()}")
    
    # P2TR address (SegWit version 1 - Taproot)
    p2tr = pub.get_taproot_address()
    print(f"P2TR address: {p2tr.to_string()}")
    
    # P2TR with script path spending
    taproot_script = Script([...])  # Script path
    p2tr = pub.get_taproot_address(scripts=taproot_script)

Message Signing and Verification
------------------------------

Bitcoin provides a standard way to sign and verify messages:

.. code-block:: python

    # Sign a message with a private key
    priv = PrivateKey.from_wif("cVwfreZB3i8hCGcnZ8JeXAE3PQCgqpd2Yx1HscAUxN6XUfBFDGH3")
    signature = priv.sign_message("Hello, Bitcoin!")
    
    # Verify a message with a public key
    pub = priv.get_public_key()
    is_valid = pub.verify(signature, "Hello, Bitcoin!")
    
    # Verify a message with an address (static method)
    address = "mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2"
    is_valid = PublicKey.verify_message(address, signature, "Hello, Bitcoin!")

Working with Taproot
------------------

Taproot is a Bitcoin upgrade that enhances privacy, efficiency, and smart contract capabilities:

.. code-block:: python

    # Create a private key
    priv = PrivateKey()
    pub = priv.get_public_key()
    
    # Get a basic P2TR address (key-path only)
    p2tr = pub.get_taproot_address()
    
    # Create a P2TR address with script paths
    from bitcoinutils.script import Script
    script_a = Script(['OP_1'])
    script_b = Script(['OP_0'])
    # A simple script tree with two scripts
    scripts = [[script_a, script_b]]
    p2tr_with_scripts = pub.get_taproot_address(scripts=scripts)
    
    # Tweak the public key for Taproot
    pubkey_tweaked, is_odd = pub.to_taproot_hex(scripts=scripts)
    
    # Sign a Taproot input for key-path spending
    sig = priv.sign_taproot_input(tx, 0, script_pubkeys, amounts)
    
    # Sign a Taproot input for script-path spending 
    sig = priv.sign_taproot_input(tx, 0, script_pubkeys, amounts, 
                                  script_path=True, tapleaf_script=script_a, 
                                  tweak=False)
    
Advanced Features
--------------

1. **Custom Network Configuration**:
   
   You can use keys and addresses on different Bitcoin networks:

   .. code-block:: python
   
       from bitcoinutils.setup import setup
       
       # Use testnet
       setup('testnet')
       priv = PrivateKey()
       addr = priv.get_public_key().get_address()
       print(f"Testnet address: {addr.to_string()}")
       
       # Use mainnet
       setup('mainnet')
       priv = PrivateKey()
       addr = priv.get_public_key().get_address()
       print(f"Mainnet address: {addr.to_string()}")

2. **Transaction Signing**:
   
   Private keys can sign different types of transactions:

   .. code-block:: python
   
       # Sign a regular P2PKH input
       sig = priv.sign_input(tx, txin_index, script_pubkey)
       
       # Sign a SegWit input
       sig = priv.sign_segwit_input(tx, txin_index, script_pubkey, amount)
       
       # Sign a Taproot input
       sig = priv.sign_taproot_input(tx, txin_index, scripts, amounts)

3. **Key Utilities**:
   
   The module provides various utility methods:

   .. code-block:: python
   
       # Check if y-coordinate is even
       is_even = pub.is_y_even()
       
       # Get raw bytes representation
       key_bytes = priv.to_bytes()
       pubkey_bytes = pub.to_bytes()
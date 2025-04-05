Address Object
==============

The Address object in the Python Bitcoin Utils library provides a unified interface for working with different Bitcoin address formats. It supports creation, validation, conversion, and management of various address types including legacy addresses, SegWit addresses, and Taproot addresses.

Address Types Supported
----------------------

The library supports the following address types:

1. **P2PKH (Pay to Public Key Hash)**: Legacy Bitcoin addresses
2. **P2SH (Pay to Script Hash)**: Script hash addresses
3. **P2WPKH (Pay to Witness Public Key Hash)**: Native SegWit v0 addresses for single signatures
4. **P2WSH (Pay to Witness Script Hash)**: Native SegWit v0 addresses for scripts
5. **P2TR (Pay to Taproot)**: Taproot addresses (SegWit v1)
6. **P2SH-P2WPKH**: Nested SegWit addresses for single signatures
7. **P2SH-P2WSH**: Nested SegWit addresses for scripts

Class Hierarchy
--------------

The Address hierarchy is organized as follows:

.. code-block::

    Address (base class)
    ├── P2pkhAddress
    ├── P2shAddress
    └── SegwitAddress (base class)
        ├── P2wpkhAddress
        ├── P2wshAddress
        └── P2trAddress

Creating Address Objects
----------------------

From a Public Key
^^^^^^^^^^^^^^^^

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PrivateKey, PublicKey

    setup('testnet')

    # Generate a private key and get its public key
    private_key = PrivateKey()
    public_key = private_key.get_public_key()

    # Create different address types from the public key
    p2pkh_address = public_key.get_address()
    p2wpkh_address = public_key.get_segwit_address()
    p2sh_p2wpkh_address = public_key.get_p2sh_p2wpkh_address()
    p2tr_address = public_key.get_taproot_address()

    print(f"P2PKH address: {p2pkh_address.to_string()}")
    print(f"P2WPKH address: {p2wpkh_address.to_string()}")
    print(f"P2SH-P2WPKH address: {p2sh_p2wpkh_address.to_string()}")
    print(f"P2TR address: {p2tr_address.to_string()}")

From a Script
^^^^^^^^^^^

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PublicKey
    from bitcoinutils.script import Script

    setup('testnet')

    # Create public keys
    pub1 = PublicKey("pub_key_1_hex")
    pub2 = PublicKey("pub_key_2_hex")

    # Create a 2-of-2 multisig script
    multisig_script = Script([2, pub1.to_hex(), pub2.to_hex(), 2, 'OP_CHECKMULTISIG'])

    # Create different address types from the script
    p2sh_address = multisig_script.get_p2sh_address()
    p2wsh_address = multisig_script.get_segwit_address()
    p2sh_p2wsh_address = multisig_script.get_p2sh_p2wsh_address()

    print(f"P2SH address: {p2sh_address.to_string()}")
    print(f"P2WSH address: {p2wsh_address.to_string()}")
    print(f"P2SH-P2WSH address: {p2sh_p2wsh_address.to_string()}")

From an Address String
^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import Address, P2pkhAddress, P2shAddress
    from bitcoinutils.keys import P2wpkhAddress, P2wshAddress, P2trAddress

    setup('testnet')

    # Create address objects from string representations
    p2pkh = P2pkhAddress('mzF2sbdxcMqKFLoakdBcvZpUXMjgiXGZW1')
    p2sh = P2shAddress('2N6Vk58WRh7gQYrRUBZAJAxXC7TKPPpKmDD')
    p2wpkh = P2wpkhAddress('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx')
    p2wsh = P2wshAddress('tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7')
    p2tr = P2trAddress('tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6')

From a Hash160
^^^^^^^^^^^^

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import P2pkhAddress, P2shAddress

    setup('testnet')

    # Create address objects from hash160 
    p2pkh = P2pkhAddress(hash160='751e76e8199196d454941c45d1b3a323f1433bd6')
    p2sh = P2shAddress(hash160='8f55563b9a19f321c211e9b9f38cdf686ea07845')

Base Address Class Methods
------------------------

The base `Address` class provides several methods:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import P2pkhAddress

    setup('testnet')

    # Create an address
    addr = P2pkhAddress('mzF2sbdxcMqKFLoakdBcvZpUXMjgiXGZW1')

    # Convert to string
    addr_str = addr.to_string()
    
    # Get hash160
    hash160 = addr.to_hash160()
    
    # Get script pubkey
    script_pubkey = addr.to_script_pub_key()
    
    # Get address type
    addr_type = addr.get_type()

SegWit Address Base Class Methods
-------------------------------

The `SegwitAddress` base class provides additional methods specific to SegWit addresses:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import P2wpkhAddress, P2trAddress

    setup('testnet')

    # Create a segwit address
    segwit_addr = P2wpkhAddress('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx')
    
    # Get witness program 
    witness_program = segwit_addr.to_witness_program()
    
    # Create a taproot address
    taproot_addr = P2trAddress('tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6')
    
    # Check if y-coordinate is odd (P2TR addresses only)
    is_odd = taproot_addr.is_odd()

Address Creation Methods in Other Classes
---------------------------------------

The library also provides convenient methods to create address objects from other objects:

From Public Key
^^^^^^^^^^^^^

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PrivateKey

    setup('testnet')

    # Generate private key
    private_key = PrivateKey()
    public_key = private_key.get_public_key()
    
    # Create different address types
    p2pkh_addr = public_key.get_address()
    p2wpkh_addr = public_key.get_segwit_address() 
    p2tr_addr = public_key.get_taproot_address()

From Script
^^^^^^^^^

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.script import Script

    setup('testnet')

    # Create a script 
    script = Script(['OP_1', 'public_key_1', 'public_key_2', 'OP_2', 'OP_CHECKMULTISIG'])
    
    # Get different address types
    p2sh_addr = script.get_p2sh_address()
    p2wsh_addr = script.get_segwit_address()
    
    # Taproot addresses with script trees
    # Define some scripts
    script1 = Script(['pubkey1', 'OP_CHECKSIG'])
    script2 = Script(['pubkey2', 'OP_CHECKSIG'])
    
    # Create a taproot address with these scripts
    p2tr_addr = public_key.get_taproot_address([script1, script2])

Creating an Address from Scratch
------------------------------

While typically addresses are derived from keys or scripts, you can also create an address object directly:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import P2pkhAddress, P2shAddress
    from bitcoinutils.keys import P2wpkhAddress, P2wshAddress, P2trAddress

    setup('testnet')

    # Legacy addresses
    p2pkh = P2pkhAddress(hash160='751e76e8199196d454941c45d1b3a323f1433bd6')
    p2sh = P2shAddress(hash160='8f55563b9a19f321c211e9b9f38cdf686ea07845')
    
    # SegWit addresses
    p2wpkh = P2wpkhAddress(witness_program='751e76e8199196d454941c45d1b3a323f1433bd6')
    p2wsh = P2wshAddress(script=some_script)
    p2tr = P2trAddress(witness_program='cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115')

Script PubKey Generation
----------------------

Each address type can generate its corresponding scriptPubKey:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import P2pkhAddress, P2shAddress, P2wpkhAddress, P2trAddress

    setup('testnet')

    # Create different address types
    p2pkh = P2pkhAddress('mzF2sbdxcMqKFLoakdBcvZpUXMjgiXGZW1')
    p2sh = P2shAddress('2N6Vk58WRh7gQYrRUBZAJAxXC7TKPPpKmDD')
    p2wpkh = P2wpkhAddress('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx')
    p2tr = P2trAddress('tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6')
    
    # Get scriptPubKey for each address type
    p2pkh_script = p2pkh.to_script_pub_key()  # OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
    p2sh_script = p2sh.to_script_pub_key()    # OP_HASH160 <hash160> OP_EQUAL
    p2wpkh_script = p2wpkh.to_script_pub_key() # OP_0 <witness program>
    p2tr_script = p2tr.to_script_pub_key()    # OP_1 <witness program>
    
    print(f"P2PKH scriptPubKey: {p2pkh_script.to_string()}")
    print(f"P2SH scriptPubKey: {p2sh_script.to_string()}")
    print(f"P2WPKH scriptPubKey: {p2wpkh_script.to_string()}")
    print(f"P2TR scriptPubKey: {p2tr_script.to_string()}")

Converting Between Address Types
-----------------------------

While there's no direct "convert" method, you can convert between address types using the intermediate objects:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PrivateKey, P2pkhAddress, P2wpkhAddress

    setup('testnet')

    # Start with a P2PKH address
    p2pkh_addr = P2pkhAddress('mzF2sbdxcMqKFLoakdBcvZpUXMjgiXGZW1')
    
    # To convert, first we'd need the underlying public key
    # In a real application, you'd have the private key
    private_key = PrivateKey('your_private_key_wif')
    public_key = private_key.get_public_key()
    
    # Now create different address types
    new_p2pkh_addr = public_key.get_address()
    p2wpkh_addr = public_key.get_segwit_address()
    p2tr_addr = public_key.get_taproot_address()

Address Validation
----------------

The library provides automatic validation when creating address objects:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import P2pkhAddress

    setup('testnet')

    # This will validate the address
    try:
        addr = P2pkhAddress('mzF2sbdxcMqKFLoakdBcvZpUXMjgiXGZW1')
        # Address is valid
        print(f"Address {addr.to_string()} is valid")
    except ValueError:
        # Address is invalid
        print("Invalid address provided")

Network-specific Addresses
------------------------

The library supports both mainnet and testnet addresses:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PrivateKey

    # For mainnet
    setup('mainnet')
    
    priv = PrivateKey()
    pub = priv.get_public_key()
    
    # Mainnet addresses
    mainnet_p2pkh = pub.get_address()
    mainnet_p2wpkh = pub.get_segwit_address()
    mainnet_p2tr = pub.get_taproot_address()
    
    print(f"Mainnet P2PKH: {mainnet_p2pkh.to_string()}")  # Starts with '1'
    print(f"Mainnet P2WPKH: {mainnet_p2wpkh.to_string()}") # Starts with 'bc1q'
    print(f"Mainnet P2TR: {mainnet_p2tr.to_string()}")    # Starts with 'bc1p'
    
    # For testnet
    setup('testnet')
    
    priv = PrivateKey()
    pub = priv.get_public_key()
    
    # Testnet addresses
    testnet_p2pkh = pub.get_address()
    testnet_p2wpkh = pub.get_segwit_address()
    testnet_p2tr = pub.get_taproot_address()
    
    print(f"Testnet P2PKH: {testnet_p2pkh.to_string()}")  # Starts with 'm' or 'n'
    print(f"Testnet P2WPKH: {testnet_p2wpkh.to_string()}")  # Starts with 'tb1q'
    print(f"Testnet P2TR: {testnet_p2tr.to_string()}")    # Starts with 'tb1p'
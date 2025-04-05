Script
======

The ``script`` module provides functionality for working with Bitcoin scripts, which are used to specify the conditions under which bitcoins can be spent.

Overview
--------

Bitcoin scripts are a stack-based programming language used to encode spending conditions in Bitcoin transactions. The script module implements a class for creating, manipulating, and converting Bitcoin scripts.

The main class is:

- ``Script``: Represents a Bitcoin script as a list of operations and data

Basic Usage
----------

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.script import Script
    
    # Always remember to setup the network
    setup('testnet')
    
    # Create a P2PKH scriptPubKey (locking script)
    scriptPubKey = Script(['OP_DUP', 'OP_HASH160', 
                          '751e76e8199196d454941c45d1b3a323f1433bd6', 
                          'OP_EQUALVERIFY', 'OP_CHECKSIG'])
    
    # Convert script to bytes
    script_bytes = scriptPubKey.to_bytes()
    
    # Convert script to hex
    script_hex = scriptPubKey.to_hex()
    
    print(f"Script (hex): {script_hex}")

Creating Scripts
--------------

The ``Script`` class provides various ways to create Bitcoin scripts:

.. code-block:: python

    # Standard P2PKH script
    p2pkh_script = Script(['OP_DUP', 'OP_HASH160', 
                           'hash160_of_public_key', 
                           'OP_EQUALVERIFY', 'OP_CHECKSIG'])
    
    # P2SH script
    p2sh_script = Script(['OP_HASH160', 'hash160_of_redeem_script', 'OP_EQUAL'])
    
    # Multi-signature script (2-of-3)
    multisig_script = Script(['OP_2', 
                             'public_key1_hex', 
                             'public_key2_hex', 
                             'public_key3_hex', 
                             'OP_3', 'OP_CHECKMULTISIG'])
    
    # P2WPKH script
    p2wpkh_script = Script(['OP_0', 'hash160_of_public_key'])
    
    # P2WSH script
    p2wsh_script = Script(['OP_0', 'sha256_of_witness_script'])
    
    # P2TR script
    p2tr_script = Script(['OP_1', 'tweaked_public_key_x_only'])
    
    # Timelock script
    timelock_script = Script(['blocknumber_or_timestamp', 'OP_CHECKLOCKTIMEVERIFY', 
                              'OP_DROP', 'OP_DUP', 'OP_HASH160',
                              'hash160_of_public_key', 
                              'OP_EQUALVERIFY', 'OP_CHECKSIG'])

Types of Script Elements
----------------------

Bitcoin scripts can contain different types of elements:

1. **OP codes**: These are the operation codes that perform stack manipulations or cryptographic operations
   
   .. code-block:: python
   
       # OP codes are represented as strings
       script = Script(['OP_DUP', 'OP_HASH160', 'OP_EQUALVERIFY', 'OP_CHECKSIG'])

2. **Data**: These can be hex-encoded strings representing binary data
   
   .. code-block:: python
   
       # Data is represented as hex strings
       script = Script(['OP_RETURN', 'deadbeef'])  # OP_RETURN followed by data

3. **Integers**: These are converted to the appropriate minimal representation
   
   .. code-block:: python
   
       # Integers from 0 to 16 can use OP_0 to OP_16
       script = Script(['OP_2', 'OP_3', 'OP_ADD'])  # Adds 2 and 3
       
       # Larger integers are pushed as data
       script = Script([42, 'OP_DROP'])  # Pushes 42 to stack, then drops it

Script Conversions
----------------

The ``Script`` class provides methods to convert scripts between different formats:

.. code-block:: python

    # Convert to bytes
    script_bytes = script.to_bytes()
    
    # Convert to hex
    script_hex = script.to_hex()
    
    # Get the original script array
    script_array = script.get_script()
    
    # Parse from raw hex (useful for parsing scripts from transactions)
    raw_script_hex = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
    parsed_script = Script.from_raw(raw_script_hex)
    
    # Create copies of scripts
    script_copy = Script.copy(script)

P2SH and P2WSH Conversions
------------------------

Scripts can be converted to P2SH and P2WSH formats for use in transactions:

.. code-block:: python

    # Convert a redeem script to a P2SH script
    redeem_script = Script(['OP_2', 'pubkey1', 'pubkey2', 'pubkey3', 'OP_3', 'OP_CHECKMULTISIG'])
    p2sh_script = redeem_script.to_p2sh_script_pub_key()
    
    # Convert a witness script to a P2WSH script
    witness_script = Script(['OP_2', 'pubkey1', 'pubkey2', 'pubkey3', 'OP_3', 'OP_CHECKMULTISIG'])
    p2wsh_script = witness_script.to_p2wsh_script_pub_key()

Address Generation from Scripts
----------------------------

Scripts can be used to generate Bitcoin addresses:

.. code-block:: python

    from bitcoinutils.keys import P2shAddress, P2wshAddress
    
    # Create P2SH address from redeem script
    redeem_script = Script(['OP_2', 'pubkey1', 'pubkey2', 'pubkey3', 'OP_3', 'OP_CHECKMULTISIG'])
    p2sh_address = P2shAddress.from_script(redeem_script)
    
    # Create P2WSH address from witness script
    witness_script = Script(['OP_2', 'pubkey1', 'pubkey2', 'pubkey3', 'OP_3', 'OP_CHECKMULTISIG'])
    p2wsh_address = P2wshAddress.from_script(witness_script)

Common Script Templates
--------------------

Here are some common script templates used in Bitcoin:

1. **Pay-to-Public-Key-Hash (P2PKH)**:
   
   .. code-block:: python
   
       # scriptPubKey (locking script)
       p2pkh_scriptPubKey = Script(['OP_DUP', 'OP_HASH160', 'hash160_of_public_key', 
                                   'OP_EQUALVERIFY', 'OP_CHECKSIG'])
       
       # scriptSig (unlocking script)
       p2pkh_scriptSig = Script(['signature', 'public_key'])

2. **Pay-to-Script-Hash (P2SH)**:
   
   .. code-block:: python
   
       # scriptPubKey (locking script)
       p2sh_scriptPubKey = Script(['OP_HASH160', 'hash160_of_redeem_script', 'OP_EQUAL'])
       
       # scriptSig (unlocking script) for a 2-of-3 multisig redeem script
       p2sh_scriptSig = Script(['OP_0', 'signature1', 'signature2', 
                               'serialized_redeem_script'])
       
       # Where serialized_redeem_script is the hex of:
       redeem_script = Script(['OP_2', 'pubkey1', 'pubkey2', 'pubkey3', 
                              'OP_3', 'OP_CHECKMULTISIG'])

3. **Pay-to-Witness-Public-Key-Hash (P2WPKH)**:
   
   .. code-block:: python
   
       # scriptPubKey (locking script)
       p2wpkh_scriptPubKey = Script(['OP_0', 'hash160_of_public_key'])
       
       # witness stack (not scriptSig):
       # [signature, public_key]

4. **Pay-to-Witness-Script-Hash (P2WSH)**:
   
   .. code-block:: python
   
       # scriptPubKey (locking script)
       p2wsh_scriptPubKey = Script(['OP_0', 'sha256_of_witness_script'])
       
       # witness stack for a 2-of-3 multisig witness script:
       # [OP_0, signature1, signature2, serialized_witness_script]
       
       # Where serialized_witness_script is the hex of:
       witness_script = Script(['OP_2', 'pubkey1', 'pubkey2', 'pubkey3', 
                               'OP_3', 'OP_CHECKMULTISIG'])

5. **Pay-to-Taproot (P2TR)**:
   
   .. code-block:: python
   
       # scriptPubKey (locking script)
       p2tr_scriptPubKey = Script(['OP_1', 'tweaked_public_key_x_only'])
       
       # Key path witness:
       # [signature]
       
       # Script path witness (for script A in a script tree):
       # [signature, script_A, control_block]

Working with OP_CODES
-------------------

The Script module provides access to all standard Bitcoin script OP_CODES. These operation codes are the building blocks of Bitcoin scripts:

.. code-block:: python

    # Accessing OP_CODES
    from bitcoinutils.script import Script
    
    # Constants
    script = Script(['OP_0', 'OP_1', 'OP_2', 'OP_16'])
    
    # Flow control
    script = Script(['OP_IF', 'OP_1', 'OP_ELSE', 'OP_0', 'OP_ENDIF'])
    
    # Stack operations
    script = Script(['OP_DUP', 'OP_DROP', 'OP_SWAP', 'OP_ROT'])
    
    # Bitwise logic
    script = Script(['OP_EQUAL', 'OP_EQUALVERIFY'])
    
    # Arithmetic
    script = Script(['OP_1ADD', 'OP_1SUB', 'OP_ADD', 'OP_SUB'])
    
    # Crypto
    script = Script(['OP_RIPEMD160', 'OP_SHA256', 'OP_HASH160', 'OP_CHECKSIG'])
    
    # Locktime
    script = Script(['OP_CHECKLOCKTIMEVERIFY', 'OP_CHECKSEQUENCEVERIFY'])

Advanced Script Examples
---------------------

Here are some more advanced script examples:

1. **Timelock Script** - This script can only be spent after a certain block height:

   .. code-block:: python
   
       # Can only be spent after block 650000
       timelock_script = Script([
           '00009e9c', # 650000 in little-endian hex
           'OP_CHECKLOCKTIMEVERIFY',
           'OP_DROP',
           'OP_DUP', 
           'OP_HASH160',
           'hash160_of_public_key',
           'OP_EQUALVERIFY',
           'OP_CHECKSIG'
       ])

2. **Hash Preimage** - This script can be spent by revealing a preimage to a hash:

   .. code-block:: python
   
       # Locking script
       hash_lock_script = Script([
           'OP_SHA256',
           'hash_of_secret',
           'OP_EQUAL'
       ])
       
       # Unlocking script (spend by revealing the secret)
       hash_unlock_script = Script(['secret_value'])

3. **Multi-signature with Timelock** - This script combines multisig with a timelock:

   .. code-block:: python
   
       # 2-of-3 multisig with a timelock (can't spend until block 650000)
       multisig_timelock_script = Script([
           '00009e9c', # 650000 in little-endian hex
           'OP_CHECKLOCKTIMEVERIFY',
           'OP_DROP',
           'OP_2',
           'pubkey1',
           'pubkey2',
           'pubkey3',
           'OP_3',
           'OP_CHECKMULTISIG'
       ])

4. **Relative Timelock** - This script can only be spent after a certain number of blocks since the UTXO was mined:

   .. code-block:: python
   
       # Can only be spent 144 blocks (approximately 1 day) after the UTXO was mined
       relative_timelock_script = Script([
           'OP_DUP',
           'OP_HASH160',
           'hash160_of_public_key',
           'OP_EQUALVERIFY',
           'OP_CHECKSIG',
           '9001', # 144 in little-endian hex with the most significant bit of the first byte set to 0
           'OP_CHECKSEQUENCEVERIFY',
           'OP_DROP'
       ])

Security Considerations
---------------------

When working with Bitcoin scripts, keep these security considerations in mind:

1. **Script Size Limits** - Bitcoin nodes have size limits for scripts. A standard redeem script can't exceed 520 bytes, and the combined size of all stack items can't exceed 10,000 bytes.

2. **Standard Scripts** - For a transaction to be relayed by most nodes, it must use standard script templates. Non-standard scripts may not be relayed by the network.

3. **OP_RETURN Data** - When storing data in the blockchain using OP_RETURN, the data is limited to 80 bytes.

4. **Stack Size** - Bitcoin script has a stack size limit of 1,000 items.

5. **Signature Verification** - CHECKSIG and CHECKMULTISIG operations are expensive. There's a limit on the number of signature checks per transaction.

6. **Taproot Considerations** - When using Taproot scripts, ensure you're constructing the script tree correctly for the intended spending paths.

Conclusion
---------

The Script module is a powerful tool for creating and manipulating Bitcoin scripts. It provides a simple, Python-based interface to Bitcoin's scripting language, allowing developers to create and use a wide variety of spending conditions in their Bitcoin applications.

For more advanced use cases, the module can be combined with the transactions and keys modules to create and sign complex Bitcoin transactions with custom scripts.
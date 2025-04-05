SegWit Functionality
==================

SegWit (Segregated Witness) is a Bitcoin protocol upgrade that separates transaction signatures from transaction data, resulting in several benefits such as increased transaction capacity and fixing transaction malleability.

The Python Bitcoin Utils library provides comprehensive support for SegWit, including both version 0 (P2WPKH, P2WSH) and version 1 (Taproot/P2TR).

SegWit Versions
--------------

The library supports different versions of SegWit:

* **SegWit v0**: Original SegWit implementation (P2WPKH and P2WSH)
* **SegWit v1**: Taproot update (P2TR)

Address Types
------------

Native SegWit Addresses
^^^^^^^^^^^^^^^^^^^^^^^

P2WPKH (Pay to Witness Public Key Hash)
""""""""""""""""""""""""""""""""""""""""

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PrivateKey

    setup('testnet')
    priv = PrivateKey()
    pub = priv.get_public_key()
    segwit_addr = pub.get_segwit_address()
    print(f"P2WPKH address: {segwit_addr.to_string()}")

P2WSH (Pay to Witness Script Hash)
""""""""""""""""""""""""""""""""""

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PublicKey
    from bitcoinutils.script import Script

    setup('testnet')
    pub1 = PublicKey("public_key_1_hex")
    pub2 = PublicKey("public_key_2_hex")

    # Create a 2-of-2 multisig redeem script
    redeem_script = Script([2, pub1.to_hex(), pub2.to_hex(), 2, 'OP_CHECKMULTISIG'])
    witness_script_addr = redeem_script.get_segwit_address()
    print(f"P2WSH address: {witness_script_addr.to_string()}")

Nested SegWit Addresses
^^^^^^^^^^^^^^^^^^^^^^^

P2SH-P2WPKH
"""""""""""

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PrivateKey

    setup('testnet')
    priv = PrivateKey()
    pub = priv.get_public_key()
    p2sh_p2wpkh_addr = pub.get_p2sh_p2wpkh_address()
    print(f"P2SH-P2WPKH address: {p2sh_p2wpkh_addr.to_string()}")

P2SH-P2WSH
""""""""""

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PublicKey
    from bitcoinutils.script import Script

    setup('testnet')
    pub1 = PublicKey("public_key_1_hex")
    pub2 = PublicKey("public_key_2_hex")

    # Create a 2-of-2 multisig redeem script
    redeem_script = Script([2, pub1.to_hex(), pub2.to_hex(), 2, 'OP_CHECKMULTISIG'])
    p2sh_p2wsh_addr = redeem_script.get_p2sh_p2wsh_address()
    print(f"P2SH-P2WSH address: {p2sh_p2wsh_addr.to_string()}")

Taproot Addresses (SegWit v1)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PrivateKey

    setup('testnet')
    priv = PrivateKey()
    pub = priv.get_public_key()
    taproot_addr = pub.get_taproot_address()
    print(f"P2TR address: {taproot_addr.to_string()}")

Creating SegWit Transactions
---------------------------

Sending to a P2WPKH Address
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PrivateKey, P2wpkhAddress
    from bitcoinutils.transactions import Transaction, TxInput, TxOutput

    setup('testnet')

    # Create a P2WPKH address to send to
    recipient_addr = P2wpkhAddress('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx')

    # Create transaction input (from a previous transaction)
    txin = TxInput('previous_tx_id', 0)

    # Create transaction output
    txout = TxOutput(0.001, recipient_addr.to_script_pub_key())

    # Create transaction
    tx = Transaction([txin], [txout])

    # Sign the transaction
    priv_key = PrivateKey('private_key_wif')
    sig = priv_key.sign_input(tx, 0, prev_script_pub_key)
    txin.script_sig = sig

    print(f"Signed transaction: {tx.serialize()}")

Spending from a P2WPKH Address
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PrivateKey, P2pkhAddress
    from bitcoinutils.transactions import Transaction, TxInput, TxOutput
    from bitcoinutils.script import Script

    setup('testnet')

    # Create a transaction input (from a P2WPKH UTXO)
    txin = TxInput('previous_tx_id', 0)

    # Create a P2PKH address to send to
    recipient_addr = P2pkhAddress('recipient_address')

    # Create transaction output
    txout = TxOutput(0.0009, recipient_addr.to_script_pub_key())

    # Create transaction
    tx = Transaction([txin], [txout])

    # For SegWit inputs, use sign_segwit_input instead of sign_input
    priv_key = PrivateKey('private_key_wif')
    pub_key = priv_key.get_public_key()
    script_code = Script(['OP_DUP', 'OP_HASH160', pub_key.to_hash160(), 'OP_EQUALVERIFY', 'OP_CHECKSIG'])

    # Sign the segwit input
    signature = priv_key.sign_segwit_input(tx, 0, script_code, 0.001)

    # Set witness data for the input
    txin.witness = [signature, pub_key.to_hex()]

    print(f"Signed transaction: {tx.serialize()}")

Taproot Transactions
-------------------

Key Path Spending
^^^^^^^^^^^^^^^^^

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PrivateKey, P2trAddress
    from bitcoinutils.transactions import Transaction, TxInput, TxOutput

    setup('testnet')

    # Create transaction input from a P2TR UTXO
    txin = TxInput('previous_tx_id', 0)

    # Create a transaction output
    recipient_addr = P2trAddress('recipient_taproot_address')
    txout = TxOutput(0.0009, recipient_addr.to_script_pub_key())

    # Create transaction
    tx = Transaction([txin], [txout])

    # Sign the taproot input using key path
    priv_key = PrivateKey('private_key_wif')
    signature = priv_key.sign_taproot_input(
        tx, 0, 
        [{'value': 0.001, 'scriptPubKey': prev_script_pub_key}]
    )

    # Set witness data for the input
    txin.witness = [signature]

    print(f"Signed transaction: {tx.serialize()}")

Script Path Spending
^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PrivateKey, PublicKey
    from bitcoinutils.transactions import Transaction, TxInput, TxOutput
    from bitcoinutils.script import Script

    setup('testnet')

    # Create transaction input from a P2TR UTXO
    txin = TxInput('previous_tx_id', 0)

    # Create a transaction output
    recipient_addr = P2pkhAddress('recipient_address')
    txout = TxOutput(0.0009, recipient_addr.to_script_pub_key())

    # Create transaction
    tx = Transaction([txin], [txout])

    # For script path spending, you need the taproot script
    tapscript = Script(['pub_key', 'OP_CHECKSIG'])
    
    # Sign the taproot input using script path
    priv_key = PrivateKey('private_key_wif')
    signature = priv_key.sign_taproot_input(
        tx, 0, 
        [{'value': 0.001, 'scriptPubKey': prev_script_pub_key}],
        script_path=True,
        tapleaf_script=tapscript
    )

    # Control block computation and witness setup would be handled internally
    # Set witness data for the input
    # Note: This is a simplified example. Actual witness data would include the
    # control block and the script.
    
    print(f"Signed transaction: {tx.serialize()}")

SegWit Transaction Digest
------------------------

The library uses different digest algorithms for signing SegWit transactions:

SegWit v0 Digest Algorithm
^^^^^^^^^^^^^^^^^^^^^^^^^

For SegWit v0, the `get_transaction_segwit_digest` method implements the BIP143 specification.

Taproot (SegWit v1) Digest Algorithm
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For Taproot (SegWit v1), the `get_transaction_taproot_digest` method implements the BIP341 specification.

Witness Structure
---------------

In SegWit transactions, the witness data is stored separately from the transaction inputs:

P2WPKH Witness
^^^^^^^^^^^^^

.. code-block:: 

    [signature, public_key]

P2WSH Witness
^^^^^^^^^^^^

.. code-block:: 

    [sig1, sig2, ..., sigN, redeem_script]

P2TR Key Path Witness
^^^^^^^^^^^^^^^^^^^

.. code-block:: 

    [signature]

P2TR Script Path Witness
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: 

    [sig1, sig2, ..., script, control_block]

Automatic Handling of Witness Data
--------------------------------

The library automatically provides the correct witness format for different types of inputs:

* For non-witness inputs in SegWit transactions, the library adds a '00' byte as required by the protocol
* For P2WPKH inputs, it creates a witness with signature and public key
* For P2WSH inputs, it creates a witness with signatures and the witness script
* For P2TR inputs, it creates a witness with one signature for key path spending, or signature, script and control block for script path spending

Mixed Input Transactions
----------------------

When creating transactions with both SegWit and non-SegWit inputs:

1. Each input needs its own specific signing method
2. For non-SegWit inputs, use `sign_input`
3. For SegWit v0 inputs, use `sign_segwit_input`
4. For Taproot inputs, use `sign_taproot_input`
5. Ensure witness data is correctly set for each input

.. code-block:: python

    # Example of a mixed input transaction
    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PrivateKey
    from bitcoinutils.transactions import Transaction, TxInput, TxOutput
    from bitcoinutils.script import Script

    setup('testnet')

    # Create transaction inputs
    # Non-SegWit input
    txin1 = TxInput('legacy_tx_id', 0)
    # SegWit v0 input
    txin2 = TxInput('segwit_v0_tx_id', 0)
    # Taproot input
    txin3 = TxInput('taproot_tx_id', 0)

    # Create transaction output
    recipient_addr = P2pkhAddress('recipient_address')
    txout = TxOutput(0.0027, recipient_addr.to_script_pub_key())

    # Create transaction
    tx = Transaction([txin1, txin2, txin3], [txout])

    # Sign each input with the appropriate method
    # Legacy input
    priv_key1 = PrivateKey('legacy_priv_key_wif')
    sig1 = priv_key1.sign_input(tx, 0, legacy_script_pub_key)
    txin1.script_sig = sig1

    # SegWit v0 input
    priv_key2 = PrivateKey('segwit_v0_priv_key_wif')
    pub_key2 = priv_key2.get_public_key()
    script_code2 = Script(['OP_DUP', 'OP_HASH160', pub_key2.to_hash160(), 'OP_EQUALVERIFY', 'OP_CHECKSIG'])
    sig2 = priv_key2.sign_segwit_input(tx, 1, script_code2, 0.001)
    txin2.witness = [sig2, pub_key2.to_hex()]

    # Taproot input
    priv_key3 = PrivateKey('taproot_priv_key_wif')
    sig3 = priv_key3.sign_taproot_input(
        tx, 2, 
        [
            {'value': 0.001, 'scriptPubKey': legacy_script_pub_key},
            {'value': 0.001, 'scriptPubKey': segwit_v0_script_pub_key},
            {'value': 0.001, 'scriptPubKey': taproot_script_pub_key}
        ]
    )
    txin3.witness = [sig3]

OP_CHECKSIGADD Support
--------------------

Taproot introduces the new OP_CHECKSIGADD opcode for more efficient threshold multi-signature scripts:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.script import Script

    setup('testnet')

    # Create a 2-of-3 multi-signature script using OP_CHECKSIGADD
    multi_sig_script = Script([
        'pub_key1', 'OP_CHECKSIG',
        'pub_key2', 'OP_CHECKSIGADD',
        'pub_key3', 'OP_CHECKSIGADD',
        '2', 'OP_EQUAL'
    ])

    # This is more efficient than the traditional way:
    traditional_multisig = Script([
        '2', 'pub_key1', 'pub_key2', 'pub_key3', '3', 'OP_CHECKMULTISIG'
    ])
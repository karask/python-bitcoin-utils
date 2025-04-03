Transactions
===========

The ``transactions`` module provides classes and methods for working with Bitcoin transactions. It includes functionality for creating, signing, and manipulating transactions.

Overview
--------

Bitcoin transactions consist of inputs and outputs. Inputs spend UTXOs (Unspent Transaction Outputs) from previous transactions, and outputs create new UTXOs. Each transaction also has additional metadata like version and locktime.

This module provides the following classes:

- ``TxInput``: Represents a transaction input
- ``TxWitnessInput``: Represents witness data for SegWit inputs
- ``TxOutput``: Represents a transaction output
- ``Sequence``: Helps setting up sequence numbers for various timelock options
- ``Locktime``: Helps setting up locktime values
- ``Transaction``: Represents a complete Bitcoin transaction

Basic Usage
----------

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.utils import to_satoshis
    from bitcoinutils.transactions import Transaction, TxInput, TxOutput
    from bitcoinutils.keys import PrivateKey, P2pkhAddress
    from bitcoinutils.script import Script

    # Always remember to setup the network
    setup('testnet')

    # Create transaction input from previous transaction
    txin = TxInput('previous_tx_id', 0)

    # Create transaction output
    addr = P2pkhAddress('n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR')
    txout = TxOutput(to_satoshis(0.1), addr.to_script_pub_key())

    # Create transaction with the input and output
    tx = Transaction([txin], [txout])

    # Sign transaction
    sk = PrivateKey('cSoXt6tHfMPPn8FVMh8dJHKVYGGVKgTQeUFCbUKvRsmQmJdqqHnJ')
    from_addr = P2pkhAddress('mgTAMEMGCk4iqMMLvfxgYvQWgEPVbR8WN2')
    sig = sk.sign_input(tx, 0, from_addr.to_script_pub_key())
    
    # Complete the transaction
    txin.script_sig = Script([sig, sk.get_public_key().to_hex()])
    signed_tx = tx.serialize()
    
    print(signed_tx)

Creating Transaction Inputs
--------------------------

The ``TxInput`` class represents an input in a transaction:

.. code-block:: python

    # Basic transaction input
    txin = TxInput('previous_tx_id', 0)
    
    # With custom script_sig
    script_sig = Script(['signature_hex', 'pubkey_hex'])
    txin = TxInput('previous_tx_id', 0, script_sig)
    
    # With custom sequence (for RBF or timelocks)
    txin = TxInput('previous_tx_id', 0, Script([]), 'fdffffff')

Transaction input fields:

- ``txid``: The transaction ID (hash) of the UTXO being spent
- ``txout_index``: The output index in the referenced transaction
- ``script_sig``: The unlocking script (signature script)
- ``sequence``: The sequence number (used for timelocks or replace-by-fee)

Creating Transaction Outputs
---------------------------

The ``TxOutput`` class represents an output in a transaction:

.. code-block:: python

    # Create transaction output using an address
    addr = P2pkhAddress('mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2')
    txout = TxOutput(to_satoshis(0.1), addr.to_script_pub_key())
    
    # Create transaction output with custom script
    script = Script(['OP_DUP', 'OP_HASH160', 'hash160_hex', 'OP_EQUALVERIFY', 'OP_CHECKSIG'])
    txout = TxOutput(to_satoshis(0.1), script)

Transaction output fields:

- ``amount``: The amount in satoshis
- ``script_pubkey``: The locking script (scriptPubKey)

Working with SegWit Transactions
-------------------------------

SegWit transactions require witness data for their inputs:

.. code-block:: python

    # Create a SegWit transaction
    txin = TxInput('previous_tx_id', 0)
    addr = P2wpkhAddress('tb1q9h0yjdupyfpxfjg24rpx755zvy0stu8h86225m')
    txout = TxOutput(to_satoshis(0.09), addr.to_script_pub_key())
    
    # Create the transaction with SegWit flag
    tx = Transaction([txin], [txout], has_segwit=True)
    
    # Create and add witness data
    witness = TxWitnessInput(['signature_hex', 'pubkey_hex'])
    tx.witnesses = [witness]
    
    # Get transaction hex
    tx_hex = tx.serialize()

Signing Transactions
------------------

The module provides methods for signing transaction inputs:

.. code-block:: python

    # Sign a standard P2PKH input
    sk = PrivateKey('private_key_wif')
    from_addr = P2pkhAddress('address')
    sig = sk.sign_input(tx, 0, from_addr.to_script_pub_key())
    txin.script_sig = Script([sig, sk.get_public_key().to_hex()])
    
    # Sign a SegWit input
    sig = sk.sign_segwit_input(tx, 0, redeem_script, input_amount)
    tx.witnesses = [TxWitnessInput([sig, sk.get_public_key().to_hex()])]
    
    # Sign a Taproot input
    sig = sk.sign_taproot_input(tx, 0, utxo_scripts, amounts)
    tx.witnesses = [TxWitnessInput([sig])]

Transaction Timelocks
--------------------

Timelocks allow creating transactions that can only be spent after a certain time:

.. code-block:: python

    # Create a transaction with absolute timelock (can't be mined until block 650000)
    locktime = Locktime(650000)
    tx = Transaction([txin], [txout], locktime=locktime.for_transaction())
    
    # Use relative timelock in an input (can't be mined until 10 blocks after the input was mined)
    sequence = Sequence(TYPE_RELATIVE_TIMELOCK, 10, is_type_block=True)
    txin = TxInput('previous_tx_id', 0, Script([]), sequence.for_input_sequence())

Replace-By-Fee (RBF)
-------------------

RBF allows replacing a transaction with a higher-fee version before it's confirmed:

.. code-block:: python

    # Create an input with RBF signal
    sequence = Sequence(TYPE_REPLACE_BY_FEE, 0)
    txin = TxInput('previous_tx_id', 0, Script([]), sequence.for_input_sequence())

Transaction Methods
-----------------

The ``Transaction`` class provides several useful methods:

- ``get_txid()``: Get the transaction ID (hash)
- ``get_wtxid()``: Get the witness transaction ID (hash including witness data)
- ``get_size()``: Get the transaction size in bytes
- ``get_vsize()``: Get the virtual size in vbytes (for fee calculation)
- ``to_hex()`` or ``serialize()``: Get the serialized transaction in hexadecimal
- ``from_raw()``: Create a transaction from raw hex data

Advanced Features
---------------

The module also supports:

1. **Parsing Transactions**: Create transaction objects from serialized hex data:

   .. code-block:: python
   
       # Parse a raw transaction
       raw_tx = "0200000001b021a77dcaad3a2..."
       tx = Transaction.from_raw(raw_tx)
       
       # Access transaction details
       print(f"Transaction ID: {tx.get_txid()}")
       print(f"Inputs: {len(tx.inputs)}")
       print(f"Outputs: {len(tx.outputs)}")

2. **Different Signature Hash Types**:

   .. code-block:: python
   
       # Sign with SIGHASH_ALL (default)
       sig = sk.sign_input(tx, 0, redeem_script, SIGHASH_ALL)
       
       # Sign with SIGHASH_NONE
       sig = sk.sign_input(tx, 0, redeem_script, SIGHASH_NONE)
       
       # Sign with SIGHASH_SINGLE
       sig = sk.sign_input(tx, 0, redeem_script, SIGHASH_SINGLE)
       
       # Sign with SIGHASH_ANYONECANPAY
       sig = sk.sign_input(tx, 0, redeem_script, SIGHASH_ALL | SIGHASH_ANYONECANPAY)

3. **Taproot Transactions**:

   .. code-block:: python
   
       # Create a Taproot transaction
       tx = Transaction([txin], [txout], has_segwit=True)
       
       # Sign for key-path spending
       sig = sk.sign_taproot_input(tx, 0, script_pubkeys, amounts)
       
       # Sign for script-path spending
       sig = sk.sign_taproot_input(tx, 0, script_pubkeys, amounts, 
                                  script_path=True, tapleaf_script=Script([...]))
Transactions
============

The transaction module provides low-level transaction objects:

* ``TxInput`` references a previous output.
* ``TxOutput`` carries an amount in satoshis and a locking script.
* ``TxWitnessInput`` stores a witness stack.
* ``Transaction`` serializes, parses, hashes, and builds signing digests.
* ``Sequence`` and ``Locktime`` help construct timelock values.

Constructing a Transaction
--------------------------

.. code-block:: python

   from bitcoinutils.transactions import Transaction, TxInput, TxOutput
   from bitcoinutils.keys import P2pkhAddress
   from bitcoinutils.utils import to_satoshis

   txin = TxInput("fb48f4e23bf6ddf606714141ac78c3e921c8c0bebeb7c8abb2c799e9ff96ce6c", 0)
   txout = TxOutput(to_satoshis(0.1), P2pkhAddress("n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR").to_script_pub_key())
   tx = Transaction([txin], [txout])

   print(tx.serialize())

Legacy Signing
--------------

For legacy inputs, pass the previous output's scriptPubKey to
``PrivateKey.sign_input`` and then place the signature and public key in
``script_sig``.

.. code-block:: python

   sig = private_key.sign_input(tx, 0, previous_script_pubkey)
   txin.script_sig = Script([sig, private_key.get_public_key().to_hex()])

SegWit Signing
--------------

For SegWit inputs, create the transaction with ``has_segwit=True``, pass the
spent amount to ``sign_segwit_input``, and put the signature stack in
``TxWitnessInput``.

.. code-block:: python

   tx = Transaction([txin], [txout], has_segwit=True)
   sig = private_key.sign_segwit_input(tx, 0, script_code, amount)
   tx.witnesses.append(TxWitnessInput([sig, private_key.get_public_key().to_hex()]))

Parsing Transactions
--------------------

.. code-block:: python

   parsed = Transaction.from_raw(tx.serialize())
   print(parsed.get_txid())
   print(parsed.get_size())

Timelocks and RBF
-----------------

Use ``Sequence`` for relative timelocks and replace-by-fee sequences, and
``Locktime`` for transaction-level locktime.

.. code-block:: python

   from bitcoinutils.constants import TYPE_RELATIVE_TIMELOCK
   from bitcoinutils.transactions import Sequence

   sequence = Sequence(TYPE_RELATIVE_TIMELOCK, 200).for_input_sequence()
   txin = TxInput(prev_txid, 0, sequence=sequence)

Examples
--------

.. literalinclude:: ../../examples/p2pkh_transaction.py
   :language: python
   :linenos:

.. literalinclude:: ../../examples/multi_input_sighash_transaction.py
   :language: python
   :linenos:

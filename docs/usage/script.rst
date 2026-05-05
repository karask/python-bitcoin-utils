Scripts
=======

``Script`` represents a Bitcoin script as a list of opcode names, integers, and
hex data pushes.

Creating Scripts
----------------

.. code-block:: python

   from bitcoinutils.script import Script

   p2pkh_script = Script([
       "OP_DUP",
       "OP_HASH160",
       "751e76e8199196d454941c45d1b3a323f1433bd6",
       "OP_EQUALVERIFY",
       "OP_CHECKSIG",
   ])

   print(p2pkh_script.to_hex())

Integers and Data Pushes
------------------------

Small integers ``0`` through ``16`` become ``OP_0`` through ``OP_16``. Larger
integers are encoded as script numbers. Hex strings are encoded using the
smallest valid pushdata opcode.

.. code-block:: python

   Script([2, "aa" * 33, "bb" * 33, 2, "OP_CHECKMULTISIG"])

Parsing and Copying
-------------------

.. code-block:: python

   raw = p2pkh_script.to_hex()
   parsed = Script.from_raw(raw)
   copied = Script.copy(parsed)

ScriptPubKey Helpers
--------------------

Scripts can be wrapped into P2SH or P2WSH scriptPubKeys:

.. code-block:: python

   redeem_script = Script(["02" + "11" * 32, "OP_CHECKSIG"])

   p2sh_script_pubkey = redeem_script.to_p2sh_script_pub_key()
   p2wsh_script_pubkey = redeem_script.to_p2wsh_script_pub_key()

Script Type Predicates
----------------------

The module provides helpers for common output patterns:

.. code-block:: python

   from bitcoinutils.script import is_p2pkh, is_p2sh, is_p2wpkh, is_p2wsh, is_p2tr

   assert is_p2pkh(p2pkh_script)

Example
-------

.. literalinclude:: ../../examples/create_non_std_tx.py
   :language: python
   :linenos:

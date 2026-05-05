Addresses
=========

Address classes live in :mod:`bitcoinutils.keys`.

Supported Types
---------------

* ``P2pkhAddress``: legacy pay-to-public-key-hash.
* ``P2shAddress``: pay-to-script-hash.
* ``P2wpkhAddress``: native SegWit v0 pay-to-witness-public-key-hash.
* ``P2wshAddress``: native SegWit v0 pay-to-witness-script-hash.
* ``P2trAddress``: Taproot, SegWit v1.

From Public Keys
----------------

.. code-block:: python

   from bitcoinutils.keys import PrivateKey

   priv = PrivateKey()
   pub = priv.get_public_key()

   legacy = pub.get_address()
   segwit = pub.get_segwit_address()
   taproot = pub.get_taproot_address()

   print(legacy.to_string())
   print(segwit.to_string())
   print(taproot.to_string())

From Scripts
------------

P2SH addresses can be built directly from a redeem script. P2WSH addresses are
built from a witness script:

.. code-block:: python

   from bitcoinutils.keys import P2shAddress, P2wshAddress
   from bitcoinutils.script import Script

   redeem_script = Script([pub.to_hex(), "OP_CHECKSIG"])

   p2sh_addr = P2shAddress.from_script(redeem_script)
   p2wsh_addr = P2wshAddress.from_script(redeem_script)

   print(p2sh_addr.to_string())
   print(p2wsh_addr.to_string())

From Existing Address Strings
-----------------------------

.. code-block:: python

   from bitcoinutils.keys import P2pkhAddress, P2wpkhAddress

   p2pkh = P2pkhAddress.from_address("n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR")
   p2wpkh = P2wpkhAddress.from_address("tb1qxmt9xgewg6mxc4mvnzvrzu4f2v0gy782fydg0w")

   print(p2pkh.to_hash160())
   print(p2wpkh.to_witness_program())

ScriptPubKeys
-------------

All address objects expose ``to_script_pub_key()``. Use it when constructing a
transaction output:

.. code-block:: python

   from bitcoinutils.transactions import TxOutput
   from bitcoinutils.utils import to_satoshis

   txout = TxOutput(to_satoshis(0.001), p2pkh.to_script_pub_key())

Example
-------

.. literalinclude:: ../../examples/keys_segwit_addresses.py
   :language: python
   :linenos:

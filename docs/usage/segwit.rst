SegWit
======

SegWit separates witness data from the transaction data used for the legacy
transaction id. The library supports native SegWit v0 outputs and nested
P2SH-SegWit outputs.

P2WPKH Addresses
----------------

.. code-block:: python

   from bitcoinutils.keys import PrivateKey

   pub = PrivateKey().get_public_key()
   address = pub.get_segwit_address()
   script_pubkey = address.to_script_pub_key()

Spending P2WPKH
---------------

For P2WPKH, the signing script code is the P2PKH template using the public key
hash.

.. literalinclude:: ../../examples/spend_p2wpkh_transaction.py
   :language: python
   :linenos:

Nested P2SH-P2WPKH
------------------

Nested SegWit spends use a P2SH scriptSig containing the redeem script and a
witness stack containing the signature and public key.

.. literalinclude:: ../../examples/spend_p2sh_p2wpkh_address.py
   :language: python
   :linenos:

P2WSH
-----

P2WSH spends use the witness script as the signing script and include it as the
last witness stack item.

.. literalinclude:: ../../examples/spend_p2wsh_to_p2wpkh.py
   :language: python
   :linenos:

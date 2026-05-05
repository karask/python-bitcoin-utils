Keys
====

Key objects are defined in :mod:`bitcoinutils.keys`.

Private Keys
------------

``PrivateKey`` can be created randomly, from WIF, from raw bytes, or from a
secret exponent:

.. code-block:: python

   from bitcoinutils.setup import setup
   from bitcoinutils.keys import PrivateKey

   setup("testnet")

   random_key = PrivateKey()
   wif_key = PrivateKey.from_wif("cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9")
   exponent_key = PrivateKey(secret_exponent=1)

   print(random_key.to_wif())
   print(wif_key.to_bytes().hex())
   print(exponent_key.get_public_key().to_hex())

Public Keys
-----------

``PublicKey`` accepts compressed SEC, uncompressed SEC, or x-only Taproot-style
hex strings.

.. code-block:: python

   from bitcoinutils.keys import PublicKey

   pub = PublicKey("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

   print(pub.to_hex())
   print(pub.to_hex(compressed=False))
   print(pub.to_x_only_hex())
   print(pub.to_hash160())

Message Signing
---------------

Bitcoin message signatures use the compact recoverable format. The library can
sign and verify them:

.. code-block:: python

   message = "The test!"
   signature = wif_key.sign_message(message)
   address = wif_key.get_public_key().get_address().to_string()

   assert signature is not None
   assert PublicKey.verify_message(address, signature, message)

Security Note
-------------

Private-key operations are pure Python and are not side-channel hardened.
Warnings are emitted on mainnet by default and can be disabled with:

.. code-block:: python

   from bitcoinutils.setup import set_security_warnings

   set_security_warnings(False)

Example
-------

.. literalinclude:: ../../examples/keys_addresses.py
   :language: python
   :linenos:

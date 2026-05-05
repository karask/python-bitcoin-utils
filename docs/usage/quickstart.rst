Quick Start
===========

Every script should first select a network:

.. code-block:: python

   from bitcoinutils.setup import setup

   setup("testnet")

Keys and Addresses
------------------

Create a private key, derive its public key, and render common address types:

.. code-block:: python

   from bitcoinutils.keys import PrivateKey

   private_key = PrivateKey()
   public_key = private_key.get_public_key()

   print(private_key.to_wif())
   print(public_key.to_hex())
   print(public_key.get_address().to_string())
   print(public_key.get_segwit_address().to_string())
   print(public_key.get_taproot_address().to_string())

Simple P2PKH Transaction
------------------------

The complete P2PKH example builds an unsigned transaction, signs one input, and
places the signature and public key in the input scriptSig:

.. literalinclude:: ../../examples/p2pkh_transaction.py
   :language: python
   :linenos:

Running Examples From the Checkout
----------------------------------

If you run examples directly from the repository, use ``PYTHONPATH=.`` so Python
imports the local checkout instead of an installed package:

.. code-block:: bash

   PYTHONPATH=. venv/bin/python examples/p2pkh_transaction.py

HD Wallets
==========

``bitcoinutils.hdwallet.HDWallet`` implements the small BIP-32/BIP-39 subset
used by the examples: derive private keys from a mnemonic or an extended
private key and return them as ``PrivateKey`` objects.

From a Mnemonic
---------------

.. code-block:: python

   from bitcoinutils.hdwallet import HDWallet

   mnemonic = "addict weather world sense idle purity rich wagon ankle fall cheese spatial"
   wallet = HDWallet.from_mnemonic(mnemonic)
   wallet.from_path("m/84'/1'/0'/0/0")

   private_key = wallet.get_private_key()
   print(private_key.get_public_key().get_segwit_address().to_string())

From an Extended Private Key
----------------------------

.. code-block:: python

   wallet = HDWallet.from_xprivate_key(tprv, "m/86'/1'/0'/0/0")
   print(wallet.get_private_key().get_public_key().get_taproot_address().to_string())

Paths
-----

Only absolute paths starting with ``m/`` are supported. Hardened components may
use ``'``, ``h``, or ``H``.

Common testnet examples:

* ``m/44'/1'/0'/0/0`` for legacy P2PKH intent.
* ``m/84'/1'/0'/0/0`` for native SegWit P2WPKH intent.
* ``m/86'/1'/0'/0/0`` for Taproot P2TR intent.

Example
-------

.. literalinclude:: ../../examples/hd_keys_detailed.py
   :language: python
   :linenos:

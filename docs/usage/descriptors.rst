Descriptors
===========

``bitcoinutils.descriptors`` implements a small educational subset of Bitcoin
Core output descriptors. It is intended to show how descriptor text maps to
scripts and addresses while still leaving transaction construction, fees,
change, and UTXO selection explicit.

Supported Forms
---------------

The first version supports fixed public keys and addresses:

* ``pk(KEY)``
* ``pkh(KEY)``
* ``wpkh(KEY)``
* ``sh(wpkh(KEY))``
* ``multi(k,KEY...)`` and ``sortedmulti(k,KEY...)``
* ``sh(multi(...))`` and ``sh(sortedmulti(...))``
* ``wsh(multi(...))`` and ``wsh(sortedmulti(...))``
* ``sh(wsh(multi(...)))`` and ``sh(wsh(sortedmulti(...)))``
* ``tr(KEY)`` for key-path Taproot
* ``addr(ADDRESS)``
* ``raw(HEX)``

Xpubs, derivation paths, wildcards, key-origin metadata, Miniscript, Taproot
script trees, ``combo``, MuSig2, and private keys are intentionally not
supported in this version.

Example
-------

.. code-block:: python

   from bitcoinutils.descriptors import parse_descriptor, add_descriptor_checksum

   desc = parse_descriptor(
       "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
   )

   print(desc.to_script_pub_key().to_hex())
   print(desc.to_address().to_string())
   print(add_descriptor_checksum(desc.to_string()))

Nested SegWit
-------------

.. code-block:: python

   native = parse_descriptor("wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)")
   nested = parse_descriptor("sh(wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798))")

   print(native.to_script_pub_key().to_hex())
   print(nested.to_script_pub_key().to_hex())

Checksums
---------

Descriptors may include Bitcoin Core compatible checksums:

.. code-block:: python

   desc = parse_descriptor("addr(mkmZxiEcEd8ZqjQWVZuC6so5dFMKEFpN2j)#02wpgw69", require_checksum=True)
   print(desc.validate_checksum())

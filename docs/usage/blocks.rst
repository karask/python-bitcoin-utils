Blocks
======

The block module parses Bitcoin block headers and full raw blocks.

Block Headers
-------------

``BlockHeader.from_raw`` accepts 80-byte header data as hex or bytes.

.. code-block:: python

   from bitcoinutils.block import BlockHeader

   header = BlockHeader.from_raw(raw_header_hex)
   print(header.get_block_hash())
   print(header.format_timestamp())
   print(header.get_target_hex())

Blocks
------

``Block.from_raw`` parses magic bytes, size, header, transaction count, and all
transactions.

.. code-block:: python

   from bitcoinutils.block import Block

   block = Block.from_raw(raw_block_hex)
   print(block.get_transactions_count())
   print(block.get_coinbase_transaction())

Example
-------

.. literalinclude:: ../../examples/block_parse.py
   :language: python
   :linenos:

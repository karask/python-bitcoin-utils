Bitcoin Core RPC Proxy
======================

``NodeProxy`` is a small wrapper around Bitcoin Core JSON-RPC. It is useful for
examples that need to query a local node or broadcast a raw transaction.

Basic Use
---------

.. code-block:: python

   from bitcoinutils.proxy import NodeProxy

   proxy = NodeProxy("bitcoinrpc", "password", host="127.0.0.1", port=18443)
   block_count = proxy.getblockcount()
   print(block_count)

Method Calls
------------

RPC methods are exposed dynamically. Calling ``proxy.getblockcount()`` maps to
the Bitcoin Core RPC method ``getblockcount``.

Example
-------

.. literalinclude:: ../../examples/node_proxy.py
   :language: python
   :linenos:

Bitcoin Utilities Documentation
===============================

``python-bitcoin-utils`` is a pure-Python educational library for building,
parsing, and signing Bitcoin data structures. It exposes low-level objects for
keys, addresses, scripts, transactions, PSBTs, blocks, HD derivation, and
Bitcoin Core RPC calls.

The library is intentionally close to the Bitcoin primitives. You usually build
objects directly, inspect their fields, serialize them, and pass them to the
next step. This documentation is organized the same way: start with workflows,
then use the API reference for exact methods and arguments.

Security Model
--------------

The private-key code is pure Python and intended for learning, tests, testnet,
and offline experimentation. ECDSA signing and Taproot/Schnorr signing are not
side-channel hardened. Do not use this library to protect real funds in
timing-observable environments.

On mainnet, the library emits a one-time warning when private-key operations
are used. Testnet, testnet4, signet, and regtest stay quiet so examples remain
usable in teaching material.

Getting Around
--------------

.. toctree::
   :maxdepth: 2
   :caption: User Guide

   usage/quickstart
   usage/keys
   usage/addresses
   usage/script
   usage/transactions
   usage/segwit
   usage/taproot
   usage/hdwallet
   usage/descriptors
   usage/psbt
   usage/blocks
   usage/proxy

.. toctree::
   :maxdepth: 2
   :caption: API Reference

   api/setup
   api/keys
   api/script
   api/transactions
   api/hdwallet
   api/descriptors
   api/psbt
   api/block
   api/utils
   api/proxy

Indices and Tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

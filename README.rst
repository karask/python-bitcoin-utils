python-bitcoin-utils
====================

This is a bitcoin library that provides tools/utilities to interact with the Bitcoin network. One of the primary goals of the library is to explain the low-level details of Bitcoin. The code is easy to read and properly documented explaining in detail all the thorny aspects of the implementation. It is a low-level library which assumes some high-level understanding of how Bitcoin works. In the future this might change.

This is an early version of the library (v0.5.8) and currently, it supports private/public keys, all type of addresses and creation of any transaction (incl. segwit) with all SIGHASH types. All script op codes are included. Timelock and non-standard transactions are supported. Currently, a simple node proxy exists to enable easy calls to a Bitcoin core node. Extra functionality will be added continuously and the documentation will be improved as the work progresses.

The API documentation can be build with Sphinx but is also available as a PDF for convenience. One can currently use the library for experimenting and learning the inner workings of Bitcoin. It is not meant for production yet and parts of the API might be updated with new versions.

Complementary to this library is a CC BY-SA 4.0 licensed `Bitcoin programming book <https://github.com/karask/bitcoin-textbook>`_.


Installation
------------
Python version 3 is required. Then just install with:

$ pip install bitcoin-utils

Examples
--------
Keys and Addresses
  https://github.com/karask/python-bitcoin-utils/blob/master/examples/keys_addresses.py - creates a private key which we use to derive a public key and in turn an address. We also use the private key to sign a message and then verify it using the public key. 

Segwit Addresses
  https://github.com/karask/python-bitcoin-utils/blob/master/examples/keys_segwit_addresses.py - creates P2WPKH, P2SH-P2WPKH, P2WSH and P2SH-P2WSH addresses.

Transaction with P2PKH input and outputs
  https://github.com/karask/python-bitcoin-utils/blob/master/examples/p2pkh_transaction.py - creates a simple transaction with one input and two outputs.

Create a P2PKH Transaction with different SIGHASHes
  https://github.com/karask/python-bitcoin-utils/blob/master/examples/multi_input_sighash_transaction.py - creates a 2-input 2-output transaction with different signature types.

Create a P2SH Address 
  https://github.com/karask/python-bitcoin-utils/blob/master/examples/send_to_p2sh_transaction.py - creates a P2SH address that corresponds to a P2PK redeem script and sends some funds to it.

Create (spent) a P2SH Transaction
  https://github.com/karask/python-bitcoin-utils/blob/master/examples/spend_p2sh_transaction.py - creates a transaction that spends a P2SH output.

Create a non-standard tx
  https://github.com/karask/python-bitcoin-utils/blob/master/examples/create_non_std_tx.py - sends funds to an address with a non-standard tx (script: OP_ADD OP_5 OP_EQUAL)

Spend a non-standard tx
  https://github.com/karask/python-bitcoin-utils/blob/master/examples/spend_non_std_tx.py - spends funds from script OP_ADD OP_5 OP_EQUAL 

Transaction to pay to a P2WPKH
  http://github.com/karask/python-bitcoin-utils/blob/master/examples/send_to_p2wpkh_transaction.py - send coins from two P2PKH UTXOs to a native segwit address (P2WPKH)

Spend from a P2SH(P2WPKH) nested segwit address
   http://github.com/karask/python-bitcoin-utils/blob/master/examples/spend_p2sh_p2wpkh_address.py - spend a P2WPKH that is nested into a P2SH for old client compatibility

Create a P2SH address with a relative timelock
  https://github.com/karask/python-bitcoin-utils/blob/master/examples/create_p2sh_csv_p2pkh_address.py - creates a P2SH address that locks funds (sent to it) with a private key (P2PKH) and a relative locktime of 200 blocks in the future.

Spend from a timelocked address
  https://github.com/karask/python-bitcoin-utils/blob/master/examples/spend_p2sh_csv_p2pkh.py - spends from a P2SH(CSV+P2PKH) address as created from above.

Use NodeProxy to make calls to a Bitcoin node
  https://github.com/karask/python-bitcoin-utils/blob/master/examples/node_proxy.py - make Bitcoin command-line interface calls programmatically (NodeProxy wraps jsonrpc-requests library)

Please explore the codebase or the API documentation (BitcoinUtilities.pdf) for supported functionality and other options.

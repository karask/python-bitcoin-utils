python-bitcoin-utils
====================
This is a bitcoin library that provides tools/utilities to interact with the Bitcoin network. One of the primary goals of the library is to explain the low-level details of Bitcoin. The code is easy to read and properly documented explaining in detail all the thorny aspects of the implementation. It is a low-level library which assumes some high-level understanding of how Bitcoin works. In the future this might change.

This is an early version of the library (v0.1.3) and currently, it only supports private/public keys, addresses and creation of P2PKH and P2SH transactions (with all SIGHASH types). All script op codes are included and non-standanrd transactions where tested. More functionality will be added continuously and the documentation will be improved as the work progresses.

The API documentation can be build with Sphinx but is also available as a PDF for convenience. One can currently use the library for experimenting and learning the inner workings of Bitcoin. It is not meant for production yet and parts of the API might be updated with new versions.



Installation
------------
$ pip install bitcoin-utils

Examples
--------
Keys and Addresses
  https://github.com/karask/python-bitcoin-utils/blob/master/examples/keys_addresses.py - creates a private key which we use to derive a public key and in turn an address. We also use the private key to sign a message and then verify it using the public key. 

Create a P2PKH Transaction
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


Please explore the code base or the API documentation (BitcoinUtilities.pdf) for supported functionality and other options.

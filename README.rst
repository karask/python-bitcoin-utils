python-bitcoin-utils
====================
This is a bitcoin library that provides tools/utilities to interact with the Bitcoin network. One of the primary goals of the library is to be explain the low-level details of Bitcoin. The code is easy to read and properly documented explaining in detail all the thorny aspects of the implementation. It is a low-level library which assumes some high-level understanding of how Bitcoin works. In the future this might change.

This is a very early version of the library (v0.0.2) and currently, it only supports private/public keys, addresses and creation of P2PKH transactions. More functionality will be added continuously and the documentation will be improved as the work progresses.

The API documentation can be build with Sphinx but is also available as a PDF for convenience. One can currently use the library for experimenting and learning the inner workings of Bitcoin. It is not meant for production yet and parts of the API might be updated with new versions.



Installation
------------
$ pip install bitcoin-utils

Keys and Addresses Examples
---------------------------
Please explore the API documentation for supported functionality.

Creates a private key which we use to derive a public key and in turn an address. We also use the private key to sign a message and then verify it using the public key.

>>> from bitcoinutils.keys import PrivateKey, PublicKey
>>> from bitcoinutils.setup import setup, get_network
>>> setup('mainnet')
'mainnet'
>>> p = PrivateKey()
>>> p.to_wif()
'KzT6YYySK8Ex2gd9FMzCgh6mzvjZTnVxqCj1hthPPbbCcssetKES'
>>> pubkey = p.get_public_key()
>>> pubkey.to_hex()
'027bf63dee798c197fad5ca05c45904a7c055e035c5f7c6e7aac8d615722f095c5'
>>> pubkey.to_hex(False)
'047bf63dee798c197fad5ca05c45904a7c055e035c5f7c6e7aac8d615722f095c5904ec20ead4e1992f76f6acf1f1e422708a81550fa5fd698b6cad981a3fcc34a'
>>> a = pubkey.get_address()
>>> a.to_hash160()
'efb37b3bc9c9510242be7f8230c0dec1df6cd220'
>>> a.to_address()
'1NrRWS5m4yySU5RdZxnu85tNEcsFaGfVZc'
>>> s = p.sign_message('test')
>>> s
'H3YyRNVNwyiuM9gk2P1fyR8OghhHoK4EKc1iXywNwdgQeYujAiOwhHHKBjtuAa22TGza1sNq3NXX+kZ1/41zAso='
>>> PublicKey.verify_message(a.to_address(), s, 'test')
True


Create P2PKH Transaction
------------------------
Please explore the API documentation for supported functionality.

Creates a simple transaction with one input and two outputs.

>>> from bitcoinutils.setup import setup, get_network
>>> from bitcoinutils.transactions import Transaction, TxInput, TxOutput
>>> from bitcoinutils.keys import Address, PrivateKey
>>> setup('testnet')
'testnet'
>>> txin = TxInput('fb48f4e23bf6ddf606714141ac78c3e921c8c0bebeb7c8abb2c799e9ff96ce6c', 0)
>>> addr = Address('n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR')
>>> txout = TxOutput(0.1, ['OP_DUP', 'OP_HASH160', addr.to_hash160(), 'OP_EQUALVERIFY', 'OP_CHECKSIG']    )
>>> change_addr = Address('mmYNBho9BWQB2dSniP1NJvnPoj5EVWw89w')
>>> change_txout = TxOutput(0.29, ['OP_DUP', 'OP_HASH160', change_addr.to_hash160(), 'OP_EQUALVERIFY',     'OP_CHECKSIG'])
>>> tx = Transaction([txin], [txout, change_txout])
>>> print(tx.serialize())
02000000016cce96ffe999c7b2abc8b7bebec0c821e9c378ac41417106f6ddf63be2f448fb0000000000ffffffff0280969800000000001976a914fd337ad3bf81e086d96a68e1f8d6a0a510f8c24a88ac4081ba01000000001976a91442151d0c21442c2b038af0ad5ee64b9d6f4f4e4988ac00000000
>>> sk = PrivateKey('cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9')
>>> from_addr = Address('myPAE9HwPeKHh8FjKwBNBaHnemApo3dw6e')
>>> sig = sk.sign_input(tx, 0, ['OP_DUP', 'OP_HASH160', from_addr.to_hash160(), 'OP_EQUALVERIFY', 'OP_CHECKSIG'])
>>> pk = sk.get_public_key()
>>> pk = pk.to_hex()
>>> txin.script_sig = [sig, pk]
>>> signed_tx = tx.serialize()
>>> print(signed_tx)
02000000016cce96ffe999c7b2abc8b7bebec0c821e9c378ac41417106f6ddf63be2f448fb000000006a473044022044ef433a24c6010a90af14f7739e7c60ce2c5bc3eab96eaee9fbccfdbb3e272202205372a617cb235d0a0ec2889dbfcadf15e10890500d184c8dda90794ecdf79492012103a2fef1829e0742b89c218c51898d9e7cb9d51201ba2bf9d9e9214ebb6af32708ffffffff0280969800000000001976a914fd337ad3bf81e086d96a68e1f8d6a0a510f8c24a88ac4081ba01000000001976a91442151d0c21442c2b038af0ad5ee64b9d6f4f4e4988ac00000000



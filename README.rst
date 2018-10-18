python-bitcoin-utils
====================
This is a bitcoin library that provides tools/utilities to interact with the Bitcoin network. One of the primary goals of the library is to be educational. The code is easy to read and properly documented explaining in detail all the thorny aspects of the implementation.

Currently, only a module that provides access to private/public keys and addresses is available.

Installation
------------
$ pip install python-bitcoin-utils

Example usage
-------------
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



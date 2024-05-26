# Copyright (C) 2018-2024 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.


from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey, PublicKey


def main():
    # always remember to setup the network
    setup("mainnet")

    # create a private key (deterministically)
    priv = PrivateKey(secret_exponent=1)

    # compressed is the default
    print("\nPrivate key WIF:", priv.to_wif(compressed=True))

    # could also instantiate from existing WIF key
    # priv = PrivateKey.from_wif('KwDiBf89qGgbjEhKnhxjUh7LrciVRzI3qYjgd9m7Rfu73SvHnOwn')

    # get the public key
    pub = priv.get_public_key()

    # compressed is the default
    print("Public key:", pub.to_hex(compressed=True))

    # get address from public key
    address = pub.get_address()

    # print the address and hash160 - default is compressed address
    print("Address:", address.to_string())
    print("Hash160:", address.to_hash160())

    print("\n--------------------------------------\n")

    # sign a message with the private key and verify it
    message = "The test!"
    signature = priv.sign_message(message)
    assert signature is not None
    print("The message to sign:", message)
    print("The signature is:", signature)

    if PublicKey.verify_message(address.to_string(), signature, message):
        print("The signature is valid!")
    else:
        print("The signature is NOT valid!")


if __name__ == "__main__":
    main()

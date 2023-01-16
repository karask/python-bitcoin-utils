# Copyright (C) 2018-2022 The python-bitcoin-utils developers
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
from bitcoinutils.script import Script
from bitcoinutils.keys import P2trAddress, PrivateKey, PublicKey

def main():
    # always remember to setup the network
    setup('testnet')

    # could also instantiate from existing WIF key
    priv = PrivateKey.from_wif('cVdte9ei2xsVjmZSPtyucG43YZgNkmKTqhwiUA8M4Fc3LdPJxPmZ')

    # compressed is the default
    print("\nPrivate key WIF:", priv.to_wif())

    # get the public key
    pub = priv.get_public_key()

    # compressed is the default
    print("Public key:", pub.to_hex())

    # get address from public key
    address = pub.get_taproot_address()

    # print the address and hash - default is compressed address
    print("Native Address:", address.to_string())
    taproot_pk = address.to_hash()
    print("Taproot public key:", taproot_pk)
    print("Segwit Version:", address.get_type())

    # test to_string
    addr2 = P2trAddress.from_hash(taproot_pk)
    print("Created P2trAddress from public key and calculate address:")
    print("Native Address:", addr2.to_string())


if __name__ == "__main__":
    main()


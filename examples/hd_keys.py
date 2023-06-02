# Copyright (C) 2018-2023 The python-bitcoin-utils developers
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
from bitcoinutils.hdwallet import HDWallet

def main():
    # always remember to setup the network
    setup('testnet')

    # get an HDWallet wrapper object by extended private key and path
    xprivkey = "tprv8ZgxMBicQKsPdQR9RuHpGGxSnNq8Jr3X4WnT6Nf2eq7FajuXyBep5KWYpYEixxx5XdTm1Ntpe84f3cVcF7mZZ7mPkntaFXLGJD2tS7YJkWU"
    path = "m/86'/1'/0'/0/1"
    hdw = HDWallet(xprivkey, path)

    print('Ext. private key:', xprivkey)
    print('Derivation path:', path)

    # get a PrivateKey object used in bitcoinutils throughout
    privkey = hdw.get_private_key()
    print('WIF:', privkey.to_wif())

    # get public key
    pubkey = privkey.get_public_key()
    print('Pubkey:', pubkey.to_hex())

    # get legacy address
    addr1 = pubkey.get_address()
    print('Legacy address:', addr1.to_string() )

    # get segwit v0 address
    addr2 = pubkey.get_segwit_address()
    print('Segwit address:', addr2.to_string() )

    # get taproot (segwit v1) address
    addr3 = pubkey.get_taproot_address()
    print('Taproot address:', addr3.to_string() )

    new_path = "m/86'/1'/0'/0/5"
    hdw.from_path(new_path)
    print('\n\nNew derivation path:', new_path)

    # get a PrivateKey object used in bitcoinutils throughout
    privkey = hdw.get_private_key()
    print('WIF:', privkey.to_wif())

    # get public key
    pubkey = privkey.get_public_key()
    print('Pubkey:', pubkey.to_hex())

    # get legacy address
    addr1 = pubkey.get_address()
    print('Legacy address:', addr1.to_string() )

    # get segwit v0 address
    addr2 = pubkey.get_segwit_address()
    print('Segwit address:', addr2.to_string() )

    # get taproot (segwit v1) address
    addr3 = pubkey.get_taproot_address()
    print('Taproot address:', addr3.to_string() )


if __name__ == "__main__":
    main()


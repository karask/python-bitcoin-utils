# Copyright (C) 2018-2020 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the
# top-level directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied,
# modified, propagated, or distributed except according to the terms
# contained in the LICENSE file.

from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, Sequence
from bitcoinutils.keys import P2pkhAddress, P2shAddress, PrivateKey
from bitcoinutils.script import Script
from bitcoinutils.constants import TYPE_RELATIVE_TIMELOCK


def main():
    # always remember to setup the network
    setup('testnet')

    #
    # This script creates a P2SH address containing a CHECKSEQUENCEVERIFY plus
    # a P2PKH locking funds with a key as well as for 20 blocks
    #

    # set values
    relative_blocks = 20

    seq = Sequence(TYPE_RELATIVE_TIMELOCK, relative_blocks)

    # secret key corresponding to the pubkey needed for the P2SH (P2PKH) transaction
    p2pkh_sk = PrivateKey('cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9')

    # get the address (from the public key)
    p2pkh_addr = p2pkh_sk.get_public_key().get_address()

    # create the redeem script
    redeem_script = Script([seq.for_script(), 'OP_CHECKSEQUENCEVERIFY', 'OP_DROP', 'OP_DUP', 'OP_HASH160', p2pkh_addr.to_hash160(), 'OP_EQUALVERIFY', 'OP_CHECKSIG'])

    # create a P2SH address from a redeem script
    addr = P2shAddress.from_script(redeem_script)
    print(addr.to_string())

if __name__ == "__main__":
    main()


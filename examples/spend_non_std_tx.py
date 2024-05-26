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
from bitcoinutils.utils import to_satoshis
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import P2pkhAddress
from bitcoinutils.script import Script


#
# Note that a non-standard transaction can only be included in a block if a
# miner agrees with it. For this to work one needs to use a node setup up
# for regtest so that you can mine your own blocks; unless you mine your own
# testnet/mainnet blocks.
# Node's config file requires:
#    regtest=1
#    acceptnonstdtxn=1
#
def main():
    # always remember to setup the network
    setup("regtest")

    # create transaction input from tx id of UTXO (contained 0.4 tBTC)
    txin = TxInput(
        "4d9a6baf45d4b57c875fe83d5e0834568eae4b5ef6e61d13720ef6685168e663", 0
    )
    # provide unlocking script
    # note that no signing is required to unlock: OP_ADD OP_5 OP_EQUAL
    txin.script_sig = Script(["OP_2", "OP_3"])

    # create transaction output using P2PKH scriptPubKey (locking script)
    addr = P2pkhAddress("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r")
    # locking script expects 2 numbers that when added equal 5 (silly example)
    txout = TxOutput(to_satoshis(0.8), addr.to_script_pub_key())

    # create transaction from inputs/outputs -- default locktime is used
    tx = Transaction([txin], [txout])

    # print raw transaction
    print("\nRaw transaction:\n" + tx.serialize())


if __name__ == "__main__":
    main()

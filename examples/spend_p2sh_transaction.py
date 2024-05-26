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
from bitcoinutils.keys import P2pkhAddress, PrivateKey
from bitcoinutils.script import Script


def main():
    # always remember to setup the network
    setup("testnet")

    #
    # This script spends from a P2SH address containing a P2PK script
    #

    # create transaction input from tx id of UTXO (contained 0.1 tBTC)
    txin = TxInput(
        "7db363d5a7fabb64ccce154e906588f1936f34481223ea8c1f2c935b0a0c945b", 0
    )

    # secret key needed to spend P2PK that is wrapped by P2SH
    p2pk_sk = PrivateKey("cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9")
    p2pk_pk = p2pk_sk.get_public_key().to_hex()
    # create the redeem script - needed to sign the transaction
    redeem_script = Script([p2pk_pk, "OP_CHECKSIG"])

    to_addr = P2pkhAddress("n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR")
    txout = TxOutput(to_satoshis(0.09), to_addr.to_script_pub_key())

    # no change address - the remaining 0.01 tBTC will go to miners)

    # create transaction from inputs/outputs -- default locktime is used
    tx = Transaction([txin], [txout])

    # print raw transaction
    print("\nRaw unsigned transaction:\n" + tx.serialize())

    # use the private key corresponding to the address that contains the
    # UTXO we are trying to spend to create the signature for the txin -
    # note that the redeem script is passed to replace the scriptSig
    sig = p2pk_sk.sign_input(tx, 0, redeem_script)
    # print(sig)

    # set the scriptSig (unlocking script)
    txin.script_sig = Script([sig, redeem_script.to_hex()])
    signed_tx = tx.serialize()

    # print raw signed transaction ready to be broadcasted
    print("\nRaw signed transaction:\n" + signed_tx)
    print("\nTxId:", tx.get_txid())


if __name__ == "__main__":
    main()

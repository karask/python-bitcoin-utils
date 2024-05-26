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
from bitcoinutils.constants import SIGHASH_ALL, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY


def main():
    # always remember to setup the network
    setup("testnet")

    # create transaction input from tx id of UTXO (contained 0.39 tBTC)
    # 0.1 tBTC
    txin = TxInput(
        "76464c2b9e2af4d63ef38a77964b3b77e629dddefc5cb9eb1a3645b1608b790f", 0
    )
    # 0.29 tBTC
    txin2 = TxInput(
        "76464c2b9e2af4d63ef38a77964b3b77e629dddefc5cb9eb1a3645b1608b790f", 1
    )

    # create transaction output using P2PKH scriptPubKey (locking script)
    addr = P2pkhAddress("myPAE9HwPeKHh8FjKwBNBaHnemApo3dw6e")
    txout = TxOutput(
        to_satoshis(0.3),
        Script(
            ["OP_DUP", "OP_HASH160", addr.to_hash160(), "OP_EQUALVERIFY", "OP_CHECKSIG"]
        ),
    )

    # create another output to get the change - remaining 0.01 is tx fees
    change_addr = P2pkhAddress("mmYNBho9BWQB2dSniP1NJvnPoj5EVWw89w")
    change_txout = TxOutput(
        to_satoshis(0.08),
        Script(
            [
                "OP_DUP",
                "OP_HASH160",
                change_addr.to_hash160(),
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ]
        ),
    )

    # create transaction from inputs/outputs -- default locktime is used
    tx = Transaction([txin, txin2], [txout, change_txout])

    # print raw transaction
    print("\nRaw unsigned transaction:\n" + tx.serialize())

    #
    # use the private keys corresponding to the addresses that contains the
    # UTXOs we are trying to spend to create the signatures
    #

    sk = PrivateKey("cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo")
    sk2 = PrivateKey("cVf3kGh6552jU2rLaKwXTKq5APHPoZqCP4GQzQirWGHFoHQ9rEVt")

    # we could have derived the addresses from the secret keys
    from_addr = P2pkhAddress("n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR")
    from_addr2 = P2pkhAddress("mmYNBho9BWQB2dSniP1NJvnPoj5EVWw89w")

    # sign the first input
    sig = sk.sign_input(
        tx,
        0,
        Script(
            [
                "OP_DUP",
                "OP_HASH160",
                from_addr.to_hash160(),
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ]
        ),
        SIGHASH_ALL | SIGHASH_ANYONECANPAY,
    )
    # print(sig)

    # sign the second input
    sig2 = sk2.sign_input(
        tx,
        1,
        Script(
            [
                "OP_DUP",
                "OP_HASH160",
                from_addr2.to_hash160(),
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ]
        ),
        SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
    )
    # print(sig2)

    # get public key as hex
    pk = sk.get_public_key()
    pk = pk.to_hex()
    # print (pk)

    # get public key as hex
    pk2 = sk2.get_public_key()
    pk2 = pk2.to_hex()

    # set the scriptSig (unlocking script)
    txin.script_sig = Script([sig, pk])
    txin2.script_sig = Script([sig2, pk2])
    signed_tx = tx.serialize()

    # print raw signed transaction ready to be broadcasted
    print("\nRaw signed transaction:\n" + signed_tx)
    print("\nTxId:", tx.get_txid())


if __name__ == "__main__":
    main()

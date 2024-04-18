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
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.keys import PrivateKey, P2wshAddress
from bitcoinutils.script import Script


def main():
    # always remember to setup the network
    setup("testnet")

    priv0 = PrivateKey("cN1XE3ESGgdvr4fWsB7L3BcqXncUauF8Fo8zzv4Sm6WrkiGrsxrG")

    pub = priv0.get_public_key()
    fromAddress = pub.get_segwit_address()

    priv1 = PrivateKey("cN1XE3ESGgdvr4fWsB7L3BcqXncUauF8Fo8zzv4Sm6WrkiGrsxrG")

    # P2SH Script: OP_M <Public key 1> <Public key 2> ... OP_N OP_CHECKMULTISIG
    p2sh_redeem_script = Script(
        ["OP_1", priv1.get_public_key().to_hex(), "OP_1", "OP_CHECKMULTISIG"]
    )

    toAddress = P2wshAddress.from_script(p2sh_redeem_script)

    # set values
    txid = "d222d91e2da368ac38e84aa615c557e4caeacce02aa5dbca10d840fd460fc938"
    vout = 0
    amount = to_satoshis(0.01764912)

    # create transaction input from tx id of UTXO
    txin = TxInput(txid, vout)
    redeem_script1 = Script(
        [
            "OP_DUP",
            "OP_HASH160",
            priv0.get_public_key().to_hash160(),
            "OP_EQUALVERIFY",
            "OP_CHECKSIG",
        ]
    )

    # create transaction output
    txOut1 = TxOutput(to_satoshis(0.0001), toAddress.to_script_pub_key())
    txOut2 = TxOutput(to_satoshis(0.01744912), fromAddress.to_script_pub_key())

    # create transaction
    tx = Transaction([txin], [txOut1, txOut2], has_segwit=True)

    print("\nRaw transaction:\n" + tx.serialize())

    sig1 = priv0.sign_segwit_input(tx, 0, redeem_script1, amount)

    # note that TxWitnessInput gets a list of witness items (not script opcodes)
    tx.witnesses.append(TxWitnessInput([sig1, pub.to_hex()]))

    # print raw signed transaction ready to be broadcasted
    print("\nRaw signed transaction:\n" + tx.serialize())
    print("\nTxId:", tx.get_txid())


if __name__ == "__main__":
    main()

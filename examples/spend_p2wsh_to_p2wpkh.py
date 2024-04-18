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
from bitcoinutils.keys import PrivateKey, P2wshAddress, P2wpkhAddress
from bitcoinutils.script import Script


def main():
    # always remember to setup the network
    setup("testnet")

    priv1 = PrivateKey("cN1XE3ESGgdvr4fWsB7L3BcqXncUauF8Fo8zzv4Sm6WrkiGrsxrG")
    priv2 = PrivateKey("cR8AkcbL2pgBswrHp28AftEznHPPLA86HiTog8MpNCibxwrsUcZ4")

    p2wsh_witness_script = Script(
        [
            "OP_1",
            priv1.get_public_key().to_hex(),
            priv2.get_public_key().to_hex(),
            "OP_2",
            "OP_CHECKMULTISIG",
        ]
    )

    fromAddress = P2wshAddress.from_script(p2wsh_witness_script)

    toAddress = P2wpkhAddress.from_address("tb1qtstf97nhk2gycz7vl37esddjpxwt3ut30qp5pn")

    # set values
    txid = "2042195c40a92353f2ffe30cd0df8d177698560e81807e8bf9174a9c0e98e6c2"
    vout = 0
    amount = to_satoshis(0.01)

    # create transaction input from tx id of UTXO
    txin = TxInput(txid, vout)

    txOut1 = TxOutput(to_satoshis(0.0001), toAddress.to_script_pub_key())
    txOut2 = TxOutput(to_satoshis(0.0098), fromAddress.to_script_pub_key())

    tx = Transaction([txin], [txOut1, txOut2], has_segwit=True)

    sig1 = priv1.sign_segwit_input(tx, 0, p2wsh_witness_script, amount)

    # note that TxWitnessInput gets a list of witness items (not script opcodes)
    tx.witnesses.append(TxWitnessInput(["", sig1, p2wsh_witness_script.to_hex()]))

    # print raw signed transaction ready to be broadcasted
    print("\nRaw signed transaction:\n" + tx.serialize())
    print("\nTxId:", tx.get_txid())


if __name__ == "__main__":
    main()

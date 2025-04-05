# Copyright (C) 2018-2025 The python-bitcoin-utils developers
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
from bitcoinutils.keys import P2pkhAddress, PrivateKey
from bitcoinutils.script import Script


def main():
    # always remember to setup the network
    setup("testnet")

    # the key that corresponds to the P2WPKH address
    priv1 = PrivateKey("cV3R88re3AZSBnWhBBNdiCKTfwpMKkYYjdiR13HQzsU7zoRNX7JL")
    priv2 = PrivateKey("cSfna7riKJdNU7skpRUx17WYANNsyHTA2FmuzLpFzpp37xpytgob")
    priv3 = PrivateKey("cNxX8M7XU8VNa5ofd8yk1eiZxaxNrQQyb7xNpwAmsrzEhcVwtCjs")

    pub1 = priv1.get_public_key()
    pub2 = priv2.get_public_key()
    pub3 = priv3.get_public_key()

    fromAddress1 = pub1.get_taproot_address()
    fromAddress2 = pub2.get_address()
    fromAddress3 = pub3.get_taproot_address()
    print(fromAddress1.to_string())
    print(fromAddress2.to_string())
    print(fromAddress3.to_string())

    # UTXO of fromAddress's respectively
    txid1 = "7b6412a0eed56338731e83c606f13ebb7a3756b3e4e1dbbe43a7db8d09106e56"
    vout1 = 1
    txid2 = "99fb66cbc26a2d1a5a03c3d00118fd370a37a29fb368817dde3b8b50920cd4dc"
    vout2 = 1
    txid3 = "2a28f8bd8ba0518a86a390da310073a30b7df863d04b42a9c487edf3a8b113af"
    vout3 = 1

    # all amounts are needed to sign a taproot input
    # (depending on sighash)
    amount1 = to_satoshis(0.00005)
    amount2 = to_satoshis(0.0001312)
    amount3 = to_satoshis(0.00005)
    amounts = [amount1, amount2, amount3]

    # all scriptPubKeys are needed to sign a taproot input
    # (depending on sighash) but always of the spend input
    script_pubkey1 = fromAddress1.to_script_pub_key()
    script_pubkey2 = fromAddress2.to_script_pub_key()
    script_pubkey3 = fromAddress3.to_script_pub_key()
    utxos_script_pubkeys = [script_pubkey1, script_pubkey2, script_pubkey3]

    toAddress = P2pkhAddress("mtVHHCqCECGwiMbMoZe8ayhJHuTdDbYWdJ")

    # create transaction input from tx id of UTXO
    txin1 = TxInput(txid1, vout1)
    txin2 = TxInput(txid2, vout2)
    txin3 = TxInput(txid3, vout3)

    # create transaction output
    txOut = TxOutput(to_satoshis(0.00022), toAddress.to_script_pub_key())

    # create transaction without change output - if at least a single input is
    # segwit we need to set has_segwit=True
    tx = Transaction([txin1, txin2, txin3], [txOut], has_segwit=True)

    print("\nRaw transaction:\n" + tx.serialize())

    print("\ntxid: " + tx.get_txid())
    print("\ntxwid: " + tx.get_wtxid())

    # sign taproot input
    # to create the digest message to sign in taproot we need to
    # pass all the utxos' scriptPubKeys and their amounts
    sig1 = priv1.sign_taproot_input(tx, 0, utxos_script_pubkeys, amounts)
    sig2 = priv2.sign_input(tx, 1, utxos_script_pubkeys[1])
    sig3 = priv3.sign_taproot_input(tx, 2, utxos_script_pubkeys, amounts)

    tx.set_witness(0, TxWitnessInput([sig1]))
    txin2.script_sig = Script([sig2, pub2.to_hex()])
    tx.set_witness(2, TxWitnessInput([sig3]))

    # print raw signed transaction ready to be broadcasted
    print("\nRaw signed transaction:\n" + tx.serialize())

    print("\nTxId:", tx.get_txid())
    print("\nTxwId:", tx.get_wtxid())

    print("\nSize:", tx.get_size())
    print("\nvSize:", tx.get_vsize())
    # print("\nCore vSize:", 160)


if __name__ == "__main__":
    main()

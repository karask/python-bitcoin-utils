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


import unittest

from bitcoinutils.setup import setup
from bitcoinutils.utils import to_satoshis
from bitcoinutils.keys import PrivateKey, P2pkhAddress
from bitcoinutils.transactions import TxInput, TxOutput, Transaction
from bitcoinutils.script import Script


class TestCreateP2shTransaction(unittest.TestCase):
    def setUp(self):
        setup("testnet")
        # values for testing create non std tx
        self.txin = TxInput(
            "e2d08a63a540000222d6a92440436375d8b1bc89a2638dc5366833804287c83f", 1
        )
        self.to_addr = P2pkhAddress("msXP94TBncQ9usP6oZNpGweE24biWjJs2d")
        self.sk = PrivateKey("cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA")
        self.txout = TxOutput(to_satoshis(0.9), Script(["OP_ADD", "OP_5", "OP_EQUAL"]))
        self.change_addr = P2pkhAddress("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r")
        self.change_txout = TxOutput(
            to_satoshis(2), self.change_addr.to_script_pub_key()
        )
        self.create_non_std_tx_result = (
            "02000000013fc8874280336836c58d63a289bcb1d87563434024a9d622020040a5638ad0e2"
            "010000006a47304402201febc032331342baaece4b88c7ab42d7148c586b9a48944cbebde9"
            "5636ac7424022018f0911a4ba664ac8cc21457a58e3a1214ba92b84cb60e57f4119fe655b3"
            "a78901210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            "ffffffff02804a5d05000000000393558700c2eb0b000000001976a914751e76e8199196d4"
            "54941c45d1b3a323f1433bd688ac00000000"
        )

        # values for testing create non std tx
        self.txin_spend = TxInput(
            "4d9a6baf45d4b57c875fe83d5e0834568eae4b5ef6e61d13720ef6685168e663", 0
        )
        self.txin_spend.script_sig = Script(["OP_2", "OP_3"])
        self.txout_spend = TxOutput(
            to_satoshis(0.8), self.change_addr.to_script_pub_key()
        )
        self.spend_non_std_tx_result = (
            "020000000163e6685168f60e72131de6f65e4bae8e5634085e3de85f877cb5d445af6b9a4"
            "d00000000025253ffffffff0100b4c404000000001976a914751e76e8199196d454941c45"
            "d1b3a323f1433bd688ac00000000"
        )

    def test_send_to_non_std(self):
        tx = Transaction([self.txin], [self.txout, self.change_txout])
        from_addr = P2pkhAddress("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r")
        sig = self.sk.sign_input(tx, 0, from_addr.to_script_pub_key())
        pk = self.sk.get_public_key().to_hex()
        self.txin.script_sig = Script([sig, pk])
        self.assertEqual(tx.serialize(), self.create_non_std_tx_result)

    def test_spend_non_std(self):
        tx = Transaction([self.txin_spend], [self.txout_spend])
        self.assertEqual(tx.serialize(), self.spend_non_std_tx_result)


if __name__ == "__main__":
    unittest.main()

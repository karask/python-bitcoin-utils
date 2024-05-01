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
from bitcoinutils.keys import PrivateKey, P2pkhAddress
from bitcoinutils.constants import TYPE_RELATIVE_TIMELOCK
from bitcoinutils.transactions import TxInput, TxOutput, Transaction, Sequence
from bitcoinutils.script import Script
from bitcoinutils.utils import to_satoshis


class TestCreateP2shTransaction(unittest.TestCase):
    def setUp(self):
        setup("testnet")
        self.txin = TxInput(
            "76464c2b9e2af4d63ef38a77964b3b77e629dddefc5cb9eb1a3645b1608b790f", 0
        )
        self.from_addr = P2pkhAddress("n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR")
        self.sk = PrivateKey("cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo")
        self.p2pk_sk = PrivateKey(
            "cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9"
        )
        self.p2pk_redeem_script = Script(
            [self.p2pk_sk.get_public_key().to_hex(), "OP_CHECKSIG"]
        )
        self.txout = TxOutput(
            to_satoshis(0.09), self.p2pk_redeem_script.to_p2sh_script_pub_key()
        )
        self.create_p2sh_and_send_result = (
            "02000000010f798b60b145361aebb95cfcdedd29e6773b4b96778af33ed6f42a9e2b4c4676"
            "000000006a47304402206f4027d0a1720ea4cc68e1aa3cc2e0ca5996806971c0cd7d40d3aa"
            "4309d4761802206c5d9c0c26dec8edab91c1c3d64e46e4dd80d8da1787a9965ade2299b41c"
            "3803012102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeeadbcff8a546"
            "ffffffff01405489000000000017a9142910fc0b1b7ab6c9789c5a67c22c5bcde5b9039087"
            "00000000"
        )

        self.txin_spend = TxInput(
            "7db363d5a7fabb64ccce154e906588f1936f34481223ea8c1f2c935b0a0c945b", 0
        )
        # self.p2pk_sk , self.p2pk_redeem_script from above
        self.to_addr = self.from_addr
        self.txout2 = TxOutput(to_satoshis(0.08), self.to_addr.to_script_pub_key())
        self.spend_p2sh_result = (
            "02000000015b940c0a5b932c1f8cea231248346f93f18865904e15cecc64bbfaa7d563b37d"
            "000000006c47304402204984c2089bf55d5e24851520ea43c431b0d79f90d464359899f27f"
            "b40a11fbd302201cc2099bfdc18c3a412afb2ef1625abad8a2c6b6ae0bf35887b787269a6f"
            "2d4d01232103a2fef1829e0742b89c218c51898d9e7cb9d51201ba2bf9d9e9214ebb6af327"
            "08acffffffff0100127a00000000001976a914fd337ad3bf81e086d96a68e1f8d6a0a510f8"
            "c24a88ac00000000"
        )

        # P2SH(CSV+P2PKH)
        self.sk_csv_p2pkh = PrivateKey(
            "cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9"
        )
        self.seq = Sequence(TYPE_RELATIVE_TIMELOCK, 200)
        self.seq_for_n_seq = self.seq.for_input_sequence()
        assert self.seq_for_n_seq is not None
        self.txin_seq = TxInput(
            "f557c623e55f0affc696b742630770df2342c4aac395e0ed470923247bc51b95",
            0,
            sequence=self.seq_for_n_seq,
        )
        self.another_addr = P2pkhAddress("n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR")
        self.spend_p2sh_csv_p2pkh_result = (
            "0200000001951bc57b24230947ede095c3aac44223df70076342b796c6ff0a5fe523c657f5"
            "000000008947304402205c2e23d8ad7825cf44b998045cb19b49cf6447cbc1cb76a254cda4"
            "3f7939982002202d8f88ab6afd2e8e1d03f70e5edc2a277c713018225d5b18889c5ad8fd66"
            "77b4012103a2fef1829e0742b89c218c51898d9e7cb9d51201ba2bf9d9e9214ebb6af32708"
            "1e02c800b27576a914c3f8e5b0f8455a2b02c29c4488a550278209b66988acc80000000100"
            "ab9041000000001976a914fd337ad3bf81e086d96a68e1f8d6a0a510f8c24a88ac00000000"
        )

    def test_signed_send_to_p2sh(self):
        tx = Transaction([self.txin], [self.txout])
        sig = self.sk.sign_input(tx, 0, self.from_addr.to_script_pub_key())
        pk = self.sk.get_public_key().to_hex()
        self.txin.script_sig = Script([sig, pk])
        self.assertEqual(tx.serialize(), self.create_p2sh_and_send_result)

    def test_spend_p2sh(self):
        tx = Transaction([self.txin_spend], [self.txout2])
        sig = self.p2pk_sk.sign_input(tx, 0, self.p2pk_redeem_script)
        self.txin_spend.script_sig = Script([sig, self.p2pk_redeem_script.to_hex()])
        self.assertEqual(tx.serialize(), self.spend_p2sh_result)

    def test_spend_p2sh_csv_p2pkh(self):
        redeem_script = Script(
            [
                self.seq.for_script(),
                "OP_CHECKSEQUENCEVERIFY",
                "OP_DROP",
                "OP_DUP",
                "OP_HASH160",
                self.sk_csv_p2pkh.get_public_key().to_hash160(),
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ]
        )
        txout = TxOutput(to_satoshis(11), self.another_addr.to_script_pub_key())
        tx = Transaction([self.txin_seq], [txout])
        sig = self.sk_csv_p2pkh.sign_input(tx, 0, redeem_script)
        self.txin_seq.script_sig = Script(
            [sig, self.sk_csv_p2pkh.get_public_key().to_hex(), redeem_script.to_hex()]
        )
        self.assertEqual(tx.serialize(), self.spend_p2sh_csv_p2pkh_result)


if __name__ == "__main__":
    unittest.main()

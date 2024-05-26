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
from bitcoinutils.keys import PrivateKey, P2wshAddress
from bitcoinutils.transactions import TxInput, TxOutput, Transaction, TxWitnessInput
from bitcoinutils.script import Script
from bitcoinutils.utils import to_satoshis


class TestCreateP2wpkhTransaction(unittest.TestCase):
    def setUp(self):
        setup("testnet")
        self.sk1 = PrivateKey.from_wif(
            "cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo"
        )
        self.sk2 = PrivateKey.from_wif(
            "cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9"
        )

        # 2-2 Multi-sign Script
        self.p2wsh_script = Script(
            [
                "OP_2",
                self.sk1.get_public_key().to_hex(),
                self.sk2.get_public_key().to_hex(),
                "OP_2",
                "OP_CHECKMULTISIG",
            ]
        )

        # tb1q89t0jucv7un4qq85u0a0tkc9qkepvg3vra72r00msx58wqplewfsfrlunx
        self.p2wsh_addr = P2wshAddress.from_script(self.p2wsh_script)

        # n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR
        self.p2pkh_addr = self.sk1.get_public_key().get_address()

        # P2PKH to P2WSH
        self.txin1 = TxInput(
            "6e9a0692ed4b3328909d66d41531854988dc39edba5df186affaefda91824e69", 0
        )
        self.txout1 = TxOutput(to_satoshis(0.0097), self.p2wsh_addr.to_script_pub_key())

        # P2WSH to P2PKH
        self.txin_spend = TxInput(
            "6233aca9f2d6165da2d7b4e35d73b039a22b53f58ce5af87dddee7682be937ea", 0
        )
        self.txin_spend_amount = to_satoshis(0.0097)
        self.txout2 = TxOutput(to_satoshis(0.0096), self.p2pkh_addr.to_script_pub_key())
        self.p2wsh_redeem_script = self.p2wsh_script

        # Multiple input multiple output
        # P2PKH UTXO
        self.txin1_multiple = TxInput(
            "24d949f8c77d7fc0cd09c8d5fccf7a0249178c16170c738da19f6c4b176c9f4b", 0
        )
        self.txin1_multiple_amount = to_satoshis(0.005)
        # P2WSH UTXO
        self.txin2_multiple = TxInput(
            "65f4d69c91a8de54dc11096eaa315e84ef91a389d1d1c17a691b72095100a3a4", 0
        )
        self.txin2_multiple_amount = to_satoshis(0.0069)
        # P2WPKH UTXO
        self.txin3_multiple = TxInput(
            "6c8fc6453a2a3039c2b5b55dcc59587e8b0afa52f92607385b5f4c7e84f38aa2", 0
        )
        self.txin3_multiple_amount = to_satoshis(0.0079)

        self.output1_multiple = TxOutput(
            to_satoshis(0.001), self.p2wsh_addr.to_script_pub_key()
        )
        self.output2_multiple = TxOutput(
            to_satoshis(0.001),
            self.sk1.get_public_key().get_segwit_address().to_script_pub_key(),
        )
        self.output3_multiple = TxOutput(
            to_satoshis(0.0177), self.p2pkh_addr.to_script_pub_key()
        )

        # result
        self.create_send_to_p2pkh_result = (
            "0200000001694e8291daeffaaf86f15dbaed39dc8849853115d4669d9028334bed92069a6e"
            "000000006a473044022038516db4e67c9217b871c690c09f60a57235084f888e23b8ac77ba"
            "01d0cba7ae022027a811be50cf54718fc6b88ea900bfa9c8d3e218208fef0e185163e3a47d"
            "9a08012102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeeadbcff8a546"
            "ffffffff0110cd0e00000000002200203956f9730cf7275000f4e3faf5db0505b216222c1f"
            "7ca1bdfb81a877003fcb9300000000"
        )
        self.spend_p2pkh_result = (
            "02000000000101ea37e92b68e7dedd87afe58cf5532ba239b0735de3b4d7a25d16d6f2a9ac"
            "33620000000000ffffffff0100a60e00000000001976a914fd337ad3bf81e086d96a68e1f8"
            "d6a0a510f8c24a88ac040047304402205c88b6c247c6b59e1cc48493b66629b6c011d97b99"
            "ecf991b595e891542cf1a802204fa0e3c238818a65adc87a0b2511ba780e4b57ff6c1ba6b2"
            "7815b1dca7b72c1c01473044022012840e38d61972f32208c23a05c73952cc36503112b0c2"
            "250fc8428b1e9c5fe4022051758dc7ce32567e2b71efb9df6dc161c9ec4bc0c2e8116c4228"
            "d27810cdb4d70147522102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acde"
            "eadbcff8a5462103a2fef1829e0742b89c218c51898d9e7cb9d51201ba2bf9d9e9214ebb6a"
            "f3270852ae00000000"
        )
        self.multiple_input_multiple_ouput_result = (
            "020000000001034b9f6c174b6c9fa18d730c17168c1749027acffcd5c809cdc07f7dc7f849"
            "d924000000006a47304402206932c93458a6ebb85f9fd6f69666cd383a3b8c8d517a096501"
            "438840d90493070220544d996a737ca9affda3573635b09e215be1ffddbee9b1260fc3d85d"
            "61d90ae5012102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeeadbcff8"
            "a546ffffffffa4a3005109721b697ac1d1d189a391ef845e31aa6e0911dc54dea8919cd6f4"
            "650000000000ffffffffa28af3847e4c5f5b380726f952fa0a8b7e5859cc5db5b5c239302a"
            "3a45c68f6c0000000000ffffffff03a0860100000000002200203956f9730cf7275000f4e3"
            "faf5db0505b216222c1f7ca1bdfb81a877003fcb93a086010000000000160014fd337ad3bf"
            "81e086d96a68e1f8d6a0a510f8c24a10021b00000000001976a914fd337ad3bf81e086d96a"
            "68e1f8d6a0a510f8c24a88ac00040047304402206503d3610d916835412449f262c8623146"
            "503d6f58c9b0343e8d1670b906c4da02200b2b8db13ddc9f157bb95e74c28d273adce49944"
            "307aa6a041dba1ed7c528d610147304402207ea74eff48e56f2c0d9afb70b2a90ebf6fcd3c"
            "e1e084350f3c061f88dde5eff402203c841f7bf969d04b383ebb1dee4118724bfc9da0260b"
            "10f64a0ba7ef3a8d43f00147522102d82c9860e36f15d7b72aa59e29347f951277c21cd4d3"
            "4822acdeeadbcff8a5462103a2fef1829e0742b89c218c51898d9e7cb9d51201ba2bf9d9e9"
            "214ebb6af3270852ae024730440220733fcbd21517a1559e9561668e480ffd0a24b62520cf"
            "a16ca7689b20f7f82be402204f053a27f19e0bd1346676c74c65e9e452515bc6510ab307ac"
            "3a3fb6d3c89ca7012102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeea"
            "dbcff8a54600000000"
        )

    def test_signed_send_to_p2wsh(self):
        # Non-segregated witness transaction
        tx = Transaction([self.txin1], [self.txout1])
        sig = self.sk1.sign_input(tx, 0, self.p2pkh_addr.to_script_pub_key())
        pk = self.sk1.get_public_key().to_hex()
        self.txin1.script_sig = Script([sig, pk])
        self.assertEqual(tx.serialize(), self.create_send_to_p2pkh_result)

    def test_spend_p2wsh(self):
        tx = Transaction([self.txin_spend], [self.txout2], has_segwit=True)
        sig1 = self.sk1.sign_segwit_input(
            tx, 0, self.p2wsh_redeem_script, self.txin_spend_amount
        )
        sig2 = self.sk2.sign_segwit_input(
            tx, 0, self.p2wsh_redeem_script, self.txin_spend_amount
        )

        pk = self.p2wsh_redeem_script.to_hex()
        tx.witnesses = [TxWitnessInput(["", sig1, sig2, pk])]
        self.assertEqual(tx.serialize(), self.spend_p2pkh_result)

    def test_multiple_input_multiple_ouput(self):
        tx = Transaction(
            [self.txin1_multiple, self.txin2_multiple, self.txin3_multiple],
            [self.output1_multiple, self.output2_multiple, self.output3_multiple],
            has_segwit=True,
        )

        sig1 = self.sk1.sign_input(tx, 0, self.p2pkh_addr.to_script_pub_key())
        pk1 = self.sk1.get_public_key().to_hex()
        self.txin1_multiple.script_sig = Script([sig1, pk1])
        tx.witnesses = [TxWitnessInput([])]

        sig_p2sh1 = self.sk1.sign_segwit_input(
            tx, 1, self.p2wsh_redeem_script, self.txin2_multiple_amount
        )
        sig_p2sh2 = self.sk2.sign_segwit_input(
            tx, 1, self.p2wsh_redeem_script, self.txin2_multiple_amount
        )
        pk2 = self.p2wsh_redeem_script.to_hex()
        tx.witnesses.append(TxWitnessInput(["", sig_p2sh1, sig_p2sh2, pk2]))

        sig3 = self.sk1.sign_segwit_input(
            tx, 2, self.p2pkh_addr.to_script_pub_key(), self.txin3_multiple_amount
        )
        pk3 = self.sk1.get_public_key().to_hex()
        tx.witnesses.append(TxWitnessInput([sig3, pk3]))

        self.assertEqual(tx.serialize(), self.multiple_input_multiple_ouput_result)


if __name__ == "__main__":
    unittest.main()

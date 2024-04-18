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
from bitcoinutils.constants import (
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY,
)
from bitcoinutils.transactions import TxInput, TxOutput, Transaction
from bitcoinutils.script import Script


class TestCreateP2pkhTransaction(unittest.TestCase):
    # maxDiff = None

    def setUp(self):
        setup("testnet")
        # values for testing unsigned tx, signed tx all, signed tx with low s,
        # sighash none
        self.txin = TxInput(
            "fb48f4e23bf6ddf606714141ac78c3e921c8c0bebeb7c8abb2c799e9ff96ce6c", 0
        )
        self.addr = P2pkhAddress("n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR")
        self.txout = TxOutput(
            to_satoshis(0.1),
            Script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    self.addr.to_hash160(),
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ),
        )
        self.change_addr = P2pkhAddress("mytmhndz4UbEMeoSZorXXrLpPfeoFUDzEp")
        self.change_txout = TxOutput(
            to_satoshis(0.29), self.change_addr.to_script_pub_key()
        )
        self.change_low_s_addr = P2pkhAddress("mmYNBho9BWQB2dSniP1NJvnPoj5EVWw89w")
        self.change_low_s_txout = TxOutput(
            to_satoshis(0.29), self.change_low_s_addr.to_script_pub_key()
        )
        self.sk = PrivateKey("cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9")
        self.from_addr = P2pkhAddress("myPAE9HwPeKHh8FjKwBNBaHnemApo3dw6e")

        self.core_tx_result = (
            "02000000016cce96ffe999c7b2abc8b7bebec0c821e9c378ac41417106f6ddf63be2f448fb"
            "0000000000ffffffff0280969800000000001976a914fd337ad3bf81e086d96a68e1f8d6a0"
            "a510f8c24a88ac4081ba01000000001976a914c992931350c9ba48538003706953831402ea"
            "34ea88ac00000000"
        )
        self.core_tx_signed_result = (
            "02000000016cce96ffe999c7b2abc8b7bebec0c821e9c378ac41417106f6ddf63be2f448fb"
            "000000006a473044022079dad1afef077fa36dcd3488708dd05ef37888ef550b45eb00cdb0"
            "4ba3fc980e02207a19f6261e69b604a92e2bffdf6ddbed0c64f55d5003e9dfb58b874b07ae"
            "f3d7012103a2fef1829e0742b89c218c51898d9e7cb9d51201ba2bf9d9e9214ebb6af32708"
            "ffffffff0280969800000000001976a914fd337ad3bf81e086d96a68e1f8d6a0a510f8c24a"
            "88ac4081ba01000000001976a914c992931350c9ba48538003706953831402ea34ea88ac00"
            "000000"
        )
        self.core_tx_signed_low_s_SIGALL_result = (
            "02000000016cce96ffe999c7b2abc8b7bebec0c821e9c378ac41417106f6ddf63be2f448fb"
            "000000006a473044022044ef433a24c6010a90af14f7739e7c60ce2c5bc3eab96eaee9fbcc"
            "fdbb3e272202205372a617cb235d0a0ec2889dbfcadf15e10890500d184c8dda90794ecdf7"
            "9492012103a2fef1829e0742b89c218c51898d9e7cb9d51201ba2bf9d9e9214ebb6af32708"
            "ffffffff0280969800000000001976a914fd337ad3bf81e086d96a68e1f8d6a0a510f8c24a"
            "88ac4081ba01000000001976a91442151d0c21442c2b038af0ad5ee64b9d6f4f4e4988ac00"
            "000000"
        )
        self.core_tx_signed_low_s_SIGNONE_result = (
            "02000000016cce96ffe999c7b2abc8b7bebec0c821e9c378ac41417106f6ddf63be2f448fb"
            "000000006a47304402201e4b7a2ed516485fdde697ba63f6670d43aa6f18d82f18bae12d5f"
            "d228363ac10220670602bec9df95d7ec4a619a2f44e0b8dcf522fdbe39530dd78d738c0ed0"
            "c430022103a2fef1829e0742b89c218c51898d9e7cb9d51201ba2bf9d9e9214ebb6af32708"
            "ffffffff0280969800000000001976a914fd337ad3bf81e086d96a68e1f8d6a0a510f8c24a"
            "88ac4081ba01000000001976a91442151d0c21442c2b038af0ad5ee64b9d6f4f4e4988ac00"
            "000000"
        )
        self.core_tx_signed_low_s_SIGNONE_txid = (
            "105933681b0ca37ae0c0af43ae6f111803c899232b7fd586584b532dbe21ae6f"
        )

        # values for testing sighash single and sighash all/none/single with
        # anyonecanpay
        self.sig_txin1 = TxInput(
            "76464c2b9e2af4d63ef38a77964b3b77e629dddefc5cb9eb1a3645b1608b790f", 0
        )
        self.sig_txin2 = TxInput(
            "76464c2b9e2af4d63ef38a77964b3b77e629dddefc5cb9eb1a3645b1608b790f", 1
        )
        self.sig_from_addr1 = P2pkhAddress("n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR")
        self.sig_from_addr2 = P2pkhAddress("mmYNBho9BWQB2dSniP1NJvnPoj5EVWw89w")
        self.sig_sk1 = PrivateKey(
            "cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo"
        )
        self.sig_sk2 = PrivateKey(
            "cVf3kGh6552jU2rLaKwXTKq5APHPoZqCP4GQzQirWGHFoHQ9rEVt"
        )
        self.sig_to_addr1 = P2pkhAddress("myPAE9HwPeKHh8FjKwBNBaHnemApo3dw6e")
        self.sig_txout1 = TxOutput(
            to_satoshis(0.09),
            Script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    self.sig_to_addr1.to_hash160(),
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ),
        )
        self.sig_to_addr2 = P2pkhAddress("mmYNBho9BWQB2dSniP1NJvnPoj5EVWw89w")
        self.sig_txout2 = TxOutput(
            to_satoshis(0.009),
            Script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    self.sig_to_addr2.to_hash160(),
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ),
        )
        self.sig_sighash_single_result = (
            "02000000010f798b60b145361aebb95cfcdedd29e6773b4b96778af33ed6f42a9e2b4c4676"
            "000000006a47304402202cfd7077fe8adfc5a65fb3953fa3482cad1413c28b53f12941c108"
            "2898d4935102201d393772c47f0699592268febb5b4f64dabe260f440d5d0f96dae5bc2b53"
            "e11e032102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeeadbcff8a546"
            "ffffffff0240548900000000001976a914c3f8e5b0f8455a2b02c29c4488a550278209b669"
            "88aca0bb0d00000000001976a91442151d0c21442c2b038af0ad5ee64b9d6f4f4e4988ac00"
            "000000"
        )
        self.sign_sighash_all_2in_2out_result = (
            "02000000020f798b60b145361aebb95cfcdedd29e6773b4b96778af33ed6f42a9e2b4c4676"
            "000000006a4730440220355c3cf50b1d320d4ddfbe1b407ddbe508f8e31a38cc5531dec353"
            "4e8cb2e565022037d4e8d7ba9dd1c788c0d8b5b99270d4c1d4087cdee7f139a71fea23dcee"
            "ca33012102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeeadbcff8a546"
            "ffffffff0f798b60b145361aebb95cfcdedd29e6773b4b96778af33ed6f42a9e2b4c467601"
            "0000006a47304402206b728374b8879fd7a10cbd4f347934d583f4301aa5d592211487732c"
            "235b85b6022030acdc07761f227c27010bd022df4b22eb9875c65a59e8e8a5722229bc7362"
            "f4012102364d6f04487a71b5966eae3e14a4dc6f00dbe8e55e61bedd0b880766bfe72b5dff"
            "ffffff0240548900000000001976a914c3f8e5b0f8455a2b02c29c4488a550278209b66988"
            "aca0bb0d00000000001976a91442151d0c21442c2b038af0ad5ee64b9d6f4f4e4988ac0000"
            "0000"
        )
        self.sign_sighash_none_2in_2out_result = (
            "02000000020f798b60b145361aebb95cfcdedd29e6773b4b96778af33ed6f42a9e2b4c4676"
            "000000006a47304402202a2804048b7f84f2dd7641ec05bbaf3da9ae0d2a9f9ad476d376ad"
            "fd8bf5033302205170fee2ab7b955d72ae2beac3bae15679d75584c37d78d82b07df540260"
            "5bab022102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeeadbcff8a546"
            "ffffffff0f798b60b145361aebb95cfcdedd29e6773b4b96778af33ed6f42a9e2b4c467601"
            "0000006a473044022021a82914b002bd02090fbdb37e2e739e9ba97367e74db5e1de834bba"
            "b9431a2f02203a11f49a3f6ac03b1550ee04f9d84deee2045bc038cb8c3e70869470126a06"
            "4d022102364d6f04487a71b5966eae3e14a4dc6f00dbe8e55e61bedd0b880766bfe72b5dff"
            "ffffff0240548900000000001976a914c3f8e5b0f8455a2b02c29c4488a550278209b66988"
            "aca0bb0d00000000001976a91442151d0c21442c2b038af0ad5ee64b9d6f4f4e4988ac0000"
            "0000"
        )
        self.sign_sighash_single_2in_2out_result = (
            "02000000020f798b60b145361aebb95cfcdedd29e6773b4b96778af33ed6f42a9e2b4c4676"
            "000000006a47304402206118d21952932deb8608f772017fe76827ccdc8b750ead0f563642"
            "9ab5883a6802207f6ded77e22785b0e6c682c05260c2e073d1e1522d4c02fb78df6cdd2862"
            "e853032102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeeadbcff8a546"
            "ffffffff0f798b60b145361aebb95cfcdedd29e6773b4b96778af33ed6f42a9e2b4c467601"
            "0000006a47304402205012090ddf07ee2e7767020f09224001360243f8dbe05c5011c54eed"
            "9fb90d4802203358e227c891f609c3baf98d975d9ee72666fb511c808419d24ec5cccaf393"
            "8e032102364d6f04487a71b5966eae3e14a4dc6f00dbe8e55e61bedd0b880766bfe72b5dff"
            "ffffff0240548900000000001976a914c3f8e5b0f8455a2b02c29c4488a550278209b66988"
            "aca0bb0d00000000001976a91442151d0c21442c2b038af0ad5ee64b9d6f4f4e4988ac0000"
            "0000"
        )
        self.sign_sighash_all_single_anyone_2in_2out_result = (
            "02000000020f798b60b145361aebb95cfcdedd29e6773b4b96778af33ed6f42a9e2b4c4676"
            "000000006a47304402205360315c439214dd1da10ea00a7531c0a211a865387531c358e586"
            "000bfb41b3022064a729e666b4d8ac7a09cb7205c8914c2eb634080597277baf946903d543"
            "8f49812102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeeadbcff8a546"
            "ffffffff0f798b60b145361aebb95cfcdedd29e6773b4b96778af33ed6f42a9e2b4c467601"
            "0000006a473044022067943abe9fa7584ba9816fc9bf002b043f7f97e11de59155d66e041"
            "1a679ba2c02200a13462236fa520b80b4ed85c7ded363b4c9264eb7b2d9746200be48f2b6f"
            "4cb832102364d6f04487a71b5966eae3e14a4dc6f00dbe8e55e61bedd0b880766bfe72b5df"
            "fffffff0240548900000000001976a914c3f8e5b0f8455a2b02c29c4488a550278209b6698"
            "8aca0bb0d00000000001976a91442151d0c21442c2b038af0ad5ee64b9d6f4f4e4988ac000"
            "00000"
        )

    def test_unsigned_tx_1_input_2_outputs(self):
        tx = Transaction([self.txin], [self.txout, self.change_txout])
        self.assertEqual(tx.serialize(), self.core_tx_result)

    def test_signed_tx_1_input_2_outputs(self):
        tx = Transaction([self.txin], [self.txout, self.change_txout])
        sig = self.sk.sign_input(
            tx,
            0,
            Script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    self.from_addr.to_hash160(),
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ),
        )
        pk = self.sk.get_public_key().to_hex()
        self.txin.script_sig = Script([sig, pk])
        self.assertEqual(tx.serialize(), self.core_tx_signed_result)

    def test_signed_low_s_SIGALL_tx_1_input_2_outputs(self):
        tx = Transaction([self.txin], [self.txout, self.change_low_s_txout])
        sig = self.sk.sign_input(tx, 0, self.from_addr.to_script_pub_key())
        pk = self.sk.get_public_key().to_hex()
        self.txin.script_sig = Script([sig, pk])
        self.assertEqual(tx.serialize(), self.core_tx_signed_low_s_SIGALL_result)

    def test_signed_low_s_SIGNONE_tx_1_input_2_outputs(self):
        tx = Transaction([self.txin], [self.txout, self.change_low_s_txout])
        sig = self.sk.sign_input(
            tx,
            0,
            Script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    self.from_addr.to_hash160(),
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ),
            SIGHASH_NONE,
        )
        pk = self.sk.get_public_key().to_hex()
        self.txin.script_sig = Script([sig, pk])
        # check correct raw tx
        self.assertEqual(tx.serialize(), self.core_tx_signed_low_s_SIGNONE_result)
        # check correct calculation of txid
        self.assertEqual(tx.get_txid(), self.core_tx_signed_low_s_SIGNONE_txid)

    def test_signed_low_s_SIGSINGLE_tx_1_input_2_outputs(self):
        tx = Transaction([self.sig_txin1], [self.sig_txout1, self.sig_txout2])
        sig = self.sig_sk1.sign_input(
            tx, 0, self.sig_from_addr1.to_script_pub_key(), SIGHASH_SINGLE
        )
        pk = self.sig_sk1.get_public_key().to_hex()
        self.sig_txin1.script_sig = Script([sig, pk])
        self.assertEqual(tx.serialize(), self.sig_sighash_single_result)

    def test_signed_SIGALL_tx_2in_2_out(self):
        # note that this would have failed due to absurdly high fees but we
        # ignore it for our purposes
        tx = Transaction(
            [self.sig_txin1, self.sig_txin2], [self.sig_txout1, self.sig_txout2]
        )
        sig = self.sig_sk1.sign_input(
            tx,
            0,
            Script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    self.sig_from_addr1.to_hash160(),
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ),
            SIGHASH_ALL,
        )
        sig2 = self.sig_sk2.sign_input(
            tx,
            1,
            Script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    self.sig_from_addr2.to_hash160(),
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ),
            SIGHASH_ALL,
        )
        pk = self.sig_sk1.get_public_key().to_hex()
        pk2 = self.sig_sk2.get_public_key().to_hex()
        self.sig_txin1.script_sig = Script([sig, pk])
        self.sig_txin2.script_sig = Script([sig2, pk2])
        self.assertEqual(tx.serialize(), self.sign_sighash_all_2in_2out_result)

    def test_signed_SIGNONE(self):
        # note that this would have failed due to absurdly high fees but we
        # ignore it for our purposes
        tx = Transaction(
            [self.sig_txin1, self.sig_txin2], [self.sig_txout1, self.sig_txout2]
        )
        sig = self.sig_sk1.sign_input(
            tx,
            0,
            Script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    self.sig_from_addr1.to_hash160(),
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ),
            SIGHASH_NONE,
        )
        sig2 = self.sig_sk2.sign_input(
            tx,
            1,
            Script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    self.sig_from_addr2.to_hash160(),
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ),
            SIGHASH_NONE,
        )
        pk = self.sig_sk1.get_public_key().to_hex()
        pk2 = self.sig_sk2.get_public_key().to_hex()
        self.sig_txin1.script_sig = Script([sig, pk])
        self.sig_txin2.script_sig = Script([sig2, pk2])
        self.assertEqual(tx.serialize(), self.sign_sighash_none_2in_2out_result)

    def test_signed_SIGSINGLE_tx_2in_2_out(self):
        # note that this would have failed due to absurdly high fees but we
        # ignore it for our purposes
        tx = Transaction(
            [self.sig_txin1, self.sig_txin2], [self.sig_txout1, self.sig_txout2]
        )
        sig = self.sig_sk1.sign_input(
            tx,
            0,
            Script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    self.sig_from_addr1.to_hash160(),
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ),
            SIGHASH_SINGLE,
        )
        sig2 = self.sig_sk2.sign_input(
            tx,
            1,
            Script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    self.sig_from_addr2.to_hash160(),
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ),
            SIGHASH_SINGLE,
        )
        pk = self.sig_sk1.get_public_key().to_hex()
        pk2 = self.sig_sk2.get_public_key().to_hex()
        self.sig_txin1.script_sig = Script([sig, pk])
        self.sig_txin2.script_sig = Script([sig2, pk2])
        self.assertEqual(tx.serialize(), self.sign_sighash_single_2in_2out_result)

    def test_signed_SIGALLSINGLE_ANYONEtx_2in_2_out(self):
        # note that this would have failed due to absurdly high fees but we
        # ignore it for our purposes
        tx = Transaction(
            [self.sig_txin1, self.sig_txin2], [self.sig_txout1, self.sig_txout2]
        )
        sig = self.sig_sk1.sign_input(
            tx,
            0,
            Script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    self.sig_from_addr1.to_hash160(),
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ),
            SIGHASH_ALL | SIGHASH_ANYONECANPAY,
        )
        sig2 = self.sig_sk2.sign_input(
            tx,
            1,
            self.sig_from_addr2.to_script_pub_key(),
            SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
        )
        pk = self.sig_sk1.get_public_key().to_hex()
        pk2 = self.sig_sk2.get_public_key().to_hex()
        self.sig_txin1.script_sig = Script([sig, pk])
        self.sig_txin2.script_sig = Script([sig2, pk2])
        self.assertEqual(
            tx.serialize(), self.sign_sighash_all_single_anyone_2in_2out_result
        )


if __name__ == "__main__":
    unittest.main()

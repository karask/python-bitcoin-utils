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
from bitcoinutils.keys import PrivateKey
from bitcoinutils.constants import (
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY,
)
from bitcoinutils.transactions import TxInput, TxOutput, Transaction, TxWitnessInput
from bitcoinutils.script import Script
from bitcoinutils.utils import to_satoshis


class TestCreateP2wpkhTransaction(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        setup("testnet")
        self.sk = PrivateKey.from_wif(
            "cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo"
        )
        # n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR
        self.p2pkh_addr = self.sk.get_public_key().get_address()

        # tb1ql5eh45als8sgdkt2drsl344q55g03sj2krzqe3
        self.p2wpkh_addr = self.sk.get_public_key().get_segwit_address()

        # P2PKH to P2WPKH
        self.txin1 = TxInput(
            "5a7b3aaa66d6b7b7abcdc9f1d05db4eee94a700297a319e19454e143875e1078", 0
        )
        self.txout1 = TxOutput(
            to_satoshis(0.0099), self.p2wpkh_addr.to_script_pub_key()
        )

        # P2WPKH to P2PKH
        self.txin_spend = TxInput(
            "b3ca1c4cc778380d1e5376a5517445104e46e97176e40741508a3b07a6483ad3", 0
        )
        self.txin_spend_amount = to_satoshis(0.0099)
        self.txout2 = TxOutput(to_satoshis(0.0098), self.p2pkh_addr.to_script_pub_key())
        self.p2pkh_redeem_script = Script(
            [
                "OP_DUP",
                "OP_HASH160",
                self.p2pkh_addr.to_hash160(),
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ]
        )

        # P2WPKH P2PKH to P2PKH
        self.txin_spend_p2pkh = TxInput(
            "1e2a5279c868d61fb2ff0b1c2b04aa3eff02cd74952a8b4e799532635a9132cc", 0
        )
        self.txin_spend_p2pkh_amount = to_satoshis(0.01)

        self.txin_spend_p2wpkh = TxInput(
            "fff39047310fbf04bdd0e0bc75dde4267ae4d25219d8ad95e0ca1cee907a60da", 0
        )
        self.txin_spend_p2wpkh_amount = to_satoshis(0.0095)

        self.txout3 = TxOutput(to_satoshis(0.0194), self.p2pkh_addr.to_script_pub_key())

        # SIGHASH NONE type send
        self.txin1_signone = TxInput(
            "fb4c338a00a75d73f9a6bd203ed4bd8884edeb111fac25a7946d5df6562f1942", 0
        )
        self.txin1_signone_amount = to_satoshis(0.01)

        self.txout1_signone = TxOutput(
            to_satoshis(0.0080), self.p2pkh_addr.to_script_pub_key()
        )
        self.txout2_signone = TxOutput(
            to_satoshis(0.0019), self.p2pkh_addr.to_script_pub_key()
        )

        # SIGHASH SINGLE type send
        self.txin1_sigsingle = TxInput(
            "b04909d4b5239a56d676c1d9d722f325a86878c9aa535915aa0df97df47cedeb", 0
        )
        self.txin1_sigsingle_amount = to_satoshis(0.0193)

        self.txout1_sigsingle = TxOutput(
            to_satoshis(0.01), self.p2pkh_addr.to_script_pub_key()
        )
        self.txout2_sigsingle = TxOutput(
            to_satoshis(0.0092), self.p2pkh_addr.to_script_pub_key()
        )

        # SIGHASH_ALL | SIGHASH_ANYONECANPAY type send
        self.txin1_siganyonecanpay_all = TxInput(
            "f67e97a2564dceed405e214843e3c954b47dd4f8b26ea48f82382f51f7626036", 0
        )
        self.txin1_siganyonecanpay_all_amount = to_satoshis(0.0018)

        self.txin2_siganyonecanpay_all = TxInput(
            "f4afddb77cd11a79bed059463085382c50d60c7f9e4075d8469cfe60040f68eb", 0
        )
        self.txin2_siganyonecanpay_all_amount = to_satoshis(0.0018)

        self.txout1_siganyonecanpay_all = TxOutput(
            to_satoshis(0.0018), self.p2pkh_addr.to_script_pub_key()
        )
        self.txout2_siganyonecanpay_all = TxOutput(
            to_satoshis(0.0017), self.p2pkh_addr.to_script_pub_key()
        )

        # SIGHASH_NONE | SIGHASH_ANYONECANPAY type send
        self.txin1_siganyonecanpay_none = TxInput(
            "d2ae5d4a3f390f108769139c9b5757846be6693b785c4e21eab777eec7289095", 0
        )
        self.txin1_siganyonecanpay_none_amount = to_satoshis(0.009)

        self.txin2_siganyonecanpay_none = TxInput(
            "ee5062d426677372e6de96e2eb47d572af5deaaef3ef225f3179dfa1ece3f4f5", 0
        )
        self.txin2_siganyonecanpay_none_amount = to_satoshis(0.007)

        self.txout1_siganyonecanpay_none = TxOutput(
            to_satoshis(0.008), self.p2pkh_addr.to_script_pub_key()
        )
        self.txout2_siganyonecanpay_none = TxOutput(
            to_satoshis(0.007), self.p2pkh_addr.to_script_pub_key()
        )

        # SIGHASH_SINGLE | SIGHASH_ANYONECANPAY type send
        self.txin1_siganyonecanpay_single = TxInput(
            "c7bb5672266c8a5b64fe91e953a9e23e3206e3b1a2ddc8e5999b607b82485042", 0
        )
        self.txin1_siganyonecanpay_single_amount = to_satoshis(0.01)

        self.txout1_siganyonecanpay_single = TxOutput(
            to_satoshis(0.005), self.p2pkh_addr.to_script_pub_key()
        )
        self.txout2_siganyonecanpay_single = TxOutput(
            to_satoshis(0.0049), self.p2pkh_addr.to_script_pub_key()
        )

        # result
        self.create_send_to_p2wpkh_result = (
            "020000000178105e8743e15494e119a39702704ae9eeb45dd0f1c9cdabb7b7d666aa3a7b5a"
            "000000006a4730440220415155963673e5582aadfdb8d53874c9764cfd56c28be8d5f2838f"
            "dab6365f9902207bf28f875e15ff53e81f3245feb07c6120df4a653feabba3b7bf274790ea"
            "1fd1012102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeeadbcff8a546"
            "ffffffff01301b0f0000000000160014fd337ad3bf81e086d96a68e1f8d6a0a510f8c24a00"
            "000000"
        )
        self.spend_p2pkh_result = (
            "02000000000101d33a48a6073b8a504107e47671e9464e10457451a576531e0d3878c74c1c"
            "cab30000000000ffffffff0120f40e00000000001976a914fd337ad3bf81e086d96a68e1f8"
            "d6a0a510f8c24a88ac0247304402201c7ec9b049daa99c78675810b5e36b0b61add3f84180"
            "eaeaa613f8525904bdc302204854830d463a4699b6d69e37c08b8d3c6158185d46499170cf"
            "cc24d4a9e9a37f012102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeea"
            "dbcff8a54600000000"
        )
        self.p2pkh_and_p2wpkh_to_p2pkh_result = (
            "02000000000102cc32915a633295794e8b2a9574cd02ff3eaa042b1c0bffb21fd668c87952"
            "2a1e000000006a47304402200fe842622e656a6780093f60b0597a36a57481611543a2e957"
            "6f9e8f1b34edb8022008ba063961c600834760037be20f45bbe077541c533b3fd257eae8e0"
            "8d0de3b3012102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeeadbcff8"
            "a546ffffffffda607a90ee1ccae095add81952d2e47a26e4dd75bce0d0bd04bf0f314790f3"
            "ff0000000000ffffffff01209a1d00000000001976a914fd337ad3bf81e086d96a68e1f8d6"
            "a0a510f8c24a88ac00024730440220274bb5445294033a36c360c48cc5e441ba8cc2bc1554"
            "dcb7d367088ec40a0d0302202a36f6e03f969e1b0c582f006257eec8fa2ada8cd34fe41ae2"
            "aa90d6728999d1012102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeea"
            "dbcff8a54600000000"
        )
        self.test_signone_send_result = (
            "0200000000010142192f56f65d6d94a725ac1f11ebed8488bdd43e20bda6f9735da7008a33"
            "4cfb0000000000ffffffff0200350c00000000001976a914fd337ad3bf81e086d96a68e1f8"
            "d6a0a510f8c24a88ac30e60200000000001976a914fd337ad3bf81e086d96a68e1f8d6a0a5"
            "10f8c24a88ac0247304402202c47de56a42143ea94c15bdeee237104524a009e50d5359596"
            "f7c6f2208a280b022076d6be5dcab09f7645d1ee001c1af14f44420c0d0b16724d741d2a5c"
            "19816902022102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeeadbcff8"
            "a54600000000"
        )
        self.test_sigsingle_send_result = (
            "02000000000101ebed7cf47df90daa155953aac97868a825f322d7d9c176d6569a23b5d409"
            "49b00000000000ffffffff0240420f00000000001976a914fd337ad3bf81e086d96a68e1f8"
            "d6a0a510f8c24a88acc0090e00000000001976a914fd337ad3bf81e086d96a68e1f8d6a0a5"
            "10f8c24a88ac0247304402205189808e5cd0d49a8211202ea1afd7d01c180892ddf054508c"
            "349c2aa5630ee202202cbe5efa11fdde964603f4b9112d5e9ac452fba2e8ad5b6cddffbc8f"
            "0043b59e032102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeeadbcff8"
            "a54600000000"
        )
        self.test_siganyonecanpay_all_send_result = (
            "02000000000102366062f7512f38828fa46eb2f8d47db454c9e34348215e40edce4d56a297"
            "7ef60000000000ffffffffeb680f0460fe9c46d875409e7f0cd6502c3885304659d0be791a"
            "d17cb7ddaff40000000000ffffffff0220bf0200000000001976a914fd337ad3bf81e086d9"
            "6a68e1f8d6a0a510f8c24a88ac10980200000000001976a914fd337ad3bf81e086d96a68e1"
            "f8d6a0a510f8c24a88ac024730440220046813b802c046c9cfa309e85d1f36b17f1eb1dfb3"
            "e8d3c4ae2f74915a3b1c1f02200c5631038bb8b6c7b5283892bb1279a40e7ac13d2392df0c"
            "7b36bde7444ec54c812102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acde"
            "eadbcff8a5460247304402206fb60dc79b5ca6c699d04ec96c4f196938332c2909fd17c040"
            "23ebcc7408f36e02202b071771a58c84e20b7bf1fcec05c0ef55c1100436a055bfcb2bf7ed"
            "1c0683a9012102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeeadbcff8"
            "a54600000000"
        )
        self.test_siganyonecanpay_none_send_result = (
            "02000000000102959028c7ee77b7ea214e5c783b69e66b8457579b9c136987100f393f4a5d"
            "aed20000000000fffffffff5f4e3eca1df79315f22eff3aeea5daf72d547ebe296dee67273"
            "6726d46250ee0000000000ffffffff0200350c00000000001976a914fd337ad3bf81e086d9"
            "6a68e1f8d6a0a510f8c24a88ac60ae0a00000000001976a914fd337ad3bf81e086d96a68e1"
            "f8d6a0a510f8c24a88ac0247304402203bbcbd2003244e9ccde7f705d3017f3baa2cb2d47e"
            "fb63ede7e39704eff3987702206932aa4b402de898ff2fd3b2182f344dc9051b4c326dacc0"
            "7b1e59059042f3ad822102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acde"
            "eadbcff8a54602473044022052dd29ab8bb0814b13633691148feceded29466ff8a1812d6d"
            "51c6fa53c55b5402205f25b3ae0da860da29a6745b0b587aa3fc3e05bef3121d3693ca2e3f"
            "4c2c3195012102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeeadbcff8"
            "a54600000000"
        )
        self.test_siganyonecanpay_single_send_result = (
            "02000000000101425048827b609b99e5c8dda2b1e306323ee2a953e991fe645b8a6c267256"
            "bbc70000000000ffffffff0220a10700000000001976a914fd337ad3bf81e086d96a68e1f8"
            "d6a0a510f8c24a88ac107a0700000000001976a914fd337ad3bf81e086d96a68e1f8d6a0a5"
            "10f8c24a88ac02473044022064b63a1da4181764a1e8246d353b72c420999c575807ec8032"
            "9c64264fd5b19e022076ec4ba6c02eae7dc9340f8c76956d5efb7d0fbad03b1234297ebed8"
            "c38e43d8832102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeeadbcff8"
            "a54600000000"
        )

    def test_signed_send_to_p2wpkh(self):
        # Non-segregated witness transaction
        tx = Transaction([self.txin1], [self.txout1])
        sig = self.sk.sign_input(tx, 0, self.p2pkh_addr.to_script_pub_key())
        pk = self.sk.get_public_key().to_hex()
        self.txin1.script_sig = Script([sig, pk])
        self.assertEqual(tx.serialize(), self.create_send_to_p2wpkh_result)

    def test_spend_p2wpkh(self):
        tx = Transaction([self.txin_spend], [self.txout2], has_segwit=True)
        sig = self.sk.sign_segwit_input(
            tx, 0, self.p2pkh_redeem_script, self.txin_spend_amount
        )
        pk = self.sk.get_public_key().to_hex()
        tx.witnesses = [TxWitnessInput([sig, pk])]
        self.assertEqual(tx.serialize(), self.spend_p2pkh_result)

    def test_p2pkh_and_p2wpkh_to_p2pkh(self):
        tx = Transaction(
            [self.txin_spend_p2pkh, self.txin_spend_p2wpkh],
            [self.txout3],
            has_segwit=True,
        )
        # spend_p2pkh
        sig1 = self.sk.sign_input(tx, 0, self.p2pkh_addr.to_script_pub_key())
        pk1 = self.sk.get_public_key().to_hex()
        self.txin_spend_p2pkh.script_sig = Script([sig1, pk1])
        tx.witnesses = [TxWitnessInput([])]
        # spend_p2wpkh
        sig2 = self.sk.sign_segwit_input(
            tx, 1, self.p2pkh_redeem_script, self.txin_spend_p2wpkh_amount
        )
        pk2 = self.sk.get_public_key().to_hex()
        tx.witnesses.append(TxWitnessInput([sig2, pk2]))

        self.assertEqual(tx.serialize(), self.p2pkh_and_p2wpkh_to_p2pkh_result)

    def test_signone_send(self):
        """
        SIGHASH_NONE:signs all of the inputs
        """
        # First, only txin1 and txout1 are added to the transaction.
        tx = Transaction([self.txin1_signone], [self.txout1_signone], has_segwit=True)
        pk = self.sk.get_public_key().to_hex()

        sig_signone = self.sk.sign_segwit_input(
            tx, 0, self.p2pkh_redeem_script, self.txin1_signone_amount, SIGHASH_NONE
        )
        tx.witnesses = [TxWitnessInput([sig_signone, pk])]
        # Adding additional output signatures will not be affected
        tx.outputs.append(self.txout2_signone)

        self.assertEqual(tx.serialize(), self.test_signone_send_result)

    def test_sigsingle_send(self):
        """
        SIGHASH_SINGLE:signs all inputs but only txin_index output
        """
        tx = Transaction(
            [self.txin1_sigsingle], [self.txout1_sigsingle], has_segwit=True
        )
        pk = self.sk.get_public_key().to_hex()

        sig_signone = self.sk.sign_segwit_input(
            tx, 0, self.p2pkh_redeem_script, self.txin1_sigsingle_amount, SIGHASH_SINGLE
        )
        tx.witnesses = [TxWitnessInput([sig_signone, pk])]

        tx.outputs.append(self.txout2_sigsingle)
        self.assertEqual(tx.serialize(), self.test_sigsingle_send_result)

    def test_siganyonecanpay_all_send(self):
        """
        SIGHASH_ALL | SIGHASH_ANYONECANPAY:signs all outputs but only txin_index input
        """
        tx = Transaction(
            [self.txin1_siganyonecanpay_all],
            [self.txout1_siganyonecanpay_all, self.txout2_siganyonecanpay_all],
            has_segwit=True,
        )
        pk = self.sk.get_public_key().to_hex()

        sig_signone = self.sk.sign_segwit_input(
            tx,
            0,
            self.p2pkh_redeem_script,
            self.txin1_siganyonecanpay_all_amount,
            SIGHASH_ALL | SIGHASH_ANYONECANPAY,
        )
        tx.witnesses = [TxWitnessInput([sig_signone, pk])]

        tx.inputs.append(self.txin2_siganyonecanpay_all)

        sig = self.sk.sign_segwit_input(
            tx,
            1,
            self.p2pkh_redeem_script,
            self.txin2_siganyonecanpay_all_amount,
            SIGHASH_ALL,
        )
        tx.witnesses.append(TxWitnessInput([sig, pk]))

        self.assertEqual(tx.serialize(), self.test_siganyonecanpay_all_send_result)

    def test_siganyonecanpay_none_send(self):
        """
        SIGHASH_NONE | SIGHASH_ANYONECANPAY:signs only the txin_index input
        """
        tx = Transaction(
            [self.txin1_siganyonecanpay_none],
            [self.txout1_siganyonecanpay_none],
            has_segwit=True,
        )
        pk = self.sk.get_public_key().to_hex()

        sig_signone = self.sk.sign_segwit_input(
            tx,
            0,
            self.p2pkh_redeem_script,
            self.txin1_siganyonecanpay_none_amount,
            SIGHASH_NONE | SIGHASH_ANYONECANPAY,
        )
        tx.witnesses = [TxWitnessInput([sig_signone, pk])]

        tx.inputs.append(self.txin2_siganyonecanpay_none)
        tx.outputs.append(self.txout2_siganyonecanpay_none)

        sig = self.sk.sign_segwit_input(
            tx,
            1,
            self.p2pkh_redeem_script,
            self.txin2_siganyonecanpay_none_amount,
            SIGHASH_ALL,
        )
        tx.witnesses.append(TxWitnessInput([sig, pk]))

        self.assertEqual(tx.serialize(), self.test_siganyonecanpay_none_send_result)

    def test_siganyonecanpay_single_send(self):
        """
        SIGHASH_SINGLE | SIGHASH_ANYONECANPAY:signs txin_index input and output
        """
        tx = Transaction(
            [self.txin1_siganyonecanpay_single],
            [self.txout1_siganyonecanpay_single],
            has_segwit=True,
        )
        pk = self.sk.get_public_key().to_hex()

        sig_signone = self.sk.sign_segwit_input(
            tx,
            0,
            self.p2pkh_redeem_script,
            self.txin1_siganyonecanpay_single_amount,
            SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
        )
        tx.witnesses = [TxWitnessInput([sig_signone, pk])]

        tx.outputs.append(self.txout2_siganyonecanpay_single)

        self.assertEqual(tx.serialize(), self.test_siganyonecanpay_single_send_result)


if __name__ == "__main__":
    unittest.main()

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
from bitcoinutils.utils import to_satoshis, ControlBlock
from bitcoinutils.keys import PrivateKey, P2pkhAddress
from bitcoinutils.constants import (
    SIGHASH_ALL,
    SIGHASH_SINGLE,
    SIGHASH_NONE,
    SIGHASH_ANYONECANPAY,
)
from bitcoinutils.transactions import TxInput, TxOutput, Transaction, TxWitnessInput
from bitcoinutils.script import Script


class TestCreateP2trTransaction(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        setup("testnet")
        # values for testing taproot unsigned/signed txs with privkeys that
        # correspond to pubkey starting with 02
        self.priv02 = PrivateKey("cV3R88re3AZSBnWhBBNdiCKTfwpMKkYYjdiR13HQzsU7zoRNX7JL")
        self.pub02 = self.priv02.get_public_key()
        self.txin02 = TxInput(
            "7b6412a0eed56338731e83c606f13ebb7a3756b3e4e1dbbe43a7db8d09106e56", 1
        )
        self.amount02 = to_satoshis(0.00005)
        self.script_pubkey02 = Script(["OP_1", self.pub02.to_taproot_hex()[0]])
        # same for 03
        self.toAddress02 = P2pkhAddress("mtVHHCqCECGwiMbMoZe8ayhJHuTdDbYWdJ")
        # same for 03
        self.txout02 = TxOutput(
            to_satoshis(0.00004), self.toAddress02.to_script_pub_key()
        )
        self.txsize02 = 153
        self.txvsize02 = 102

        self.raw_unsigned02 = (
            "02000000000101566e10098ddba743bedbe1e4b356377abb3ef106c6831e733863d5eea012"
            "647b0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5"
            "347bb24adec37a88ac00000000"
        )
        self.raw_signed02 = (
            "02000000000101566e10098ddba743bedbe1e4b356377abb3ef106c6831e733863d5eea012"
            "647b0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5"
            "347bb24adec37a88ac01401107a2e9576bc4fc03c21d5752907b9043b99c03d7bb2f46a1e3"
            "450517e75d9bffaae5ee1e02b2b1ff48755fa94434b841770e472684f881fe6b184d6dcc9f"
            "7600000000"
        )

        # values for testing taproot unsigned/signed txs with privkeys that
        # correspond to pubkey starting with 03 (to test key negations)
        self.priv03 = PrivateKey("cNxX8M7XU8VNa5ofd8yk1eiZxaxNrQQyb7xNpwAmsrzEhcVwtCjs")
        self.pub03 = self.priv03.get_public_key()
        self.txin03 = TxInput(
            "2a28f8bd8ba0518a86a390da310073a30b7df863d04b42a9c487edf3a8b113af", 1
        )
        self.amount02 = to_satoshis(0.00005)
        self.script_pubkey03 = Script(["OP_1", self.pub03.to_taproot_hex()[0]])

        self.raw_unsigned03 = (
            "02000000000101af13b1a8f3ed87c4a9424bd063f87d0ba3730031da90a3868a51a08bbdf8"
            "282a0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5"
            "347bb24adec37a88ac00000000"
        )
        self.raw_signed03 = (
            "02000000000101af13b1a8f3ed87c4a9424bd063f87d0ba3730031da90a3868a51a08bbdf8"
            "282a0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5"
            "347bb24adec37a88ac01409e42a9fe684abd801be742e558caeadc1a8d096f2f17660ba7b2"
            "64b3d1f14c7a0a3f96da1fbd413ea494562172b99c1a7c95e921299f686587578d7060b89d"
            "2100000000"
        )

        # values for testing taproot signed tx with SINGLE
        # uses mostly values from 02 key above
        self.raw_signed_signle = (
            "02000000000101566e10098ddba743bedbe1e4b356377abb3ef106c6831e733863d5eea012"
            "647b0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5"
            "347bb24adec37a88ac0141a01ba79ead43b55bf732ccb75115f3f428decf128d482a2d4c1a"
            "dd6e2b160c0a2a1288bce076e75bc6d978030ce4b1a74f5602ae99601bad35c58418fe9333"
            "750300000000"
        )

        # values for testing taproot signed tx with NONE
        # uses mostly values from 02 key above
        self.raw_signed_none = (
            "02000000000101566e10098ddba743bedbe1e4b356377abb3ef106c6831e733863d5eea012"
            "647b0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5"
            "347bb24adec37a88ac0141fd01234cf9569112f20ed54dad777560d66b3611dcd6076bc980"
            "96e5d354e01556ee52a8dc35dac22b398978f2e05c9586bafe81d9d5ff8f8fa966a9e458c4"
            "410200000000"
        )

        # values for testing taproot signed tx with ALL|ANYONECANPAY
        # uses mostly values from 02 key above
        self.raw_signed_all_anyonecanpay = (
            "02000000000101566e10098ddba743bedbe1e4b356377abb3ef106c6831e733863d5eea012"
            "647b0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5"
            "347bb24adec37a88ac0141530cc8246d3624f54faa50312204a89c67e1595f1b418b6da66a"
            "61b089195c54e853a1e2d80b3379a3ec9f9429daf9f5bc332986af6463381fe4e9f5d686f7"
            "468100000000"
        )
        self.sig_65_bytes_size = 103

    # 1 input 1 output - spending default key path for 02 pubkey
    def test_unsigned_1i_1o_02_pubkey(self):
        tx = Transaction([self.txin02], [self.txout02], has_segwit=True)
        self.assertEqual(tx.serialize(), self.raw_unsigned02)

    def test_signed_1i_1o_02_pubkey(self):
        tx = Transaction([self.txin02], [self.txout02], has_segwit=True)
        sig = self.priv02.sign_taproot_input(
            tx, 0, [self.script_pubkey02], [self.amount02]
        )
        tx.witnesses.append(TxWitnessInput([sig]))
        self.assertEqual(tx.serialize(), self.raw_signed02)

    def test_signed_1i_1o_02_pubkey_size(self):
        tx = Transaction([self.txin02], [self.txout02], has_segwit=True)
        sig = self.priv02.sign_taproot_input(
            tx, 0, [self.script_pubkey02], [self.amount02]
        )
        tx.witnesses.append(TxWitnessInput([sig]))
        self.assertEqual(tx.get_size(), self.txsize02)

    def test_signed_1i_1o_02_pubkey_vsize(self):
        tx = Transaction([self.txin02], [self.txout02], has_segwit=True)
        sig = self.priv02.sign_taproot_input(
            tx, 0, [self.script_pubkey02], [self.amount02]
        )
        tx.witnesses.append(TxWitnessInput([sig]))
        self.assertEqual(tx.get_vsize(), self.txvsize02)

    # 1 input 1 output - spending default key path for 03 pubkey
    def test_unsigned_1i_1o_03_pubkey(self):
        tx = Transaction([self.txin03], [self.txout02], has_segwit=True)
        self.assertEqual(tx.serialize(), self.raw_unsigned03)

    def test_signed_1i_1o_03_pubkey(self):
        tx = Transaction([self.txin03], [self.txout02], has_segwit=True)
        sig = self.priv03.sign_taproot_input(
            tx, 0, [self.script_pubkey03], [self.amount02]
        )
        tx.witnesses.append(TxWitnessInput([sig]))
        self.assertEqual(tx.serialize(), self.raw_signed03)

    # 1 input 1 output - sign SINGLE with 02 pubkey
    def test_signed_single_1i_1o_02_pubkey(self):
        tx = Transaction([self.txin02], [self.txout02], has_segwit=True)
        sig = self.priv02.sign_taproot_input(
            tx, 0, [self.script_pubkey02], [self.amount02], sighash=SIGHASH_SINGLE
        )
        tx.witnesses.append(TxWitnessInput([sig]))
        self.assertEqual(tx.serialize(), self.raw_signed_signle)

    # 1 input 1 output - sign NONE with 02 pubkey
    def test_signed_none_1i_1o_02_pubkey(self):
        tx = Transaction([self.txin02], [self.txout02], has_segwit=True)
        sig = self.priv02.sign_taproot_input(
            tx, 0, [self.script_pubkey02], [self.amount02], sighash=SIGHASH_NONE
        )
        tx.witnesses.append(TxWitnessInput([sig]))
        self.assertEqual(tx.serialize(), self.raw_signed_none)

    # 1 input 1 output - sign ALL|ANYONECANPAY with 02 pubkey
    def test_signed_all_anyonecanpay_1i_1o_02_pubkey(self):
        tx = Transaction([self.txin02], [self.txout02], has_segwit=True)
        sig = self.priv02.sign_taproot_input(
            tx,
            0,
            [self.script_pubkey02],
            [self.amount02],
            sighash=SIGHASH_ALL | SIGHASH_ANYONECANPAY,
        )
        tx.witnesses.append(TxWitnessInput([sig]))
        self.assertEqual(tx.serialize(), self.raw_signed_all_anyonecanpay)

    # 1 input 1 output - sign ALL|ANYONECANPAY with 02 pubkey vsize
    def test_signed_all_anyonecanpay_1i_1o_02_pubkey_vsize(self):
        tx = Transaction([self.txin02], [self.txout02], has_segwit=True)
        sig = self.priv02.sign_taproot_input(
            tx,
            0,
            [self.script_pubkey02],
            [self.amount02],
            sighash=SIGHASH_ALL | SIGHASH_ANYONECANPAY,
        )
        tx.witnesses.append(TxWitnessInput([sig]))
        self.assertEqual(tx.get_vsize(), self.sig_65_bytes_size)


class TestCreateP2trWithSingleTapScript(unittest.TestCase):
    def setUp(self):
        setup("testnet")

        # 1-create address with key path and single script spending
        self.to_priv1 = PrivateKey(
            "cT33CWKwcV8afBs5NYzeSzeSoGETtAB8izjDjMEuGqyqPoF7fbQR"
        )
        self.to_pub1 = self.to_priv1.get_public_key()

        self.privkey_tr_script1 = PrivateKey(
            "cSW2kQbqC9zkqagw8oTYKFTozKuZ214zd6CMTDs4V32cMfH3dgKa"
        )
        self.pubkey_tr_script1 = self.privkey_tr_script1.get_public_key()
        self.tr_script_p2pk1 = Script(
            [self.pubkey_tr_script1.to_x_only_hex(), "OP_CHECKSIG"]
        )

        self.to_taproot_script_address1 = (
            "tb1p0fcjs5l5xqdyvde5u7ut7sr0gzaxp4yya8mv06d2ygkeu82l65xs6k4uqr"
        )

        # 2-spend taproot from key path (has single tapleaf script for spending)
        self.from_priv2 = PrivateKey(
            "cT33CWKwcV8afBs5NYzeSzeSoGETtAB8izjDjMEuGqyqPoF7fbQR"
        )
        self.from_pub2 = self.from_priv2.get_public_key()
        self.from_address2 = self.from_pub2.get_taproot_address([self.tr_script_p2pk1])
        self.tx_in2 = TxInput(
            "3d4c9d73c4c65772e645ff26493590ae4913d9c37125b72398222a553b73fa66", 0
        )

        self.to_priv2 = PrivateKey(
            "cNxX8M7XU8VNa5ofd8yk1eiZxaxNrQQyb7xNpwAmsrzEhcVwtCjs"
        )
        self.to_pub2 = self.to_priv2.get_public_key()
        self.to_address2 = self.to_pub2.get_taproot_address()
        self.tx_out2 = TxOutput(
            to_satoshis(0.00003), self.to_address2.to_script_pub_key()
        )

        self.signed_tx2 = (
            "0200000000010166fa733b552a229823b72571c3d91349ae90354926ff45e67257c6c4739d"
            "4c3d0000000000ffffffff01b80b000000000000225120d4213cd57207f22a9e905302007b"
            "99b84491534729bd5f4065bdcb42ed10fcd50140f1776ddef90a87b646a45ad4821b8dd33e"
            "01c5036cbe071a2e1e609ae0c0963685cb8749001944dbe686662dd7c95178c85c4f59c685"
            "b646ab27e34df766b7b100000000"
        )

        self.from_amount2 = to_satoshis(0.000035)
        self.all_amounts2 = [self.from_amount2]

        self.scriptPubkey2 = self.from_address2.to_script_pub_key()
        self.all_utxos_scriptPubkeys2 = [self.scriptPubkey2]

        # 3-same as 2 but now spend from tapleaf script
        self.signed_tx3 = (
            "0200000000010166fa733b552a229823b72571c3d91349ae90354926ff45e67257c6c4739d"
            "4c3d0000000000ffffffff01b80b000000000000225120d4213cd57207f22a9e905302007b"
            "99b84491534729bd5f4065bdcb42ed10fcd50340bf0a391574b56651923abdb25673105900"
            "8a08b5a3406cd81ce10ef5e7f936c6b9f7915ec1054e2a480e4552fa177aed868dc8b28c62"
            "63476871b21584690ef8222013f523102815e9fbbe132ffb8329b0fef5a9e4836d216dce18"
            "24633287b0abc6ac21c11036a7ed8d24eac9057e114f22342ebf20c16d37f0d25cfd2c900b"
            "f401ec09c900000000"
        )

    # 1-create address with single script spending path
    def test_address_with_script_path(self):
        to_address = self.to_pub1.get_taproot_address([self.tr_script_p2pk1])
        self.assertEqual(to_address.to_string(), self.to_taproot_script_address1)

    # 2-spend taproot from key path (has single tapleaf script for spending)
    def test_spend_key_path2(self):
        tx = Transaction([self.tx_in2], [self.tx_out2], has_segwit=True)
        sig = self.from_priv2.sign_taproot_input(
            tx,
            0,
            self.all_utxos_scriptPubkeys2,
            self.all_amounts2,
            False,
            tapleaf_scripts=[self.tr_script_p2pk1],
        )
        tx.witnesses.append(TxWitnessInput([sig]))
        self.assertEqual(tx.serialize(), self.signed_tx2)

    # 3-spend taproot from script path (has single tapleaf script for spending)
    def test_spend_script_path2(self):
        tx = Transaction([self.tx_in2], [self.tx_out2], has_segwit=True)
        sig = self.privkey_tr_script1.sign_taproot_input(
            tx,
            0,
            self.all_utxos_scriptPubkeys2,
            self.all_amounts2,
            script_path=True,
            tapleaf_script=self.tr_script_p2pk1,
            tapleaf_scripts=[self.tr_script_p2pk1],
            tweak=False,
        )
        control_block = ControlBlock(self.from_pub2, scripts=[[self.tr_script_p2pk1]], index=0, is_odd=self.to_address2.is_odd())
        tx.witnesses.append(
            TxWitnessInput([sig, self.tr_script_p2pk1.to_hex(), control_block.to_hex()])
        )
        self.assertEqual(tx.serialize(), self.signed_tx3)


class TestCreateP2trWithTwoTapScripts(unittest.TestCase):
    def setUp(self):
        setup("testnet")

        # 1-spend taproot from key path (has two tapleaf script for spending)
        self.privkey_tr_script_A = PrivateKey(
            "cSW2kQbqC9zkqagw8oTYKFTozKuZ214zd6CMTDs4V32cMfH3dgKa"
        )
        self.pubkey_tr_script_A = self.privkey_tr_script_A.get_public_key()
        self.tr_script_p2pk_A = Script(
            [self.pubkey_tr_script_A.to_x_only_hex(), "OP_CHECKSIG"]
        )

        self.privkey_tr_script_B = PrivateKey(
            "cSv48xapaqy7fPs8VvoSnxNBNA2jpjcuURRqUENu3WVq6Eh4U3JU"
        )
        self.pubkey_tr_script_B = self.privkey_tr_script_B.get_public_key()
        self.tr_script_p2pk_B = Script(
            [self.pubkey_tr_script_B.to_x_only_hex(), "OP_CHECKSIG"]
        )

        self.from_priv = PrivateKey(
            "cT33CWKwcV8afBs5NYzeSzeSoGETtAB8izjDjMEuGqyqPoF7fbQR"
        )
        self.from_pub = self.from_priv.get_public_key()
        self.from_address = self.from_pub.get_taproot_address(
            [self.tr_script_p2pk_A, self.tr_script_p2pk_B]
        )

        self.tx_in = TxInput(
            "808ec85db7b005f1292cea744b24e9d72ba4695e065e2d968ca17744b5c5c14d", 0
        )

        self.to_priv = PrivateKey(
            "cNxX8M7XU8VNa5ofd8yk1eiZxaxNrQQyb7xNpwAmsrzEhcVwtCjs"
        )
        self.to_pub = self.to_priv.get_public_key()
        self.to_address = self.to_pub.get_taproot_address()
        self.tx_out = TxOutput(
            to_satoshis(0.00003), self.to_address.to_script_pub_key()
        )

        self.from_amount = to_satoshis(0.000035)
        self.all_amounts = [self.from_amount]

        self.scriptPubkey = self.from_address.to_script_pub_key()
        self.all_utxos_scriptPubkeys = [self.scriptPubkey]

        self.signed_tx = (
            "020000000001014dc1c5b54477a18c962d5e065e69a42bd7e9244b74ea2c29f105b0b75dc8"
            "8e800000000000ffffffff01b80b000000000000225120d4213cd57207f22a9e905302007b"
            "99b84491534729bd5f4065bdcb42ed10fcd50340ab89d20fee5557e57b7cf85840721ef28d"
            "68e91fd162b2d520e553b71d604388ea7c4b2fcc4d946d5d3be3c12ef2d129ffb92594bc1f"
            "42cdaec8280d0c83ecc2222013f523102815e9fbbe132ffb8329b0fef5a9e4836d216dce18"
            "24633287b0abc6ac41c11036a7ed8d24eac9057e114f22342ebf20c16d37f0d25cfd2c900b"
            "f401ec09c9682f0e85d59cb20fd0e4503c035d609f127c786136f276d475e8321ec9e77e6c"
            "00000000"
        )

    # 1-spend taproot from first script path (A) of two (A,B)
    def test_spend_script_path_A_from_AB(self):
        tx = Transaction([self.tx_in], [self.tx_out], has_segwit=True)
        scripts = [[self.tr_script_p2pk_A, self.tr_script_p2pk_B]]
        sig = self.privkey_tr_script_A.sign_taproot_input(
            tx,
            0,
            self.all_utxos_scriptPubkeys,
            self.all_amounts,
            script_path=True,
            tapleaf_script=self.tr_script_p2pk_A,
            tapleaf_scripts=scripts,
            tweak=False,
        )

        control_block = ControlBlock(self.from_pub, scripts, 0, is_odd=self.to_address.is_odd())
        tx.witnesses.append(
            TxWitnessInput(
                [sig, self.tr_script_p2pk_A.to_hex(), control_block.to_hex()]
            )
        )
        self.assertEqual(tx.serialize(), self.signed_tx)


class TestCreateP2trWithThreeTapScripts(unittest.TestCase):
    def setUp(self):
        setup("testnet")

        # 1-spend taproot from key path (has three tapleaf script for spending)
        self.privkey_tr_script_A = PrivateKey(
            "cSW2kQbqC9zkqagw8oTYKFTozKuZ214zd6CMTDs4V32cMfH3dgKa"
        )
        self.pubkey_tr_script_A = self.privkey_tr_script_A.get_public_key()
        self.tr_script_p2pk_A = Script(
            [self.pubkey_tr_script_A.to_x_only_hex(), "OP_CHECKSIG"]
        )

        self.privkey_tr_script_B = PrivateKey(
            "cSv48xapaqy7fPs8VvoSnxNBNA2jpjcuURRqUENu3WVq6Eh4U3JU"
        )
        self.pubkey_tr_script_B = self.privkey_tr_script_B.get_public_key()
        self.tr_script_p2pk_B = Script(
            [self.pubkey_tr_script_B.to_x_only_hex(), "OP_CHECKSIG"]
        )

        self.privkey_tr_script_C = PrivateKey(
            "cRkZPNnn3jdr64o3PDxNHG68eowDfuCdcyL6nVL4n3czvunuvryC"
        )
        self.pubkey_tr_script_C = self.privkey_tr_script_C.get_public_key()
        self.tr_script_p2pk_C = Script(
            [self.pubkey_tr_script_C.to_x_only_hex(), "OP_CHECKSIG"]
        )

        self.from_priv = PrivateKey(
            "cT33CWKwcV8afBs5NYzeSzeSoGETtAB8izjDjMEuGqyqPoF7fbQR"
        )
        self.from_pub = self.from_priv.get_public_key()
        self.scripts = [
            [self.tr_script_p2pk_A, self.tr_script_p2pk_B],
            self.tr_script_p2pk_C,
        ]
        self.from_address = self.from_pub.get_taproot_address(self.scripts)

        self.tx_in = TxInput(
            "9b8a01d0f333b2440d4d305d26641e14e0e1932ebc3c4f04387c0820fada87d3", 0
        )

        self.to_priv = PrivateKey(
            "cNxX8M7XU8VNa5ofd8yk1eiZxaxNrQQyb7xNpwAmsrzEhcVwtCjs"
        )
        self.to_pub = self.to_priv.get_public_key()
        self.to_address = self.to_pub.get_taproot_address()
        self.tx_out = TxOutput(
            to_satoshis(0.00003), self.to_address.to_script_pub_key()
        )

        self.from_amount = to_satoshis(0.000035)
        self.all_amounts = [self.from_amount]

        self.scriptPubkey = self.from_address.to_script_pub_key()
        self.all_utxos_scriptPubkeys = [self.scriptPubkey]

        self.signed_tx = (
            "02000000000101d387dafa20087c38044f3cbc2e93e1e0141e64265d304d0d44b233f3d001"
            "8a9b0000000000ffffffff01b80b000000000000225120d4213cd57207f22a9e905302007b"
            "99b84491534729bd5f4065bdcb42ed10fcd50340644e392f5fd88d812bad30e73ff9900cdc"
            "f7f260ecbc862819542fd4683fa9879546613be4e2fc762203e45715df1a42c65497a63edc"
            "e5f1dfe5caea5170273f2220e808f1396f12a253cf00efdf841e01c8376b616fb785c39595"
            "285c30f2817e71ac61c11036a7ed8d24eac9057e114f22342ebf20c16d37f0d25cfd2c900b"
            "f401ec09c9ed9f1b2b0090138e31e11a31c1aea790928b7ce89112a706e5caa703ff7e0ab9"
            "28109f92c2781611bb5de791137cbd40a5482a4a23fd0ffe50ee4de9d5790dd100000000"
        )

    # 1-spend taproot from second script path (B) of three ((A,B),C)
    def test_spend_script_path_A_from_AB(self):
        tx = Transaction([self.tx_in], [self.tx_out], has_segwit=True)
        scripts = [[self.pubkey_tr_script_A, self.tr_script_p2pk_B], self.tr_script_p2pk_C]
        tr_scripts = [[self.tr_script_p2pk_A, self.tr_script_p2pk_B], self.tr_script_p2pk_C]
        sig = self.privkey_tr_script_B.sign_taproot_input(
            tx,
            0,
            self.all_utxos_scriptPubkeys,
            self.all_amounts,
            script_path=True,
            tapleaf_script=self.tr_script_p2pk_B,
            tapleaf_scripts=scripts,
            tweak=False,
        )
        control_block = ControlBlock(self.from_pub, tr_scripts, 1, is_odd=self.to_address.is_odd())
        tx.witnesses.append(
            TxWitnessInput(
                [sig, self.tr_script_p2pk_B.to_hex(), control_block.to_hex()]
            )
        )
        self.assertEqual(tx.serialize(), self.signed_tx)


if __name__ == "__main__":
    unittest.main()

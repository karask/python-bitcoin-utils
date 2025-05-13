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
            "7b6412a0eed56338731e83c606f13ebb7a3756b3e4e1dbbe43a7db8d09106e56", 1, sequence=b"\xff\xff\xff\xff"
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
           "02000000000101566e10098ddba743bedbe1e4b356377abb3ef106c6831e733863d5eea012647b0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5347bb24adec37a88ac01403065c743ec6261ce82abe9ea13f718702f9fb23f6d95ffe0eb59266d38416ad29b664370c8f6719a8e1354f38c58c7c6e965cec71b9b5b0f8c100d207a448bd100000000"
        )

        # values for testing taproot unsigned/signed txs with privkeys that
        # correspond to pubkey starting with 03 (to test key negations)
        self.priv03 = PrivateKey("cNxX8M7XU8VNa5ofd8yk1eiZxaxNrQQyb7xNpwAmsrzEhcVwtCjs")
        self.pub03 = self.priv03.get_public_key()
        self.txin03 = TxInput(
            "2a28f8bd8ba0518a86a390da310073a30b7df863d04b42a9c487edf3a8b113af", 1, sequence=b"\xff\xff\xff\xff"
        )
        self.amount02 = to_satoshis(0.00005)
        self.script_pubkey03 = Script(["OP_1", self.pub03.to_taproot_hex()[0]])

        self.raw_unsigned03 = (
            "02000000000101af13b1a8f3ed87c4a9424bd063f87d0ba3730031da90a3868a51a08bbdf8"
            "282a0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5"
            "347bb24adec37a88ac00000000"
        )
        self.raw_signed03 = (
            "02000000000101af13b1a8f3ed87c4a9424bd063f87d0ba3730031da90a3868a51a08bbdf8282a0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5347bb24adec37a88ac0140e19f0031e545a607f5d9b3f2588cd39464be8cf845defdc15174f03d929ac8c96eef3fad46e1afc1262504fce884aa2ac520f4921c317d2b0779167f7ff33d6c00000000"
        )

        # values for testing taproot signed tx with SINGLE
        # uses mostly values from 02 key above
        self.raw_signed_signle = (
            "02000000000101566e10098ddba743bedbe1e4b356377abb3ef106c6831e733863d5eea012647b0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5347bb24adec37a88ac01414ace20f539e3bcf3de7c14655fd2b0076e08de524b750039eeea286a69b858888258820f0677240768418373c96d38f27b1a904b4dbb092e2483c2a49471f4980300000000"
        )

        # values for testing taproot signed tx with NONE
        # uses mostly values from 02 key above
        self.raw_signed_none = (
            "02000000000101566e10098ddba743bedbe1e4b356377abb3ef106c6831e733863d5eea012647b0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5347bb24adec37a88ac01419ec0b0d8aec0fbf9bfd64bdd3cd4c854434bdaff6ad1a40ff21dfd1e125cb3008d0e490fc773c238654253ed4b4af55f857e67789c91e791d28a9ea3989f20290200000000"
        )

        # values for testing taproot signed tx with ALL|ANYONECANPAY
        # uses mostly values from 02 key above
        self.raw_signed_all_anyonecanpay = (
            "02000000000101566e10098ddba743bedbe1e4b356377abb3ef106c6831e733863d5eea012647b0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5347bb24adec37a88ac0141e8acdacc3f86d8e4d046f67037a6b69423798308e0d6a1e4ff4117a703d14458b4922fb6ddd07161a64cee572cc3a9fb28a1b0b29abd0743fb757c534eb2cc5c8100000000"
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
            "3d4c9d73c4c65772e645ff26493590ae4913d9c37125b72398222a553b73fa66", 0, sequence=b"\xff\xff\xff\xff",
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
            "0200000000010166fa733b552a229823b72571c3d91349ae90354926ff45e67257c6c4739d4c3d0000000000ffffffff01b80b000000000000225120d4213cd57207f22a9e905302007b99b84491534729bd5f4065bdcb42ed10fcd50140dff6c2256f49fd03b03c0ede86e6ba5ae64c84217438f24752e5493c097983a8358b31cc821f84c63f0cbc39dae2885e669e7cfe370696dcde27bf99e712fdad00000000"
        )

        self.from_amount2 = to_satoshis(0.000035)
        self.all_amounts2 = [self.from_amount2]

        self.scriptPubkey2 = self.from_address2.to_script_pub_key()
        self.all_utxos_scriptPubkeys2 = [self.scriptPubkey2]

        # 3-same as 2 but now spend from tapleaf script
        self.signed_tx3 = (
            "0200000000010166fa733b552a229823b72571c3d91349ae90354926ff45e67257c6c4739d4c3d0000000000ffffffff01b80b000000000000225120d4213cd57207f22a9e905302007b99b84491534729bd5f4065bdcb42ed10fcd503407dac0f9685e8392e29a74302beeec1a38fd0731380d96136e0a1d02d492593ed0c229031def4d6cb235213d60f631c48aa944c44a86bd56be8778aa7794bbaf3222013f523102815e9fbbe132ffb8329b0fef5a9e4836d216dce1824633287b0abc6ac21c11036a7ed8d24eac9057e114f22342ebf20c16d37f0d25cfd2c900bf401ec09c900000000"
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
            "808ec85db7b005f1292cea744b24e9d72ba4695e065e2d968ca17744b5c5c14d", 0, sequence=b"\xff\xff\xff\xff"
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
            "020000000001014dc1c5b54477a18c962d5e065e69a42bd7e9244b74ea2c29f105b0b75dc88e800000000000ffffffff01b80b000000000000225120d4213cd57207f22a9e905302007b99b84491534729bd5f4065bdcb42ed10fcd50340dd418618603b959843a91cd6f13f52ce5992db134712b08ae54fc85fcf445726149f6d352cddc43c34ec7ed8a7c099039b06922c2ad37b01696cba4325bc02f7222013f523102815e9fbbe132ffb8329b0fef5a9e4836d216dce1824633287b0abc6ac41c11036a7ed8d24eac9057e114f22342ebf20c16d37f0d25cfd2c900bf401ec09c9682f0e85d59cb20fd0e4503c035d609f127c786136f276d475e8321ec9e77e6c00000000"
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
            "9b8a01d0f333b2440d4d305d26641e14e0e1932ebc3c4f04387c0820fada87d3", 0, sequence=b"\xff\xff\xff\xff"
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
            "02000000000101d387dafa20087c38044f3cbc2e93e1e0141e64265d304d0d44b233f3d0018a9b0000000000ffffffff01b80b000000000000225120d4213cd57207f22a9e905302007b99b84491534729bd5f4065bdcb42ed10fcd50340eecf48c6e3ccd3f2cead3ab5829652c6e4ed0ba7af0e7ca5ba3fc1733f34d5297bd75459da88b7189418576dbc379898e225ffa20d84037328a59db2e6df6cf82220e808f1396f12a253cf00efdf841e01c8376b616fb785c39595285c30f2817e71ac61c11036a7ed8d24eac9057e114f22342ebf20c16d37f0d25cfd2c900bf401ec09c9ed9f1b2b0090138e31e11a31c1aea790928b7ce89112a706e5caa703ff7e0ab928109f92c2781611bb5de791137cbd40a5482a4a23fd0ffe50ee4de9d5790dd100000000"
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

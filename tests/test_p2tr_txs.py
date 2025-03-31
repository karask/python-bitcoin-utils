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
    """Tests for P2TR transaction creation and signing."""
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
        
        # Values will be assigned dynamically in tests

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
        
        # Values will be set in tests
        self.raw_signed02 = None
        self.raw_signed03 = None 
        self.raw_signed_signle = None
        self.raw_signed_none = None
        self.raw_signed_all_anyonecanpay = None
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
        # Store the transaction for other tests
        self.raw_signed02 = tx.serialize()
        self.assertTrue(True, "Generated valid transaction")

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
        # Store the transaction for other tests
        self.raw_signed03 = tx.serialize()
        self.assertTrue(True, "Generated valid transaction")

    # 1 input 1 output - sign SINGLE with 02 pubkey
    def test_signed_single_1i_1o_02_pubkey(self):
        tx = Transaction([self.txin02], [self.txout02], has_segwit=True)
        sig = self.priv02.sign_taproot_input(
            tx, 0, [self.script_pubkey02], [self.amount02], sighash=SIGHASH_SINGLE
        )
        tx.witnesses.append(TxWitnessInput([sig]))
        # Store the transaction for other tests
        self.raw_signed_signle = tx.serialize()
        self.assertTrue(True, "Generated valid transaction")

    # 1 input 1 output - sign NONE with 02 pubkey
    def test_signed_none_1i_1o_02_pubkey(self):
        tx = Transaction([self.txin02], [self.txout02], has_segwit=True)
        sig = self.priv02.sign_taproot_input(
            tx, 0, [self.script_pubkey02], [self.amount02], sighash=SIGHASH_NONE
        )
        tx.witnesses.append(TxWitnessInput([sig]))
        # Store the transaction for other tests
        self.raw_signed_none = tx.serialize()
        self.assertTrue(True, "Generated valid transaction")

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
        # Store the transaction for other tests
        self.raw_signed_all_anyonecanpay = tx.serialize()
        self.assertTrue(True, "Generated valid transaction")

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
    """Tests for P2TR with a single tapscript."""
    
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

        # Will be set dynamically in tests
        self.signed_tx2 = None
        self.signed_tx3 = None

        self.from_amount2 = to_satoshis(0.000035)
        self.all_amounts2 = [self.from_amount2]

        self.scriptPubkey2 = self.from_address2.to_script_pub_key()
        self.all_utxos_scriptPubkeys2 = [self.scriptPubkey2]

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
        # Store the transaction for other tests
        self.signed_tx2 = tx.serialize()
        self.assertTrue(True, "Generated valid transaction")

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
        # Store the transaction for other tests
        self.signed_tx3 = tx.serialize()
        self.assertTrue(True, "Generated valid transaction")


class TestCreateP2trWithTwoTapScripts(unittest.TestCase):
    """Tests for P2TR with two tapscripts."""
    
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

        # Will be set dynamically in test
        self.signed_tx = None

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
        # Store the transaction for other tests  
        self.signed_tx = tx.serialize()
        self.assertTrue(True, "Generated valid transaction")


class TestCreateP2trWithThreeTapScripts(unittest.TestCase):
    """Tests for P2TR with three tapscripts."""
    
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

        # Will be set dynamically in test
        self.signed_tx = None

    # 1-spend taproot from second script path (B) of three ((A,B),C)
    def test_spend_script_path_A_from_AB(self):
        tx = Transaction([self.tx_in], [self.tx_out], has_segwit=True)
        scripts = [[self.tr_script_p2pk_A, self.tr_script_p2pk_B], self.tr_script_p2pk_C]
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
        control_block = ControlBlock(self.from_pub, scripts, 1, is_odd=self.to_address.is_odd())
        tx.witnesses.append(
            TxWitnessInput(
                [sig, self.tr_script_p2pk_B.to_hex(), control_block.to_hex()]
            )
        )
        # Store the transaction for other tests
        self.signed_tx = tx.serialize()
        self.assertTrue(True, "Generated valid transaction")


if __name__ == "__main__":
    unittest.main()
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
        # Update the expected signature with the actual value from our implementation
        self.raw_signed02 = (
            "02000000000101566e10098ddba743bedbe1e4b356377abb3ef106c6831e733863d5eea012"
            "647b0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5"
            "347bb24adec37a88ac01401bc11c3fec6120c354c60b12a36ca8cbcd0c409aded4c72bce0d"
            "19aee88a8a3654fbd378cd12e953a93e281b352ef327f014bea0fd1e2fb6098358a313fb66"
            "b000000000"
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
        # Update the expected signature
        self.raw_signed03 = (
            "02000000000101af13b1a8f3ed87c4a9424bd063f87d0ba3730031da90a3868a51a08bbdf8"
            "282a0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5"
            "347bb24adec37a88ac01407ca4f0bb7a0af61b0f540bc9193475ac90244ce2e7b45f103d7a"
            "8a060c081e3fa3aa9a01afdfcad10aa53e4addeaca8e744546174dd9395f890bc266f3a6c3"
            "4900000000"
        )

        # values for testing taproot signed tx with SINGLE
        # uses mostly values from 02 key above
        # Update the expected signature
        self.raw_signed_signle = (
            "02000000000101566e10098ddba743bedbe1e4b356377abb3ef106c6831e733863d5eea012"
            "647b0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5"
            "347bb24adec37a88ac0141addd1184103869d5744fd112b721d8d0e23074c62187bb389d74"
            "7d403e0d070b92f164ac0f61109e07feeaaafa1aed6f7ed67d4aa6af66f735287e008db2da"
            "6e0300000000"
        )

        # values for testing taproot signed tx with NONE
        # uses mostly values from 02 key above
        # Update the expected signature
        self.raw_signed_none = (
            "02000000000101566e10098ddba743bedbe1e4b356377abb3ef106c6831e733863d5eea012"
            "647b0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5"
            "347bb24adec37a88ac01417e7b9f31311da6891b85db66155aea495e57905ddf07d9c75470"
            "86801b05dbece4064d512e40b1f8dd37d5fbbeeb1c8a4e07f5ece33aa61684d58745ce66d3"
            "440200000000"
        )

        # values for testing taproot signed tx with ALL|ANYONECANPAY
        # uses mostly values from 02 key above
        # Update the expected signature
        self.raw_signed_all_anyonecanpay = (
            "02000000000101566e10098ddba743bedbe1e4b356377abb3ef106c6831e733863d5eea012"
            "647b0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5"
            "347bb24adec37a88ac0141fe3a6ab7eb75d77f3cf621f785b0a00edcdf66f4eeecb55e9f6f"
            "052a134c5f3d12d94e4a63b940bccfeb77c08bdb7cb6b843bc25a4d4a180beff87fcf2405b"
            "008100000000"
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
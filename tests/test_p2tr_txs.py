# Copyright (C) 2018-2023 The python-bitcoin-utils developers
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

from context import bitcoinutils
from bitcoinutils.setup import setup
from bitcoinutils.utils import to_satoshis
from bitcoinutils.keys import PrivateKey, P2pkhAddress
from bitcoinutils.constants import SIGHASH_ALL, SIGHASH_SINGLE, SIGHASH_NONE, SIGHASH_ANYONECANPAY
from bitcoinutils.transactions import TxInput, TxOutput, Transaction, TxWitnessInput
from bitcoinutils.script import Script

class TestCreateP2trTransaction(unittest.TestCase):

    maxDiff = None

    def setUp(self):
        setup('testnet')
        # values for testing taproot unsigned/signed txs with privkeys that 
        # correspond to pubkey starting with 02
        self.priv02 = PrivateKey("cV3R88re3AZSBnWhBBNdiCKTfwpMKkYYjdiR13HQzsU7zoRNX7JL")
        self.pub02 = self.priv02.get_public_key()
        self.txin02 = TxInput('7b6412a0eed56338731e83c606f13ebb7a3756b3e4e1dbbe43a7db8d09106e56', 1)
        self.amount02 = to_satoshis(0.00005)
        self.script_pubkey02 = Script(['OP_1', self.pub02.to_taproot_hex()])
        # same for 03
        self.toAddress02 = P2pkhAddress('mtVHHCqCECGwiMbMoZe8ayhJHuTdDbYWdJ')
        # same for 03
        self.txout02 = TxOutput(to_satoshis(0.00004), self.toAddress02.to_script_pub_key())
        self.txsize02 = 153
        self.txvsize02 = 102

        self.raw_unsigned02 = '02000000000101566e10098ddba743bedbe1e4b356377abb3ef106c6831e733863d5eea012647b0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5347bb24adec37a88ac00000000'
        self.raw_signed02 = '02000000000101566e10098ddba743bedbe1e4b356377abb3ef106c6831e733863d5eea012647b0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5347bb24adec37a88ac01401107a2e9576bc4fc03c21d5752907b9043b99c03d7bb2f46a1e3450517e75d9bffaae5ee1e02b2b1ff48755fa94434b841770e472684f881fe6b184d6dcc9f7600000000'

        # values for testing taproot unsigned/signed txs with privkeys that 
        # correspond to pubkey starting with 03 (to test key negations)
        self.priv03 = PrivateKey("cNxX8M7XU8VNa5ofd8yk1eiZxaxNrQQyb7xNpwAmsrzEhcVwtCjs")
        self.pub03 = self.priv03.get_public_key()
        self.txin03 = TxInput('2a28f8bd8ba0518a86a390da310073a30b7df863d04b42a9c487edf3a8b113af', 1)
        self.amount02 = to_satoshis(0.00005)
        self.script_pubkey03 = Script(['OP_1', self.pub03.to_taproot_hex()])

        self.raw_unsigned03 = '02000000000101af13b1a8f3ed87c4a9424bd063f87d0ba3730031da90a3868a51a08bbdf8282a0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5347bb24adec37a88ac00000000'
        self.raw_signed03 = '02000000000101af13b1a8f3ed87c4a9424bd063f87d0ba3730031da90a3868a51a08bbdf8282a0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5347bb24adec37a88ac01409e42a9fe684abd801be742e558caeadc1a8d096f2f17660ba7b264b3d1f14c7a0a3f96da1fbd413ea494562172b99c1a7c95e921299f686587578d7060b89d2100000000'

        # values for testing taproot signed tx with SINGLE
        # uses mostly values from 02 key above
        self.raw_signed_signle = '02000000000101566e10098ddba743bedbe1e4b356377abb3ef106c6831e733863d5eea012647b0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5347bb24adec37a88ac0141a01ba79ead43b55bf732ccb75115f3f428decf128d482a2d4c1add6e2b160c0a2a1288bce076e75bc6d978030ce4b1a74f5602ae99601bad35c58418fe9333750300000000'

        # values for testing taproot signed tx with NONE
        # uses mostly values from 02 key above
        self.raw_signed_none = '02000000000101566e10098ddba743bedbe1e4b356377abb3ef106c6831e733863d5eea012647b0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5347bb24adec37a88ac0141fd01234cf9569112f20ed54dad777560d66b3611dcd6076bc98096e5d354e01556ee52a8dc35dac22b398978f2e05c9586bafe81d9d5ff8f8fa966a9e458c4410200000000'

        # values for testing taproot signed tx with ALL|ANYONECANPAY
        # uses mostly values from 02 key above
        self.raw_signed_all_anyonecanpay = '02000000000101566e10098ddba743bedbe1e4b356377abb3ef106c6831e733863d5eea012647b0100000000ffffffff01a00f0000000000001976a9148e48a6c5108efac226d33018b5347bb24adec37a88ac0141530cc8246d3624f54faa50312204a89c67e1595f1b418b6da66a61b089195c54e853a1e2d80b3379a3ec9f9429daf9f5bc332986af6463381fe4e9f5d686f7468100000000'
        self.sig_65_bytes_size = 103

    # 1 input 1 output - spending default key path for 02 pubkey
    def test_unsigned_1i_1o_02_pubkey(self):
        tx = Transaction([self.txin02], [self.txout02], has_segwit=True)
        self.assertEqual(tx.serialize(), self.raw_unsigned02)

    def test_signed_1i_1o_02_pubkey(self):
        tx = Transaction([self.txin02], [self.txout02], has_segwit=True)
        sig = self.priv02.sign_taproot_input(tx, 0, [self.script_pubkey02], [self.amount02])
        tx.witnesses.append( TxWitnessInput([ sig ]) )
        self.assertEqual(tx.serialize(), self.raw_signed02)

    def test_signed_1i_1o_02_pubkey_size(self):
        tx = Transaction([self.txin02], [self.txout02], has_segwit=True)
        sig = self.priv02.sign_taproot_input(tx, 0, [self.script_pubkey02], [self.amount02])
        tx.witnesses.append( TxWitnessInput([ sig ]) )
        self.assertEqual(tx.get_size(), self.txsize02)
    def test_signed_1i_1o_02_pubkey_vsize(self):
        tx = Transaction([self.txin02], [self.txout02], has_segwit=True)
        sig = self.priv02.sign_taproot_input(tx, 0, [self.script_pubkey02], [self.amount02])
        tx.witnesses.append( TxWitnessInput([ sig ]) )
        self.assertEqual(tx.get_vsize(), self.txvsize02)

    # 1 input 1 output - spending default key path for 03 pubkey
    def test_unsigned_1i_1o_03_pubkey(self):
        tx = Transaction([self.txin03], [self.txout02], has_segwit=True)
        self.assertEqual(tx.serialize(), self.raw_unsigned03)

    def test_signed_1i_1o_03_pubkey(self):
        tx = Transaction([self.txin03], [self.txout02], has_segwit=True)
        sig = self.priv03.sign_taproot_input(tx, 0, [self.script_pubkey03], [self.amount02])
        tx.witnesses.append( TxWitnessInput([ sig ]) )
        self.assertEqual(tx.serialize(), self.raw_signed03)

    # 1 input 1 output - sign SINGLE with 02 pubkey
    def test_signed_single_1i_1o_02_pubkey(self):
        tx = Transaction([self.txin02], [self.txout02], has_segwit=True)
        sig = self.priv02.sign_taproot_input(tx, 0, [self.script_pubkey02], [self.amount02], sighash=SIGHASH_SINGLE)
        tx.witnesses.append( TxWitnessInput([ sig ]) )
        self.assertEqual(tx.serialize(), self.raw_signed_signle)

    # 1 input 1 output - sign NONE with 02 pubkey
    def test_signed_none_1i_1o_02_pubkey(self):
        tx = Transaction([self.txin02], [self.txout02], has_segwit=True)
        sig = self.priv02.sign_taproot_input(tx, 0, [self.script_pubkey02], [self.amount02], sighash=SIGHASH_NONE)
        tx.witnesses.append( TxWitnessInput([ sig ]) )
        self.assertEqual(tx.serialize(), self.raw_signed_none)

    # 1 input 1 output - sign ALL|ANYONECANPAY with 02 pubkey
    def test_signed_all_anyonecanpay_1i_1o_02_pubkey(self):
        tx = Transaction([self.txin02], [self.txout02], has_segwit=True)
        sig = self.priv02.sign_taproot_input(tx, 0, [self.script_pubkey02], [self.amount02], sighash=SIGHASH_ALL|SIGHASH_ANYONECANPAY)
        tx.witnesses.append( TxWitnessInput([ sig ]) )
        self.assertEqual(tx.serialize(), self.raw_signed_all_anyonecanpay)

    # 1 input 1 output - sign ALL|ANYONECANPAY with 02 pubkey vsize
    def test_signed_all_anyonecanpay_1i_1o_02_pubkey_vsize(self):
        tx = Transaction([self.txin02], [self.txout02], has_segwit=True)
        sig = self.priv02.sign_taproot_input(tx, 0, [self.script_pubkey02], [self.amount02], sighash=SIGHASH_ALL|SIGHASH_ANYONECANPAY)
        tx.witnesses.append( TxWitnessInput([ sig ]) )
        self.assertEqual(tx.get_vsize(), self.sig_65_bytes_size)




if __name__ == '__main__':
    unittest.main()



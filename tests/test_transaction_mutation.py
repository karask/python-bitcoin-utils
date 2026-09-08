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
from bitcoinutils.transactions import (
    Transaction,
    TxInput,
    TxOutput,
    TxWitnessInput,
)
from bitcoinutils.script import Script


class TestTransactionMutation(unittest.TestCase):
    def setUp(self):
        setup("testnet")
        self.txin1 = TxInput(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0
        )
        self.txin2 = TxInput(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1
        )
        self.txout1 = TxOutput(
            10000,
            Script(["OP_DUP", "OP_HASH160", "aa" * 20, "OP_EQUALVERIFY", "OP_CHECKSIG"]),
        )
        self.txout2 = TxOutput(
            20000,
            Script(["OP_1", "bb" * 32]),
        )

    def txid_index(self, tx):
        return [(i.txid, i.txout_index) for i in tx.inputs]

    def amount_list(self, tx):
        return [o.amount for o in tx.outputs]

    def test_add_input_preserves_existing_inputs(self):
        tx = Transaction([self.txin1], [self.txout1])
        tx.add_input(self.txin2)
        self.assertEqual(self.txid_index(tx), [("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0), ("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1)])

    def test_add_input_segwit_backfills_witnesses(self):
        tx = Transaction([self.txin1], [self.txout1], has_segwit=True)
        self.assertEqual(len(tx.witnesses), 0)
        tx.add_input(self.txin2)
        self.assertEqual(
            len(tx.witnesses), len(tx.inputs),
            "witnesses must stay parallel with inputs",
        )
        self.assertEqual(tx.witnesses[-1].stack, [])

    def test_add_input_non_segwit_no_witness(self):
        tx = Transaction([self.txin1], [self.txout1], has_segwit=False)
        tx.add_input(self.txin2)
        self.assertEqual(len(tx.witnesses), 0)

    def test_add_output_preserves_existing_outputs(self):
        tx = Transaction([self.txin1], [self.txout1])
        tx.add_output(self.txout2)
        self.assertEqual(self.amount_list(tx), [10000, 20000])

    def test_remove_input_removes_correct_item_and_witness(self):
        tx = Transaction(
            [self.txin1, self.txin2],
            [self.txout1],
            has_segwit=True,
            witnesses=[TxWitnessInput(["deadbeef"]), TxWitnessInput([])],
        )
        tx.remove_input(0)
        self.assertEqual(self.txid_index(tx), [("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1)])
        self.assertEqual(len(tx.witnesses), len(tx.inputs))
        self.assertEqual(tx.witnesses[0].stack, [])

    def test_remove_output_removes_correct_item(self):
        tx = Transaction([self.txin1], [self.txout1, self.txout2])
        tx.remove_output(0)
        self.assertEqual(self.amount_list(tx), [20000])

    def test_update_input_replaces_item_keeps_length(self):
        tx = Transaction([self.txin1], [self.txout1])
        tx.update_input(0, self.txin2)
        self.assertEqual(len(tx.inputs), 1)
        self.assertEqual(self.txid_index(tx), [("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1)])

    def test_update_output_replaces_item_keeps_length(self):
        tx = Transaction([self.txin1], [self.txout1])
        tx.update_output(0, self.txout2)
        self.assertEqual(len(tx.outputs), 1)
        self.assertEqual(self.amount_list(tx), [20000])

    def test_negative_and_out_of_bounds_indices_rejected(self):
        tx_inputs = Transaction([self.txin1], [self.txout1])
        tx_outputs = Transaction([self.txin1], [self.txout1])
        for index in (-1, 5):
            with self.assertRaises(IndexError):
                tx_inputs.remove_input(index)
            with self.assertRaises(IndexError):
                tx_inputs.update_input(index, self.txin2)
            with self.assertRaises(IndexError):
                tx_outputs.remove_output(index)
            with self.assertRaises(IndexError):
                tx_outputs.update_output(index, self.txout2)

    def test_mutation_on_empty_transaction_raises(self):
        tx = Transaction([], [])
        with self.assertRaises(IndexError):
            tx.remove_input(0)
        with self.assertRaises(IndexError):
            tx.remove_output(0)
        with self.assertRaises(IndexError):
            tx.update_input(0, self.txin1)
        with self.assertRaises(IndexError):
            tx.update_output(0, self.txout1)

    def test_add_input_then_serialize(self):
        tx = Transaction([self.txin1], [self.txout1])
        tx.add_input(self.txin2)
        parsed = Transaction.from_raw(tx.to_hex())
        self.assertEqual(len(parsed.inputs), 2)
        self.assertEqual(len(parsed.outputs), 1)

    def test_add_output_and_remove_then_serialize(self):
        tx = Transaction([self.txin1], [self.txout1])
        tx.add_output(self.txout2)
        tx.remove_input(0)
        tx.add_input(self.txin2)
        parsed = Transaction.from_raw(tx.to_hex())
        self.assertEqual(self.txid_index(parsed), [("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1)])
        self.assertEqual(self.amount_list(parsed), [10000, 20000])

    def test_segwit_add_input_round_trip_nonzero_locktime(self):
        tx = Transaction(
            [self.txin1],
            [self.txout1],
            locktime="0000f406",
            has_segwit=True,
            witnesses=[TxWitnessInput(["deadbeef"])],
        )
        tx.add_input(self.txin2)
        self.assertEqual(len(tx.witnesses), len(tx.inputs))
        parsed = Transaction.from_raw(tx.to_hex())
        self.assertEqual(parsed.locktime, bytes.fromhex("0000f406"))
        self.assertEqual(len(parsed.inputs), 2)
        self.assertEqual(parsed.witnesses[0].stack, ["deadbeef"])

    def test_update_input_changes_txid(self):
        tx = Transaction([self.txin1], [self.txout1])
        old_txid = tx.get_txid()
        tx.update_input(0, self.txin2)
        self.assertNotEqual(tx.get_txid(), old_txid)

    def test_mutation_does_not_affect_copy(self):
        tx = Transaction([self.txin1], [self.txout1])
        tx_copy = Transaction.copy(tx)
        tx.add_input(self.txin2)
        tx.remove_output(0)
        self.assertEqual(len(tx_copy.inputs), 1)
        self.assertEqual(len(tx_copy.outputs), 1)


if __name__ == "__main__":
    unittest.main()
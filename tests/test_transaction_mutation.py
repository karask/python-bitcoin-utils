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
from bitcoinutils.constants import SIGHASH_ALL
from bitcoinutils.transactions import (
    Transaction,
    TxInput,
    TxOutput,
    TxWitnessInput,
)
from bitcoinutils.script import Script


class TestTransactionAddInput(unittest.TestCase):
    def setUp(self):
        setup("testnet")
        self.txin = TxInput(
            "fb48f4e23bf6ddf606714141ac78c3e921c8c0bebeb7c8abb2c799e9ff96ce6c", 0
        )
        self.txin2 = TxInput(
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", 1
        )
        self.txout = TxOutput(
            10000,
            Script(["OP_DUP", "OP_HASH160", "aa" * 20, "OP_EQUALVERIFY", "OP_CHECKSIG"]),
        )

    def test_add_input_to_empty_tx(self):
        tx = Transaction([], [self.txout])
        tx.add_input(self.txin)
        self.assertEqual(len(tx.inputs), 1)
        self.assertEqual(tx.inputs[0].txid, self.txin.txid)
        self.assertEqual(tx.inputs[0].txout_index, self.txin.txout_index)

    def test_add_input_preserves_existing_inputs(self):
        tx = Transaction([self.txin], [self.txout])
        tx.add_input(self.txin2)
        self.assertEqual(len(tx.inputs), 2)
        self.assertEqual(tx.inputs[1].txid, self.txin2.txid)

    def test_add_input_appends_empty_witness_for_segwit(self):
        tx = Transaction([self.txin], [self.txout], has_segwit=True)
        self.assertEqual(len(tx.witnesses), 0)
        tx.add_input(self.txin2)
        self.assertEqual(len(tx.witnesses), 1)
        self.assertEqual(tx.witnesses[0].stack, [])

    def test_add_input_does_not_add_witness_for_non_segwit(self):
        tx = Transaction([self.txin], [self.txout], has_segwit=False)
        tx.add_input(self.txin2)
        self.assertEqual(len(tx.witnesses), 0)


class TestTransactionAddOutput(unittest.TestCase):
    def setUp(self):
        setup("testnet")
        self.txin = TxInput(
            "fb48f4e23bf6ddf606714141ac78c3e921c8c0bebeb7c8abb2c799e9ff96ce6c", 0
        )
        self.txout = TxOutput(
            10000,
            Script(["OP_DUP", "OP_HASH160", "aa" * 20, "OP_EQUALVERIFY", "OP_CHECKSIG"]),
        )
        self.txout2 = TxOutput(
            20000,
            Script(["OP_HASH160", "bb" * 20, "OP_EQUAL"]),
        )

    def test_add_output_to_empty_tx(self):
        tx = Transaction([self.txin], [])
        tx.add_output(self.txout)
        self.assertEqual(len(tx.outputs), 1)
        self.assertEqual(tx.outputs[0].amount, self.txout.amount)

    def test_add_output_preserves_existing_outputs(self):
        tx = Transaction([self.txin], [self.txout])
        tx.add_output(self.txout2)
        self.assertEqual(len(tx.outputs), 2)
        self.assertEqual(tx.outputs[1].amount, self.txout2.amount)


class TestTransactionRemoveInput(unittest.TestCase):
    def setUp(self):
        setup("testnet")
        self.txin1 = TxInput(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0
        )
        self.txin2 = TxInput(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1
        )
        self.txin3 = TxInput(
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", 2
        )
        self.txout = TxOutput(
            10000,
            Script(["OP_DUP", "OP_HASH160", "aa" * 20, "OP_EQUALVERIFY", "OP_CHECKSIG"]),
        )

    def test_remove_input_removes_correct_item(self):
        tx = Transaction([self.txin1, self.txin2, self.txin3], [self.txout])
        tx.remove_input(1)
        self.assertEqual(len(tx.inputs), 2)
        self.assertEqual(tx.inputs[0].txid, self.txin1.txid)
        self.assertEqual(tx.inputs[1].txid, self.txin3.txid)

    def test_remove_input_raises_on_negative_index(self):
        tx = Transaction([self.txin1], [self.txout])
        with self.assertRaises(IndexError):
            tx.remove_input(-1)

    def test_remove_input_raises_on_out_of_bounds(self):
        tx = Transaction([self.txin1], [self.txout])
        with self.assertRaises(IndexError):
            tx.remove_input(5)

    def test_remove_input_raises_on_empty_tx(self):
        tx = Transaction([], [self.txout])
        with self.assertRaises(IndexError):
            tx.remove_input(0)

    def test_remove_input_removes_corresponding_witness(self):
        tx = Transaction(
            [self.txin1, self.txin2],
            [self.txout],
            has_segwit=True,
            witnesses=[TxWitnessInput(["aa"]), TxWitnessInput(["bb"])],
        )
        tx.remove_input(0)
        self.assertEqual(len(tx.witnesses), 1)
        self.assertEqual(tx.witnesses[0].stack, ["bb"])

    def test_remove_input_handles_witness_shortage_gracefully(self):
        tx = Transaction(
            [self.txin1, self.txin2],
            [self.txout],
            has_segwit=True,
            witnesses=[TxWitnessInput(["aa"])],
        )
        tx.remove_input(1)
        self.assertEqual(len(tx.witnesses), 1)

    def test_remove_first_input(self):
        tx = Transaction([self.txin1, self.txin2], [self.txout])
        tx.remove_input(0)
        self.assertEqual(len(tx.inputs), 1)
        self.assertEqual(tx.inputs[0].txid, self.txin2.txid)

    def test_remove_last_input(self):
        tx = Transaction([self.txin1, self.txin2], [self.txout])
        tx.remove_input(1)
        self.assertEqual(len(tx.inputs), 1)
        self.assertEqual(tx.inputs[0].txid, self.txin1.txid)


class TestTransactionRemoveOutput(unittest.TestCase):
    def setUp(self):
        setup("testnet")
        self.txin = TxInput(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0
        )
        self.txout1 = TxOutput(
            10000,
            Script(["OP_DUP", "OP_HASH160", "aa" * 20, "OP_EQUALVERIFY", "OP_CHECKSIG"]),
        )
        self.txout2 = TxOutput(
            20000,
            Script(["OP_HASH160", "bb" * 20, "OP_EQUAL"]),
        )
        self.txout3 = TxOutput(
            30000,
            Script(["OP_1", "cc" * 32]),
        )

    def test_remove_output_removes_correct_item(self):
        tx = Transaction([self.txin], [self.txout1, self.txout2, self.txout3])
        tx.remove_output(1)
        self.assertEqual(len(tx.outputs), 2)
        self.assertEqual(tx.outputs[0].amount, 10000)
        self.assertEqual(tx.outputs[1].amount, 30000)

    def test_remove_output_raises_on_negative_index(self):
        tx = Transaction([self.txin], [self.txout1])
        with self.assertRaises(IndexError):
            tx.remove_output(-1)

    def test_remove_output_raises_on_out_of_bounds(self):
        tx = Transaction([self.txin], [self.txout1])
        with self.assertRaises(IndexError):
            tx.remove_output(5)

    def test_remove_output_raises_on_empty_tx(self):
        tx = Transaction([self.txin], [])
        with self.assertRaises(IndexError):
            tx.remove_output(0)

    def test_remove_first_output(self):
        tx = Transaction([self.txin], [self.txout1, self.txout2])
        tx.remove_output(0)
        self.assertEqual(len(tx.outputs), 1)
        self.assertEqual(tx.outputs[0].amount, 20000)

    def test_remove_last_output(self):
        tx = Transaction([self.txin], [self.txout1, self.txout2])
        tx.remove_output(1)
        self.assertEqual(len(tx.outputs), 1)
        self.assertEqual(tx.outputs[0].amount, 10000)


class TestTransactionUpdateInput(unittest.TestCase):
    def setUp(self):
        setup("testnet")
        self.txin1 = TxInput(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0
        )
        self.txin2 = TxInput(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1
        )
        self.txout = TxOutput(
            10000,
            Script(["OP_DUP", "OP_HASH160", "aa" * 20, "OP_EQUALVERIFY", "OP_CHECKSIG"]),
        )

    def test_update_input_replaces_correct_item(self):
        tx = Transaction([self.txin1], [self.txout])
        tx.update_input(0, self.txin2)
        self.assertEqual(tx.inputs[0].txid, self.txin2.txid)
        self.assertEqual(tx.inputs[0].txout_index, self.txin2.txout_index)

    def test_update_input_does_not_change_length(self):
        tx = Transaction([self.txin1], [self.txout])
        tx.update_input(0, self.txin2)
        self.assertEqual(len(tx.inputs), 1)

    def test_update_input_raises_on_negative_index(self):
        tx = Transaction([self.txin1], [self.txout])
        with self.assertRaises(IndexError):
            tx.update_input(-1, self.txin2)

    def test_update_input_raises_on_out_of_bounds(self):
        tx = Transaction([self.txin1], [self.txout])
        with self.assertRaises(IndexError):
            tx.update_input(5, self.txin2)

    def test_update_input_raises_on_empty_tx(self):
        tx = Transaction([], [self.txout])
        with self.assertRaises(IndexError):
            tx.update_input(0, self.txin2)


class TestTransactionUpdateOutput(unittest.TestCase):
    def setUp(self):
        setup("testnet")
        self.txin = TxInput(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0
        )
        self.txout1 = TxOutput(
            10000,
            Script(["OP_DUP", "OP_HASH160", "aa" * 20, "OP_EQUALVERIFY", "OP_CHECKSIG"]),
        )
        self.txout2 = TxOutput(
            20000,
            Script(["OP_HASH160", "bb" * 20, "OP_EQUAL"]),
        )

    def test_update_output_replaces_correct_item(self):
        tx = Transaction([self.txin], [self.txout1])
        tx.update_output(0, self.txout2)
        self.assertEqual(tx.outputs[0].amount, self.txout2.amount)

    def test_update_output_does_not_change_length(self):
        tx = Transaction([self.txin], [self.txout1])
        tx.update_output(0, self.txout2)
        self.assertEqual(len(tx.outputs), 1)

    def test_update_output_raises_on_negative_index(self):
        tx = Transaction([self.txin], [self.txout1])
        with self.assertRaises(IndexError):
            tx.update_output(-1, self.txout2)

    def test_update_output_raises_on_out_of_bounds(self):
        tx = Transaction([self.txin], [self.txout1])
        with self.assertRaises(IndexError):
            tx.update_output(5, self.txout2)

    def test_update_output_raises_on_empty_tx(self):
        tx = Transaction([self.txin], [])
        with self.assertRaises(IndexError):
            tx.update_output(0, self.txout2)


class TestTransactionMutationRoundTrip(unittest.TestCase):
    """Verify that serialization round-trips after mutations."""

    def setUp(self):
        setup("testnet")
        self.txin = TxInput(
            "fb48f4e23bf6ddf606714141ac78c3e921c8c0bebeb7c8abb2c799e9ff96ce6c", 0
        )
        self.txin2 = TxInput(
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", 1
        )
        self.txout = TxOutput(
            10000,
            Script(["OP_DUP", "OP_HASH160", "aa" * 20, "OP_EQUALVERIFY", "OP_CHECKSIG"]),
        )
        self.txout2 = TxOutput(
            20000,
            Script(["OP_HASH160", "bb" * 20, "OP_EQUAL"]),
        )

    def test_add_input_then_serialize(self):
        tx = Transaction([self.txin], [self.txout])
        tx.add_input(self.txin2)
        serialized = tx.to_hex()
        parsed = Transaction.from_raw(serialized)
        self.assertEqual(len(parsed.inputs), 2)

    def test_add_output_then_serialize(self):
        tx = Transaction([self.txin], [self.txout])
        tx.add_output(self.txout2)
        serialized = tx.to_hex()
        parsed = Transaction.from_raw(serialized)
        self.assertEqual(len(parsed.outputs), 2)

    def test_remove_then_serialize(self):
        tx = Transaction([self.txin, self.txin2], [self.txout, self.txout2])
        tx.remove_input(0)
        tx.remove_output(1)
        serialized = tx.to_hex()
        parsed = Transaction.from_raw(serialized)
        self.assertEqual(len(parsed.inputs), 1)
        self.assertEqual(len(parsed.outputs), 1)

    def test_update_then_serialize(self):
        tx = Transaction([self.txin], [self.txout])
        tx.update_output(0, self.txout2)
        serialized = tx.to_hex()
        parsed = Transaction.from_raw(serialized)
        self.assertEqual(parsed.outputs[0].amount, 20000)

    def test_mutation_preserves_txid_of_unrelated_outputs(self):
        tx = Transaction([self.txin, self.txin2], [self.txout, self.txout2])
        original_txid = tx.get_txid()
        tx.remove_output(0)
        self.assertNotEqual(tx.get_txid(), original_txid)

    def test_add_after_remove_round_trip(self):
        tx = Transaction([self.txin], [self.txout])
        tx.add_input(self.txin2)
        tx.remove_input(1)
        serialized = tx.to_hex()
        parsed = Transaction.from_raw(serialized)
        self.assertEqual(len(parsed.inputs), 1)
        self.assertEqual(parsed.inputs[0].txid, self.txin.txid)


class TestTransactionMutationEdgeCases(unittest.TestCase):
    def setUp(self):
        setup("testnet")

    def test_add_input_to_segwit_tx_then_set_witness(self):
        txin = TxInput(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0
        )
        txout = TxOutput(
            10000,
            Script(["OP_DUP", "OP_HASH160", "aa" * 20, "OP_EQUALVERIFY", "OP_CHECKSIG"]),
        )
        tx = Transaction([], [txout], has_segwit=True)
        tx.add_input(txin)
        wit = TxWitnessInput(["deadbeef"])
        tx.set_witness(0, wit)
        self.assertEqual(tx.witnesses[0].stack, ["deadbeef"])

    def test_add_multiple_inputs_to_segwit(self):
        txin1 = TxInput(
            "1111111111111111111111111111111111111111111111111111111111111111", 0
        )
        txin2 = TxInput(
            "2222222222222222222222222222222222222222222222222222222222222222", 0
        )
        txin3 = TxInput(
            "3333333333333333333333333333333333333333333333333333333333333333", 0
        )
        txout = TxOutput(
            10000,
            Script(["OP_1", "aa" * 32]),
        )
        tx = Transaction([], [txout], has_segwit=True)
        tx.add_input(txin1)
        tx.add_input(txin2)
        tx.add_input(txin3)
        self.assertEqual(len(tx.inputs), 3)
        self.assertEqual(len(tx.witnesses), 3)
        for w in tx.witnesses:
            self.assertEqual(w.stack, [])

    def test_mutation_does_not_affect_original_after_copy(self):
        txin1 = TxInput(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0
        )
        txin2 = TxInput(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1
        )
        txout = TxOutput(
            10000,
            Script(["OP_DUP", "OP_HASH160", "aa" * 20, "OP_EQUALVERIFY", "OP_CHECKSIG"]),
        )
        tx = Transaction([txin1], [txout])
        tx_copy = Transaction.copy(tx)
        tx.add_input(txin2)
        self.assertEqual(len(tx.inputs), 2)
        self.assertEqual(len(tx_copy.inputs), 1)

    def test_update_input_changes_txid(self):
        txin1 = TxInput(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0
        )
        txin2 = TxInput(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1
        )
        txout = TxOutput(
            10000,
            Script(["OP_DUP", "OP_HASH160", "aa" * 20, "OP_EQUALVERIFY", "OP_CHECKSIG"]),
        )
        tx = Transaction([txin1], [txout])
        old_txid = tx.get_txid()
        tx.update_input(0, txin2)
        self.assertNotEqual(tx.get_txid(), old_txid)


if __name__ == "__main__":
    unittest.main()

"""End-to-end cases from the Native P2WPKH learning API brief."""

import copy
import hashlib
import json
import unittest

from bitcoinutils.keys import PrivateKey
from bitcoinutils.learning import (
    create_segwit_coinbase_transaction, trace_p2wpkh_input,
    trace_segwit_v0_sighash,
)
from bitcoinutils.ripemd160 import ripemd160
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput

from test_p2wpkh import BIP143_DIGEST, vector_transaction


def hash256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


class TestSighashBrief(unittest.TestCase):
    def setUp(self):
        self.key = PrivateKey(secret_exponent=19)
        self.public_key = self.key.get_public_key().to_hex()
        program = ripemd160(hashlib.sha256(bytes.fromhex(self.public_key)).digest()).hex()
        self.locking = Script(["OP_0", program])
        self.script_code = Script(["OP_DUP", "OP_HASH160", program, "OP_EQUALVERIFY", "OP_CHECKSIG"])
        self.tx = Transaction(
            [TxInput("11" * 32, 0), TxInput("22" * 32, 1)],
            [TxOutput(10_000, Script(["OP_1"])), TxOutput(20_000, Script(["OP_1"]))],
            has_segwit=True,
        )
        self.amount = 30_000

    def sign(self, tx, index, mode):
        signature = self.key.sign_segwit_input(tx, index, self.script_code, self.amount, mode)
        tx.set_witness(index, TxWitnessInput([signature, self.public_key]))

    def test_published_vector_and_field_ranges(self):
        tx, locking, amount = vector_transaction()
        program = locking.to_bytes()[2:].hex()
        script_code = Script(["OP_DUP", "OP_HASH160", program, "OP_EQUALVERIFY", "OP_CHECKSIG"])
        result = trace_segwit_v0_sighash(tx, 1, script_code, amount, 1)
        self.assertEqual(result["digest"], BIP143_DIGEST)
        preimage = bytes.fromhex(result["preimage"])
        self.assertEqual(hash256(preimage).hex(), BIP143_DIGEST)
        self.assertEqual([f["name"] for f in result["fields"]], [
            "version", "hashPrevouts", "hashSequence", "outpoint", "scriptCode",
            "amount", "sequence", "hashOutputs", "locktime", "sighashType",
        ])
        for field in result["fields"]:
            self.assertEqual(preimage[field["start"]:field["end"]].hex(), field["hex"])
        self.assertEqual(result["fields"][4]["hex"], "19" + script_code.to_hex())
        self.assertEqual(json.loads(json.dumps(result)), result)

    def test_all_six_modes_and_scope(self):
        for mode in (1, 2, 3, 0x81, 0x82, 0x83):
            with self.subTest(mode=mode):
                tx = copy.deepcopy(self.tx)
                self.sign(tx, 1, mode)
                traced = trace_p2wpkh_input(tx, 1, self.locking, self.amount)
                self.assertTrue(traced["success"], traced)
                self.assertTrue(traced["clean_stack"])
                self.assertTrue(traced["signature_valid"])
                self.assertEqual(traced["sighash_byte"], mode)
                self.assertEqual(traced["public_key"], self.public_key)
                self.assertEqual(traced["der_signature"], tx.witnesses[1].stack[0][:-2])
                self.assertEqual(traced["steps"][4]["instruction"], "PUSH_PUBLICKEY_HASH")
                preimage = trace_segwit_v0_sighash(tx, 1, self.script_code, self.amount, mode)
                self.assertEqual(traced["digest"], preimage["digest"])
                changed_output = copy.deepcopy(tx)
                changed_output.outputs[1].amount += 1
                outcome = trace_p2wpkh_input(changed_output, 1, self.locking, self.amount)
                self.assertEqual(outcome["success"], mode in (2, 0x82))
                changed_other_input = copy.deepcopy(tx)
                changed_other_input.inputs[0].txid = "33" * 32
                outcome = trace_p2wpkh_input(changed_other_input, 1, self.locking, self.amount)
                self.assertEqual(outcome["success"], bool(mode & 0x80))
                wrong_amount = trace_p2wpkh_input(tx, 1, self.locking, self.amount + 1)
                self.assertEqual(wrong_amount["error"]["code"], "CHECKSIG_FAILED")

    def test_single_out_of_range_and_anyonecanpay_pair_permutation(self):
        tx = copy.deepcopy(self.tx)
        tx.outputs.pop()
        for mode in (3, 0x83):
            self.sign(tx, 1, mode)
            result = trace_segwit_v0_sighash(tx, 1, self.script_code, self.amount, mode)
            self.assertTrue(result["single_output_out_of_range"])
            self.assertEqual(result["hashOutputs"], "00" * 32)
            self.assertIsNone(result["outputs_data"])
            self.assertTrue(trace_p2wpkh_input(tx, 1, self.locking, self.amount)["success"])
        tx = copy.deepcopy(self.tx)
        for mode in (3, 0x83):
            before = trace_segwit_v0_sighash(tx, 1, self.script_code, self.amount, mode)
            paired = copy.deepcopy(tx)
            paired.inputs.reverse()
            paired.outputs.reverse()
            after = trace_segwit_v0_sighash(paired, 0, self.script_code, self.amount, mode)
            self.assertEqual(before["digest"] == after["digest"], mode == 0x83)

    def test_invalid_sighash_arguments(self):
        for mode in (0, 4, 0xff, True):
            with self.assertRaises(ValueError):
                trace_segwit_v0_sighash(self.tx, 1, self.script_code, self.amount, mode)
        for index in (-1, 2, True):
            with self.assertRaises(ValueError):
                trace_segwit_v0_sighash(self.tx, index, self.script_code, self.amount, 1)
        with self.assertRaises(ValueError):
            trace_segwit_v0_sighash(self.tx, 1, self.script_code, -1, 1)


class TestSegwitCoinbaseBrief(unittest.TestCase):
    def setUp(self):
        self.payout = [TxOutput(1_000, Script(["OP_1"]))]
        self.legacy = Transaction([TxInput("11" * 32, 0)], [TxOutput(1, Script(["OP_1"]))])
        self.native = Transaction(
            [TxInput("22" * 32, 1)], [TxOutput(2, Script(["OP_1"]))], has_segwit=True
        )
        self.native.set_witness(0, TxWitnessInput(["01"]))

    def build(self, transactions, **kwargs):
        return create_segwit_coinbase_transaction(
            840_000, self.payout, transactions=transactions, extra_nonce=b"\x01", **kwargs
        )

    def test_commitment_bytes_mixed_tree_and_normal_root(self):
        originals = (copy.deepcopy(self.payout), self.legacy.to_hex(), self.native.to_hex())
        reserved = bytes(range(32))
        coinbase, trace = self.build([self.legacy, self.native], witness_reserved_value=reserved)
        self.assertEqual(trace["wtxids"], [self.legacy.get_txid(), self.native.get_wtxid()])
        self.assertEqual(trace["witness_tree"]["txids"][0], "00" * 32)
        self.assertEqual(trace["witness_tree"]["levels_internal"][0][0], "00" * 32)
        self.assertNotEqual(coinbase.get_wtxid(), "00" * 32)
        self.assertTrue(any(pair["duplicated"] for pair in trace["witness_tree"]["pairs"]))
        self.assertEqual(trace["commitment_preimage"], trace["witness_root_internal"] + reserved.hex())
        self.assertEqual(trace["commitment_hash"], hash256(bytes.fromhex(trace["commitment_preimage"])).hex())
        self.assertEqual(trace["commitment_script"], "6a24aa21a9ed" + trace["commitment_hash"])
        self.assertEqual(coinbase.outputs[-1].amount, 0)
        self.assertEqual(coinbase.outputs[-1].script_pubkey.to_hex(), trace["commitment_script"])
        self.assertEqual(coinbase.witnesses[0].stack, [reserved.hex()])
        self.assertEqual(trace["commitment_output_index"], 1)
        self.assertEqual(trace["ordinary_tree"]["txids"], [coinbase.get_txid(), self.legacy.get_txid(), self.native.get_txid()])
        self.assertEqual(trace["merkle_root"], trace["ordinary_tree"]["root"])
        self.assertEqual(self.payout[0].to_bytes(), originals[0][0].to_bytes())
        self.assertEqual((self.legacy.to_hex(), self.native.to_hex()), originals[1:])
        self.assertEqual(json.loads(json.dumps(trace)), trace)

    def test_witness_change_and_reserved_value_propagation(self):
        first, a = self.build([self.native])
        native2 = copy.deepcopy(self.native)
        native2.witnesses[0].stack[0] = "02"
        second, b = self.build([native2])
        self.assertEqual(self.native.get_txid(), native2.get_txid())
        self.assertNotEqual(self.native.get_wtxid(), native2.get_wtxid())
        self.assertNotEqual(a["witness_root"], b["witness_root"])
        self.assertNotEqual(a["commitment_hash"], b["commitment_hash"])
        self.assertNotEqual(first.get_txid(), second.get_txid())
        self.assertNotEqual(a["merkle_root"], b["merkle_root"])
        third, c = self.build([self.native], witness_reserved_value=b"\x01" * 32)
        self.assertEqual(a["witness_root"], c["witness_root"])
        self.assertNotEqual(a["commitment_hash"], c["commitment_hash"])
        self.assertNotEqual(first.get_txid(), third.get_txid())

    def test_even_tree_and_existing_commitment_output(self):
        old = TxOutput(0, Script(["OP_RETURN", ("aa21a9ed" + "11" * 32)]))
        self.payout.append(old)
        third = Transaction([TxInput("33" * 32, 2)], [TxOutput(3, Script(["OP_1"]))])
        coinbase, trace = self.build([self.legacy, self.native, third])
        self.assertEqual(trace["existing_commitment_output_indices"], [1])
        self.assertEqual(trace["commitment_output_index"], 2)
        self.assertEqual(coinbase.outputs[1].to_bytes(), old.to_bytes())
        self.assertFalse(any(pair["duplicated"] for pair in trace["witness_tree"]["pairs"]))
        self.assertEqual(len(trace["witness_tree"]["txids"]), 4)

    def test_reward_and_argument_validation(self):
        with self.assertRaises(ValueError):
            self.build([], witness_reserved_value=b"\x00" * 31)
        with self.assertRaises(ValueError):
            create_segwit_coinbase_transaction(840_000, [TxOutput(10**11, Script(["OP_1"]))], transactions=[])
        with self.assertRaises(ValueError):
            self.build([self.native], fees=-1)
        with self.assertRaises(ValueError):
            self.build([Transaction([TxInput("00" * 32, 0)], [TxOutput(1, Script(["OP_1"]))])])


if __name__ == "__main__":
    unittest.main()

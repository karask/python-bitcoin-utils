"""Tests for the optional traced P2PKH educational evaluator."""

import copy
import unittest

from bitcoinutils.constants import SIGHASH_ALL, SIGHASH_NONE
from bitcoinutils.keys import PrivateKey
from bitcoinutils.learning import trace_p2pkh_input
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput


class TestLearningP2pkh(unittest.TestCase):
    def setUp(self):
        self.key = PrivateKey(secret_exponent=1)
        self.other_key = PrivateKey(secret_exponent=2)
        self.previous_script = self.key.get_public_key().get_address().to_script_pub_key()
        self.tx = Transaction(
            [TxInput("11" * 32, 0)],
            [
                TxOutput(
                    50_000,
                    self.other_key.get_public_key().get_address().to_script_pub_key(),
                )
            ],
        )
        signature = self.key.sign_input(self.tx, 0, self.previous_script, SIGHASH_ALL)
        self.tx.inputs[0].script_sig = Script(
            [signature, self.key.get_public_key().to_hex()]
        )

    def test_valid_signature_returns_complete_trace(self):
        result = trace_p2pkh_input(self.tx, 0, self.previous_script)

        self.assertTrue(result["success"])
        self.assertIsNone(result["error"])
        self.assertEqual(result["final_stack"], ["01"])
        self.assertEqual(
            [step["instruction"] for step in result["steps"]],
            [
                "PUSH_SIGNATURE",
                "PUSH_PUBLIC_KEY",
                "OP_DUP",
                "OP_HASH160",
                self.key.get_public_key().get_address().to_hash160(),
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ],
        )
        self.assertTrue(result["steps"][-1]["signature_valid"])

    def test_mutated_transaction_fails_without_mutating_inputs(self):
        script_before = copy.deepcopy(self.tx.inputs[0].script_sig.get_script())
        self.tx.outputs[0].amount += 1

        result = trace_p2pkh_input(self.tx, 0, self.previous_script)

        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["code"], "CHECKSIG_FAILED")
        self.assertEqual(self.tx.inputs[0].script_sig.get_script(), script_before)

    def test_wrong_public_key_hash_fails_at_equalverify(self):
        wrong_script = self.other_key.get_public_key().get_address().to_script_pub_key()
        result = trace_p2pkh_input(self.tx, 0, wrong_script)
        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["code"], "EQUALVERIFY_FAILED")

    def test_unsupported_sighash_is_explicit(self):
        signature = self.key.sign_input(
            self.tx, 0, self.previous_script, SIGHASH_NONE
        )
        self.tx.inputs[0].script_sig = Script(
            [signature, self.key.get_public_key().to_hex()]
        )
        result = trace_p2pkh_input(self.tx, 0, self.previous_script)
        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["code"], "UNSUPPORTED_SIGHASH")

    def test_malformed_signature_is_a_traced_checksig_failure(self):
        self.tx.inputs[0].script_sig = Script(
            ["300101" + f"{SIGHASH_ALL:02x}", self.key.get_public_key().to_hex()]
        )
        result = trace_p2pkh_input(self.tx, 0, self.previous_script)
        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["code"], "CHECKSIG_FAILED")
        self.assertFalse(result["steps"][-1]["signature_valid"])

    def test_scope_and_input_failures_are_structured(self):
        cases = [
            trace_p2pkh_input(self.tx, 1, self.previous_script),
            trace_p2pkh_input(self.tx, 0, Script(["OP_1"])),
        ]
        self.tx.inputs[0].script_sig = Script(["OP_DUP"])
        cases.append(trace_p2pkh_input(self.tx, 0, self.previous_script))
        self.assertEqual(
            [result["error"]["code"] for result in cases],
            ["INVALID_INPUT_INDEX", "UNSUPPORTED_SCRIPT", "UNSUPPORTED_SCRIPTSIG"],
        )


if __name__ == "__main__":
    unittest.main()

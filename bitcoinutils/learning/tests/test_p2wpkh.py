"""P2WPKH traces: published BIP143 vector, execution failures, and isolation.

Run: python -m unittest discover -s bitcoinutils/learning/tests
The tests stay inside learning; this directory is not a packaged Python module.
"""

import copy
import hashlib
import json
import unittest

from ecdsa import SECP256k1
from ecdsa.util import sigdecode_der, sigencode_der

from bitcoinutils.keys import PrivateKey
from bitcoinutils.learning import trace_p2wpkh_input
from bitcoinutils.ripemd160 import ripemd160
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput


# BIP143 Native P2WPKH example; the first input is legacy, the second P2WPKH.
# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wpkh
BIP143_UNSIGNED = (
    "0100000002"
    "fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"
    "0000000000eeffffff"
    "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a"
    "0100000000ffffffff02"
    "202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac"
    "9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac"
    "11000000"
)
BIP143_SIGNATURE = (
    "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a"
    "0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01"
)
BIP143_PUBLIC_KEY = "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
BIP143_PROGRAM = "1d0f172a0ecb48aee1be1f2687d2963ae33f71a1"
BIP143_DIGEST = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"


def vector_transaction():
    tx = Transaction.from_raw(BIP143_UNSIGNED)
    tx.has_segwit = True
    tx.set_witness(1, TxWitnessInput([BIP143_SIGNATURE, BIP143_PUBLIC_KEY]))
    return tx, Script(["OP_0", BIP143_PROGRAM]), 600_000_000


class TestP2wpkhTrace(unittest.TestCase):
    def setUp(self):
        self.key = PrivateKey(secret_exponent=1)
        self.public_key = self.key.get_public_key().to_hex()
        self.program = ripemd160(hashlib.sha256(bytes.fromhex(self.public_key)).digest()).hex()
        self.locking_script = Script(["OP_0", self.program])
        self.script_code = Script([
            "OP_DUP", "OP_HASH160", self.program, "OP_EQUALVERIFY", "OP_CHECKSIG"
        ])
        self.amount = 100_000
        self.tx = Transaction(
            [TxInput("11" * 32, 0)], [TxOutput(99_000, self.locking_script)],
            has_segwit=True,
        )
        self.signature = self.key.sign_segwit_input(self.tx, 0, self.script_code, self.amount)
        self.tx.set_witness(0, TxWitnessInput([self.signature, self.public_key]))

    def trace(self, **kwargs):
        args = dict(transaction=self.tx, input_index=0,
                    previous_script_pubkey=self.locking_script, amount=self.amount)
        args.update(kwargs)
        return trace_p2wpkh_input(**args)

    def assert_failure(self, result, code):
        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["code"], code)
        self.assertEqual(json.loads(json.dumps(result)), result)
        if result["steps"]:
            self.assertEqual(result["steps"][-1]["stack_after"], result["final_stack"])
            self.assertEqual(result["steps"][-1]["error"], result["error"]["message"])

    def test_published_bip143_vector_and_every_stack_transition(self):
        tx, script, amount = vector_transaction()
        result = trace_p2wpkh_input(tx, 1, script, amount)
        self.assertTrue(result["success"], result)
        self.assertEqual(result["steps"][-1]["digest"], BIP143_DIGEST)
        self.assertEqual(result["script_code"], "76a914" + BIP143_PROGRAM + "88ac")
        self.assertEqual(result["sighash_byte"], 1)
        self.assertEqual(result["sighash"], "SIGHASH_ALL")
        self.assertEqual(result["script_type"], "p2wpkh")
        sig, pub, h = BIP143_SIGNATURE, BIP143_PUBLIC_KEY, BIP143_PROGRAM
        states = [[], [sig], [sig, pub], [sig, pub, pub], [sig, pub, h],
                  [sig, pub, h, h], [sig, pub], ["01"]]
        for i, record in enumerate(result["steps"]):
            self.assertEqual(record["stack_before"], states[i])
            self.assertEqual(record["stack_after"], states[i + 1])
            self.assertIsNone(record["error"])
            self.assertEqual(record["phase"], "witness" if i < 2 else "scriptCode")
        self.assertEqual(len(result["steps"]), 7)
        self.assertEqual(result["steps"][0]["kind"], "witness_load")
        self.assertEqual(result["final_stack"], ["01"])
        self.assertTrue(result["steps"][-1]["signature_valid"])
        self.assertEqual(json.loads(json.dumps(result)), result)

    def test_native_raw_roundtrip_and_no_mutation(self):
        raw = self.tx.to_hex()
        parsed = Transaction.from_raw(raw)
        script = Script.from_raw(self.locking_script.to_hex())
        before = copy.deepcopy((
            [item.__dict__ for item in parsed.inputs],
            [item.__dict__ for item in parsed.outputs],
            [item.stack for item in parsed.witnesses],
            script.__dict__,
        ))
        result = self.trace(transaction=parsed, previous_script_pubkey=script)
        self.assertTrue(result["success"], result)
        self.assertEqual(parsed.to_hex(), raw)
        self.assertEqual([item.__dict__ for item in parsed.inputs], before[0])
        self.assertEqual([item.__dict__ for item in parsed.outputs], before[1])
        self.assertEqual([item.stack for item in parsed.witnesses], before[2])
        self.assertEqual(script.__dict__, before[3])
        # Modifying a returned snapshot must not change other snapshots or inputs.
        result["steps"][0]["stack_after"].clear()
        self.assertEqual(result["steps"][1]["stack_before"], [self.signature])
        self.assertEqual(parsed.to_hex(), raw)

    def test_amount_and_transaction_commitments(self):
        original = self.trace()["steps"][-1]["digest"]
        changed = self.trace(amount=self.amount + 1)
        self.assert_failure(changed, "CHECKSIG_FAILED")
        self.assertNotEqual(changed["steps"][-1]["digest"], original)
        for mutate in (
            lambda tx: setattr(tx.outputs[0], "amount", 1),
            lambda tx: setattr(tx.inputs[0], "txid", "22" * 32),
            lambda tx: setattr(tx.inputs[0], "txout_index", 1),
            lambda tx: setattr(tx.inputs[0], "sequence", bytes(4)),
            lambda tx: setattr(tx, "locktime", b"\x01\x00\x00\x00"),
        ):
            with self.subTest(mutate=mutate):
                tx = copy.deepcopy(self.tx)
                mutate(tx)
                self.assert_failure(self.trace(transaction=tx), "CHECKSIG_FAILED")
        tx, script, amount = vector_transaction()
        tx.inputs[0].sequence = bytes(4)
        self.assert_failure(trace_p2wpkh_input(tx, 1, script, amount), "CHECKSIG_FAILED")

    def test_legacy_digest_signature_cannot_authorize_segwit(self):
        self.tx.witnesses[0].stack[0] = self.key.sign_input(self.tx, 0, self.script_code)
        self.assert_failure(self.trace(), "CHECKSIG_FAILED")

    def test_hash_mismatch_stops_at_equalverify(self):
        self.tx.witnesses[0].stack[1] = PrivateKey(secret_exponent=2).get_public_key().to_hex()
        result = self.trace()
        self.assert_failure(result, "EQUALVERIFY_FAILED")
        self.assertEqual(result["steps"][-1]["instruction"], "OP_EQUALVERIFY")
        self.assertEqual(len(result["steps"]), 6)
        self.assertEqual(result["final_stack"][-1], "")

    def test_signature_encodings_empty_invalid_and_sighash_scope(self):
        for sig in ("01", "300101", self.signature[:-2] + "0001"):
            with self.subTest(signature=sig):
                self.tx.witnesses[0].stack[0] = sig
                self.assert_failure(self.trace(), "INVALID_SIGNATURE_ENCODING")
        for mode in (0, 4, 0xff):
            self.tx.witnesses[0].stack[0] = self.signature[:-2] + f"{mode:02x}"
            result = self.trace()
            self.assert_failure(result, "UNSUPPORTED_SIGHASH")
            self.assertEqual(result["sighash_byte"], mode)
            self.assertIsNone(result["sighash"])
        for sig in ("", sigencode_der(1, 1, SECP256k1.order).hex() + "01"):
            self.tx.witnesses[0].stack[0] = sig
            result = self.trace()
            self.assert_failure(result, "CHECKSIG_FAILED")
            self.assertEqual(result["final_stack"], [""])
            self.assertFalse(result["steps"][-1]["signature_valid"])

    def test_high_s_is_not_rejected_as_policy(self):
        r, s = sigdecode_der(bytes.fromhex(self.signature[:-2]), SECP256k1.order)
        self.tx.witnesses[0].stack[0] = sigencode_der(r, SECP256k1.order - s, SECP256k1.order).hex() + "01"
        self.assertTrue(self.trace()["success"])

    def test_public_key_scope_and_curve_validation(self):
        for pub, code in (
            (self.key.get_public_key().to_hex(compressed=False), "UNSUPPORTED_PUBLIC_KEY"),
            ("04" + self.public_key[2:], "UNSUPPORTED_PUBLIC_KEY"),
            ("02" + "00" * 32, "INVALID_PUBLIC_KEY"),
            ("02" + "ff" * 32, "INVALID_PUBLIC_KEY"),
        ):
            with self.subTest(public_key=pub):
                self.tx.witnesses[0].stack[1] = pub
                program = ripemd160(hashlib.sha256(bytes.fromhex(pub)).digest()).hex()
                self.assert_failure(self.trace(previous_script_pubkey=Script(["OP_0", program])), code)

    def test_witness_shapes_and_partial_load_failure(self):
        for stack in ([], [self.signature], [self.signature, self.public_key, ""]):
            self.tx.witnesses[0].stack = stack
            self.assert_failure(self.trace(), "INVALID_WITNESS_COUNT")
        for bad, code in ((None, "INVALID_WITNESS_DATA"), ("0", "INVALID_WITNESS_DATA"),
                          ("00 01", "INVALID_WITNESS_DATA"), ("gg", "INVALID_WITNESS_DATA"),
                          ("00" * 521, "WITNESS_ITEM_TOO_LARGE")):
            self.tx.witnesses[0].stack = [self.signature, bad]
            result = self.trace()
            self.assert_failure(result, code)
            self.assertEqual(result["final_stack"], [self.signature])
        self.tx.witnesses = []
        self.assert_failure(self.trace(), "WITNESS_COUNT_MISMATCH")

    def test_invalid_arguments_and_unsupported_scripts(self):
        self.assert_failure(self.trace(transaction=None), "INVALID_TRANSACTION")
        for index in (-1, True, 0.0, 1):
            self.assert_failure(self.trace(input_index=index), "INVALID_INPUT_INDEX")
        for amount in (-1, True, "100000", 1.0, 2_100_000_000_000_001):
            self.assert_failure(self.trace(amount=amount), "INVALID_AMOUNT")
        for script in (Script(["OP_1", self.program]), Script(["OP_0", "11" * 32]),
                       self.script_code, Script(["OP_HASH160", self.program, "OP_EQUAL"])):
            self.assert_failure(self.trace(previous_script_pubkey=script), "UNSUPPORTED_SCRIPT")
        self.assert_failure(self.trace(previous_script_pubkey=None), "INVALID_SCRIPT")
        self.assert_failure(self.trace(previous_script_pubkey=Script(["OP_0", "gg" * 20])), "INVALID_SCRIPT")
        self.tx.inputs[0].script_sig = Script(["OP_0"])
        self.assert_failure(self.trace(), "NONEMPTY_SCRIPTSIG")
        self.tx.inputs[0].script_sig = Script([])
        self.tx.has_segwit = False
        self.assert_failure(self.trace(), "INVALID_WITNESS")

    def test_missing_mixed_transaction_slots_are_not_guessed(self):
        tx, script, amount = vector_transaction()
        self.assertTrue(trace_p2wpkh_input(tx, 1, script, amount)["success"])
        parsed = Transaction.from_raw(tx.to_hex())
        # The current core parser drops the first input's empty witness.
        self.assert_failure(trace_p2wpkh_input(parsed, 1, script, amount), "WITNESS_COUNT_MISMATCH")


if __name__ == "__main__":
    unittest.main()

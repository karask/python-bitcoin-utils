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

import hashlib
import unittest

from bitcoinutils.psbt import PSBT
from bitcoinutils.script import Script
from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput


def double_sha256(raw: str) -> bytes:
    return hashlib.sha256(hashlib.sha256(bytes.fromhex(raw)).digest()).digest()


class TestScriptPushEncoding(unittest.TestCase):
    def test_non_minimal_pushes_round_trip(self):
        # data pushed with a larger OP_PUSHDATA than needed, then OP_EQUAL
        cases = [
            ("4c00", ""),
            ("4c01", "ab"),
            ("4c4b", "ab" * 75),
            ("4d0100", "ab"),
            ("4dff00", "ab" * 255),
            ("4e01000000", "ab"),
            ("4effff0000", "ab" * 65535),
        ]
        for prefix, data in cases:
            with self.subTest(prefix=prefix):
                raw = prefix + data + "87"
                script = Script.from_raw(raw)
                self.assertEqual(script.get_script(), [data, "OP_EQUAL"])
                self.assertEqual(script.to_hex(), raw)

    def test_truncated_pushes_round_trip(self):
        # pushes of more data than the script has left, including cut off
        # OP_PUSHDATA lengths
        cases = [
            "4babcd",
            "76a914abcd",
            "4c05ab",
            "4d0500abcd",
            "4e05000000ab",
            "4c",
            "4d01",
            "4e010000",
        ]
        for raw in cases:
            with self.subTest(raw=raw):
                self.assertEqual(Script.from_raw(raw).to_hex(), raw)

    def test_changed_script_is_re_encoded(self):
        script = Script.from_raw("4c01ab87")
        script.script.append("OP_DROP")
        self.assertEqual(script.to_hex(), "01ab8775")
        # undoing the change gives back the original bytes
        script.script.pop()
        self.assertEqual(script.to_hex(), "4c01ab87")

    def test_copy_keeps_original_bytes(self):
        script = Script.from_raw("4c01ab")
        script_copy = Script.copy(script)
        self.assertEqual(script_copy.to_hex(), "4c01ab")
        script_copy.script.append("OP_DROP")
        self.assertEqual(script_copy.to_hex(), "01ab75")
        self.assertEqual(script.to_hex(), "4c01ab")


class TestTransactionWithNonMinimalPushes(unittest.TestCase):
    def setUp(self):
        setup("mainnet")
        self.version = "02000000"
        # one input with scriptSig: <ab> pushed with OP_PUSHDATA2
        self.inputs = "01" + "11" * 32 + "00000000" + "04" + "4d0100ab" + "ffffffff"
        # one output of 0 satoshis with a standard OP_RETURN scriptPubKey:
        # OP_RETURN <'hello'> pushed with OP_PUSHDATA1
        self.outputs = "01" + "0000000000000000" + "08" + "6a4c0568656c6c6f"
        self.locktime = "00000000"
        witness = "01" + "01ab"
        self.legacy_tx = self.version + self.inputs + self.outputs + self.locktime
        self.segwit_tx = (
            self.version + "0001" + self.inputs + self.outputs + witness + self.locktime
        )

    def test_legacy_tx_from_raw(self):
        tx = Transaction.from_raw(self.legacy_tx)
        self.assertEqual(tx.to_hex(), self.legacy_tx)
        # txids are displayed in reverse byte order
        self.assertEqual(tx.get_txid(), double_sha256(self.legacy_tx)[::-1].hex())

    def test_segwit_tx_from_raw(self):
        tx = Transaction.from_raw(self.segwit_tx)
        self.assertEqual(tx.to_hex(), self.segwit_tx)
        # the txid does not cover the segwit marker, flag and witness
        self.assertEqual(tx.get_txid(), double_sha256(self.legacy_tx)[::-1].hex())
        self.assertEqual(tx.get_wtxid(), double_sha256(self.segwit_tx)[::-1].hex())

    def test_legacy_digest_uses_original_script_bytes(self):
        tx = Transaction.from_raw(self.legacy_tx)
        # OP_DUP OP_HASH160 <20 bytes pushed with OP_PUSHDATA1> OP_EQUALVERIFY
        # OP_CHECKSIG
        script_code = "76a94c14" + "22" * 20 + "88ac"
        # SIGHASH_ALL signs the tx with the input's scriptSig replaced by the
        # script code, followed by the sighash type as 4 bytes
        signed_input = "01" + "11" * 32 + "00000000" + "1a" + script_code + "ffffffff"
        preimage = (
            self.version + signed_input + self.outputs + self.locktime + "01000000"
        )
        self.assertEqual(
            tx.get_transaction_digest(0, Script.from_raw(script_code)),
            double_sha256(preimage),
        )


class TestPsbtWithNonMinimalPushes(unittest.TestCase):
    def setUp(self):
        setup("testnet")

    def test_witness_script_keeps_its_bytes(self):
        # <ab> pushed with OP_PUSHDATA1, OP_DROP, OP_1
        witness_script = "4c01ab7551"
        tx = Transaction(
            [TxInput("11" * 32, 0)],
            [TxOutput(1000, Script(["OP_1"]))],
            has_segwit=True,
        )
        psbt = PSBT(tx)
        psbt.inputs[0].witness_script = Script.from_raw(witness_script)
        psbt_hex = psbt.to_hex()

        parsed_psbt = PSBT.from_hex(psbt_hex)
        self.assertEqual(parsed_psbt.inputs[0].witness_script.to_hex(), witness_script)
        self.assertEqual(parsed_psbt.to_hex(), psbt_hex)


if __name__ == "__main__":
    unittest.main()

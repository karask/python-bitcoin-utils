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

from bitcoinutils.keys import P2pkhAddress
from bitcoinutils.script import Script
from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput


class TestExtremeTransactions(unittest.TestCase):
    def setUp(self):
        setup("testnet")
        self.txin = TxInput(
            "11" * 32,
            0,
            sequence=b"\xff\xff\xff\xff",
        )
        self.script_pubkey = P2pkhAddress(
            "mytmhndz4UbEMeoSZorXXrLpPfeoFUDzEp"
        ).to_script_pub_key()

    def _assert_script_length_prefix(self, commands, expected_prefix):
        script = Script(commands)
        tx = Transaction([self.txin], [TxOutput(1000, script)])

        raw = tx.serialize()

        # version + input count + one input with empty scriptSig + output count
        # + output amount
        script_length_offset = (4 + 1 + 32 + 4 + 1 + 4 + 1 + 8) * 2
        self.assertEqual(
            raw[script_length_offset : script_length_offset + len(expected_prefix)],
            expected_prefix,
        )

        parsed_tx = Transaction.from_raw(raw)
        self.assertEqual(len(parsed_tx.outputs[0].script_pubkey.script), len(commands))
        self.assertEqual(parsed_tx.serialize(), raw)

    def test_transaction_with_260_outputs_uses_compact_size(self):
        outputs = [TxOutput(1000 + i, self.script_pubkey) for i in range(260)]
        tx = Transaction([self.txin], outputs)

        raw = tx.serialize()

        # version + input count + one input with empty scriptSig
        output_count_offset = (4 + 1 + 32 + 4 + 1 + 4) * 2
        self.assertEqual(raw[output_count_offset : output_count_offset + 6], "fd0401")

        parsed_tx = Transaction.from_raw(raw)
        self.assertEqual(len(parsed_tx.outputs), 260)
        self.assertEqual(parsed_tx.serialize(), raw)

    def test_script_with_260_commands_uses_compact_size_uint16(self):
        self._assert_script_length_prefix(["OP_1"] * 260, "fd0401")

    def test_script_with_66000_commands_uses_compact_size_uint32(self):
        self._assert_script_length_prefix(["OP_1"] * 66000, "fed0010100")

    def test_segwit_digest_uses_compact_size_for_long_script_code(self):
        tx = Transaction(
            [self.txin], [TxOutput(1000, self.script_pubkey)], has_segwit=True
        )
        # Golden BIP143 digests at the CompactSize boundary and above 520 bytes.
        cases = [
            (
                Script(
                    ["01" * 60] * 4
                    + ["OP_DROP"] * 4
                    + ["OP_NOP"] * 4
                    + ["OP_1"]
                ),
                253,
                "ddd62d2dc5d54b3a3318d96e5bcbfd10"
                "f3be935f11bcbe58682be3830c040ab2",
            ),
            (
                Script(["01" * 75] * 7 + ["OP_DROP"] * 7 + ["OP_1"]),
                540,
                "4566ea6e48b430dd3efdf14a563d6628"
                "e107d823d30997c77cbb186f86896438",
            ),
        ]

        for script_code, expected_length, expected_digest in cases:
            with self.subTest(script_code_length=expected_length):
                self.assertEqual(len(script_code.to_bytes()), expected_length)
                digest = tx.get_transaction_segwit_digest(0, script_code, 2000)
                self.assertEqual(digest.hex(), expected_digest)

    def test_pushdata_boundaries_use_minimal_opcode(self):
        cases = [
            (75, "4b"),
            (76, "4c4c"),
            (255, "4cff"),
            (256, "4d0001"),
            (65535, "4dffff"),
            (65536, "4e00000100"),
        ]

        for size, expected_prefix in cases:
            with self.subTest(size=size):
                raw = Script(["aa" * size]).to_hex()
                self.assertEqual(raw[: len(expected_prefix)], expected_prefix)


if __name__ == "__main__":
    unittest.main()

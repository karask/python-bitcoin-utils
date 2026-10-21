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

from bitcoinutils.script import CODE_OPS, OP_CODES, Script
from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction

# opcodes 0x4f-0xff, none of which is followed by data to push
NON_PUSH_OPCODES = [bytes([byte]).hex() for byte in range(0x4F, 0x100)]


def double_sha256_hex(raw: str) -> str:
    digest = hashlib.sha256(hashlib.sha256(bytes.fromhex(raw)).digest()).digest()
    # reversed for display, like txids
    return digest[::-1].hex()


class TestScriptOpcodes(unittest.TestCase):
    def test_every_opcode_round_trips(self):
        for opcode in NON_PUSH_OPCODES:
            with self.subTest(opcode=opcode):
                script = Script.from_raw(opcode)
                self.assertEqual(script.get_script(), [CODE_OPS[bytes.fromhex(opcode)]])
                self.assertEqual(script.to_hex(), opcode)

    def test_every_opcode_round_trips_when_followed_by_more_opcodes(self):
        # OP_1 OP_EQUAL <abcd> OP_DROP OP_DUP OP_CHECKSIG
        suffix = "5187" + "02abcd" + "7576ac"
        for opcode in NON_PUSH_OPCODES:
            with self.subTest(opcode=opcode):
                script = Script.from_raw(opcode + suffix)
                self.assertEqual(
                    script.get_script(),
                    [
                        CODE_OPS[bytes.fromhex(opcode)],
                        "OP_1",
                        "OP_EQUAL",
                        "abcd",
                        "OP_DROP",
                        "OP_DUP",
                        "OP_CHECKSIG",
                    ],
                )
                self.assertEqual(script.to_hex(), opcode + suffix)

    def test_all_opcodes_in_one_script_round_trip(self):
        raw = "".join(NON_PUSH_OPCODES)
        script = Script.from_raw(raw)
        self.assertEqual(len(script.get_script()), len(NON_PUSH_OPCODES))
        self.assertEqual(script.to_hex(), raw)

    def test_reserved_opcode_does_not_swallow_following_opcodes(self):
        self.assertEqual(
            Script.from_raw("505187").get_script(), ["OP_RESERVED", "OP_1", "OP_EQUAL"]
        )

    def test_direct_pushes_round_trip(self):
        # 0x01-0x4b push that many bytes; 0xff would be an opcode if not data
        for size in range(0x01, 0x4C):
            with self.subTest(size=size):
                raw = bytes([size]).hex() + "ff" * size + "87"
                script = Script.from_raw(raw)
                self.assertEqual(script.get_script(), ["ff" * size, "OP_EQUAL"])
                self.assertEqual(script.to_hex(), raw)

    def test_opcode_names(self):
        names = {
            "50": "OP_RESERVED",
            "62": "OP_VER",
            "65": "OP_VERIF",
            "66": "OP_VERNOTIF",
            "7e": "OP_CAT",
            "7f": "OP_SUBSTR",
            "80": "OP_LEFT",
            "81": "OP_RIGHT",
            "83": "OP_INVERT",
            "84": "OP_AND",
            "85": "OP_OR",
            "86": "OP_XOR",
            "89": "OP_RESERVED1",
            "8a": "OP_RESERVED2",
            "8d": "OP_2MUL",
            "8e": "OP_2DIV",
            "95": "OP_MUL",
            "96": "OP_DIV",
            "97": "OP_MOD",
            "98": "OP_LSHIFT",
            "99": "OP_RSHIFT",
            "b0": "OP_NOP1",
            "b1": "OP_CHECKLOCKTIMEVERIFY",
            "b2": "OP_CHECKSEQUENCEVERIFY",
            "b3": "OP_NOP4",
            "b4": "OP_NOP5",
            "b5": "OP_NOP6",
            "b6": "OP_NOP7",
            "b7": "OP_NOP8",
            "b8": "OP_NOP9",
            "b9": "OP_NOP10",
            "ba": "OP_CHECKSIGADD",
            "bb": "OP_UNKNOWN187",
            "fe": "OP_UNKNOWN254",
            "ff": "OP_INVALIDOPCODE",
        }
        for opcode, name in names.items():
            with self.subTest(name=name):
                self.assertEqual(Script.from_raw(opcode).get_script(), [name])
                self.assertEqual(Script([name]).to_hex(), opcode)

    def test_nop_aliases_serialize_to_their_opcodes(self):
        self.assertEqual(Script(["OP_NOP2"]).to_hex(), "b1")
        self.assertEqual(Script(["OP_NOP3"]).to_hex(), "b2")

    def test_opcode_tables_are_unambiguous(self):
        # every byte that is not a direct push has a canonical name, which
        # serializes back to that byte
        not_direct_pushes = {bytes([b]) for b in range(0x100) if not 0x01 <= b <= 0x4B}
        self.assertEqual(set(CODE_OPS), not_direct_pushes)
        for byte, name in CODE_OPS.items():
            self.assertEqual(OP_CODES[name], byte)
        # and no name can be mistaken for hex data to push
        for name in OP_CODES:
            with self.assertRaises(ValueError):
                bytes.fromhex(name)


class TestTransactionWithNonPushOpcodes(unittest.TestCase):
    def setUp(self):
        setup("mainnet")
        version = "02000000"
        # one input with scriptSig: OP_RESERVED OP_NOP1 <ab>
        inputs = "01" + "11" * 32 + "00000000" + "04" + "50b001ab" + "ffffffff"
        # one output of 1000 satoshis with scriptPubKey:
        # OP_NOP4 OP_CAT OP_UNKNOWN187 OP_INVALIDOPCODE OP_1
        outputs = "01" + "e803000000000000" + "05" + "b37ebbff51"
        witness = "01" + "01ab"
        locktime = "00000000"
        self.legacy_tx = version + inputs + outputs + locktime
        self.segwit_tx = version + "0001" + inputs + outputs + witness + locktime

    def test_legacy_tx_from_raw(self):
        tx = Transaction.from_raw(self.legacy_tx)
        self.assertEqual(
            tx.inputs[0].script_sig.get_script(), ["OP_RESERVED", "OP_NOP1", "ab"]
        )
        self.assertEqual(
            tx.outputs[0].script_pubkey.get_script(),
            ["OP_NOP4", "OP_CAT", "OP_UNKNOWN187", "OP_INVALIDOPCODE", "OP_1"],
        )
        self.assertEqual(tx.to_hex(), self.legacy_tx)
        self.assertEqual(tx.get_txid(), double_sha256_hex(self.legacy_tx))

    def test_segwit_tx_from_raw(self):
        tx = Transaction.from_raw(self.segwit_tx)
        self.assertEqual(tx.to_hex(), self.segwit_tx)
        # the txid does not cover the segwit marker, flag and witness
        self.assertEqual(tx.get_txid(), double_sha256_hex(self.legacy_tx))
        self.assertEqual(tx.get_wtxid(), double_sha256_hex(self.segwit_tx))


if __name__ == "__main__":
    unittest.main()

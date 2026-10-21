# Copyright (C) 2018-2026 The python-bitcoin-utils developers
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

from bitcoinutils.script import Script
from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction
from bitcoinutils.utils import encode_varint


def double_sha256(data: str) -> str:
    """Returns the double SHA-256 of hex data in display (reversed) byte order"""
    data_bytes = bytes.fromhex(data)
    return hashlib.sha256(hashlib.sha256(data_bytes).digest()).digest()[::-1].hex()


class TestScriptFromRawPushData(unittest.TestCase):
    """OP_PUSHDATA1/2/4 push data the same way in legacy and segwit transactions"""

    def test_pushdata(self):
        cases = [
            # OP_PUSHDATA1 of 105 bytes (0x69 is also OP_VERIFY)
            ("4c69" + "ab" * 105 + "87", ["ab" * 105, "OP_EQUAL"]),
            # OP_PUSHDATA2 of 256 bytes
            ("4d0001" + "ab" * 256 + "87", ["ab" * 256, "OP_EQUAL"]),
            # OP_PUSHDATA4 of 5 bytes
            ("4e05000000" + "ab" * 5 + "87", ["ab" * 5, "OP_EQUAL"]),
        ]
        for raw, commands in cases:
            for has_segwit in (False, True):
                with self.subTest(opcode=raw[:2], has_segwit=has_segwit):
                    script = Script.from_raw(raw, has_segwit=has_segwit)
                    self.assertEqual(script.get_script(), commands)


class TestFromRawSegwitP2shMultisig(unittest.TestCase):
    """Segwit tx that also spends a legacy P2SH multisig output, whose redeem
    script is pushed with OP_PUSHDATA1 in the scriptSig"""

    def setUp(self):
        setup("mainnet")
        # mainnet tx d7550eeb688d58e22094a8b92fb649aceda897bf65560dbca21bf2457065fc06
        # (in segwit_v0_block.txt): input 0 is P2SH 2-of-3 multisig, input 1 is
        # P2SH-P2WSH 2-of-3 multisig
        self.sig1 = "3045022100c132292e494f47223ee3e91490706812aec121ea1163c71b9f13474777e0718502205b7654b748cc010c9bcdb42e6efd2564e03f9c308899a7046a88d8f959897e9f01"
        self.sig2 = "304402203ae80a41b8aeedc9e58fce7453dc055d32335e9e740bc8f3bcff430e801006dd02207706f20fac00615eabd0e0996a91b6e9fd741f7891a699e138d91127551b2ed901"
        self.redeem_script = "522103a1c0ff599e827aec899b4ea5f0270cdcb4785793f33a33b50922768c90011f6d21020e1b219d99f747bf379c6c542af3bc4302807d7cb6efc2cc6e25508bcff53e5f21031f9346d8882feb34185489570ae34642247e3b8a10c4f9c53a016fdce816aa4353ae"
        # OP_0 <sig1> <sig2> OP_PUSHDATA1 0x69 <redeem script>
        self.script_sig = (
            "00" + "48" + self.sig1 + "47" + self.sig2 + "4c69" + self.redeem_script
        )
        version = "01000000"
        inputs = (
            "02"
            # input 0
            + "731afb80187960244cc2930423152e931b5acecbbeebc46178b22458ed41339004000000"
            + "fdfd00"
            + self.script_sig
            + "ffffffff"
            # input 1
            + "563a40d15dbdcec531eb9b3f489abac2c53908f45b1ce18eb031fd17b8550d2406000000"
            + "23"
            + "2200203f678e29dbcc5582cad1cd002e1fa56f3438625b735381ec7464c90434e73810"
            + "ffffffff"
        )
        outputs = (
            "03"
            + "a07a060000000000"
            + "1976a914d2907833a9db8a0c854649bc838c7a5e0fb3267788ac"
            + "52f7000000000000"
            + "17a9142e3c6aad0331a540f8cfd4a78b93b69736403e0a87"
            + "de94020000000000"
            + "17a9147efd93f964ba338bc361fbe94da9c91066bebccf87"
        )
        witnesses = (
            # input 0: no witness
            "00"
            # input 1
            + "04"
            + "00"
            + "47304402202dcf25295221cc96c72b8a37db9fccab4f53c756f38d4331bf3aa2a1658a03f10220662b24b07a7642edc36cdab4cc958e9c8d06eb810439dcc58647a868d8ae8f4b01"
            + "47304402204d1e6c40e8097e4aa3281b82dfa053c9f58cf2e3ed0f9688d3a0a83e34fe9fe502206be1f2bf1acb99607904318d1f062c60411850f312ba88070f4a10fddb482ca901"
            + "69522102095a5cbb2db69ca1571433e09f4b231af3ac2cd75d689ebb1c38a03e70cc882221036789a53e87a4d6c1445d6de69412577356829970519edd8d9e55b19a143cdaf4210267ae7a263af8d48855a4e6ab36d955adf651f8761d34d65b4db85a1a52cc66c153ae"
        )
        locktime = "00000000"
        self.raw = version + "0001" + inputs + outputs + witnesses + locktime
        # the txid commits to the serialization without marker, flag and witnesses
        self.raw_no_witness = version + inputs + outputs + locktime
        self.txid = "d7550eeb688d58e22094a8b92fb649aceda897bf65560dbca21bf2457065fc06"

    def test_script_sig(self):
        tx = Transaction.from_raw(self.raw)
        # the redeem script is a single data push, not a sequence of opcodes
        self.assertEqual(
            tx.inputs[0].script_sig.get_script(),
            ["OP_0", self.sig1, self.sig2, self.redeem_script],
        )
        self.assertEqual(tx.inputs[0].script_sig.to_hex(), self.script_sig)

    def test_txid(self):
        tx = Transaction.from_raw(self.raw)
        self.assertEqual(tx.to_bytes(False).hex(), self.raw_no_witness)
        self.assertEqual(double_sha256(self.raw_no_witness), self.txid)
        self.assertEqual(tx.get_txid(), self.txid)

    def test_round_trip(self):
        tx = Transaction.from_raw(self.raw)
        self.assertEqual(tx.to_hex(), self.raw)
        self.assertEqual(tx.get_wtxid(), double_sha256(self.raw))


class TestFromRawSegwitOpReturn(unittest.TestCase):
    def setUp(self):
        setup("mainnet")

    def test_pushdata1_round_trip(self):
        # every data size that needs OP_PUSHDATA1, since its length byte must not
        # be parsed as an opcode (e.g. 0x4c is OP_PUSHDATA1 and 0x69 OP_VERIFY)
        sig = "30440220" + "44" * 32 + "0220" + "55" * 32 + "01"
        pubkey = "02" + "11" * 32
        for size in range(0x4C, 0x100):
            script_pubkey = "6a" + "4c" + f"{size:02x}" + "ab" * size
            raw = (
                "02000000"  # version
                + "0001"  # segwit marker and flag
                + "01" + "aa" * 32 + "00000000" + "00" + "fdffffff"
                + "01" + "0000000000000000"
                + encode_varint(len(script_pubkey) // 2).hex() + script_pubkey
                + "02" + "47" + sig + "21" + pubkey  # P2WPKH witness
                + "00000000"  # locktime
            )
            with self.subTest(size=size):
                self.assertEqual(Transaction.from_raw(raw).to_hex(), raw)


if __name__ == "__main__":
    unittest.main()

# Copyright (C) 2018-2024 The python-bitcoin-utils developers
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

from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction


class TestFromRawUnsignedSegwit(unittest.TestCase):
    def setUp(self):
        setup("mainnet")
        self.raw_segwit_tx = [
            # Unsigned
            "02000000000102daf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a90000000000fdffffffdaf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a90100000000fdffffff0101410f0000000000160014e4d3a1ec51102902f6bbede1318047880c9c7680a7011900",
            # Signed
            "02000000000102daf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a90000000000fdffffffdaf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a90100000000fdffffff0101410f0000000000160014e4d3a1ec51102902f6bbede1318047880c9c7680024730440220495838c36533616d8cbd6474842459596f4f312dce5483fe650791c82e17221c02200660520a2584144915efa8519a72819091e5ed78c52689b24235182f17d96302012102ddf4af49ff0eae1d507cc50c86f903cd6aa0395f3239759c440ea67556a3b91b0247304402200090c2507517abc7a9cb32452aabc8d1c8a0aee75ce63618ccd901542415f2db02205bb1d22cb6e8173e91dc82780481ea55867b8e753c35424da664f1d2662ecb1301210254c54648226a45dd2ad79f736ebf7d5f0fc03b6f8f0e6d4a61df4e531aaca431a7011900",
            # Unsigned, with an OP_PUSHDATA1 in an OP_RETURN output
            "02000000000102daf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a90000000000fdffffffdaf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a90100000000fdffffff0201410f0000000000160014e4d3a1ec51102902f6bbede1318047880c9c768000000000000000004f6a4c4cababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababa7011900",
        ]

    def test_segwit_tx_from_raw(self):
        for tx in self.raw_segwit_tx:
            tx_from_raw = Transaction.from_raw(tx)
            self.assertEqual(tx_from_raw.to_hex(), tx)


class TestFromRawMixedSegwit(unittest.TestCase):
    """Segwit txs that also spend non-witness inputs; the empty witness of such
    an input must be kept so that the tx re-serializes identically"""

    def setUp(self):
        setup("mainnet")
        sig = "30440220" + "44" * 32 + "0220" + "55" * 32 + "01"
        pk = "02" + "11" * 32
        self.p2wpkh_stack = [sig, pk]
        # input 0 is P2PKH (empty witness), input 1 is P2WPKH
        self.raw_legacy_first = (
            "02000000"  # version
            "0001"  # segwit marker and flag
            "02"  # input count
            + "aa" * 32 + "00000000" + "6a" + "47" + sig + "21" + pk + "fdffffff"
            + "bb" * 32 + "01000000" + "00" + "fdffffff"
            + "01"  # output count
            + "50c3000000000000" + "16" + "0014" + "66" * 20
            + "00"  # input 0 witness: no items
            + "02" + "47" + sig + "21" + pk  # input 1 witness
            + "00000000"  # locktime
        )
        # mainnet tx d48ecd93129c02d530594f3bc587c94fc9d3d97d6e5e84d44193d5aa7020bf5d
        # (in segwit_v1_block.txt): input 0 is P2WPKH, input 1 is P2PKH (empty witness)
        self.raw_legacy_last = "01000000000102348f77c798521433c3f3db637d5a040110ea18b0ee507862d97222cb57f47a340100000000ffffffffc644cd3fa08a8cf17359d7ebbe42eb67feb4a94c709aece614b203a6e204d878000000006a4730440220675fb76ad580c648e415b08cbd8ac892b46853138d84127696dda5025e7d4432022024a87294b00088663516e256786c3b19ba3dfba0459934ec95a84c40f25f974e0121039d995cdd513d443987bc43314d1574fa0f64558989f52e2907180f9dcdfa96c7ffffffff0185d03900000000001976a9149502e857fd44fe474bd9c4379ce828f5f2e5050888ac02483045022100ad15fc82cf36442d95ef2454c6c03d009795ac5a82c974176d880191b4ee774502204ca339a6dc4d6e4d47bebf6b284eda1aec7d37152bbd374bc985efc315d3224e01210203291a5000477423e216e8b70e2c7dc8dc4899dba62ba2602f7465f4088648a90000000000"
        self.raw_txs = [self.raw_legacy_first, self.raw_legacy_last]

    def test_witnesses_parallel_to_inputs(self):
        tx = Transaction.from_raw(self.raw_legacy_first)
        self.assertEqual(len(tx.witnesses), len(tx.inputs))
        self.assertEqual(tx.witnesses[0].stack, [])
        self.assertEqual(tx.witnesses[1].stack, self.p2wpkh_stack)

        tx = Transaction.from_raw(self.raw_legacy_last)
        self.assertEqual(len(tx.witnesses), len(tx.inputs))
        self.assertEqual(len(tx.witnesses[0].stack), 2)
        self.assertEqual(tx.witnesses[1].stack, [])

    def test_round_trip(self):
        for raw in self.raw_txs:
            self.assertEqual(Transaction.from_raw(raw).to_hex(), raw)

    def test_wtxid(self):
        for raw in self.raw_txs:
            data = bytes.fromhex(raw)
            wtxid = hashlib.sha256(hashlib.sha256(data).digest()).digest()[::-1].hex()
            self.assertEqual(Transaction.from_raw(raw).get_wtxid(), wtxid)


if __name__ == "__main__":
    unittest.main()

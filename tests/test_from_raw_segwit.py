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
            "02000000000102daf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a90000000000fdffffffdaf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a90100000000fdffffff0101410f0000000000160014e4d3a1ec51102902f6bbede1318047880c9c7680024730440220495838c36533616d8cbd6474842459596f4f312dce5483fe650791c82e17221c02200660520a2584144915efa8519a72819091e5ed78c52689b24235182f17d96302012102ddf4af49ff0eae1d507cc50c86f903cd6aa0395f3239759c440ea67556a3b91b0247304402200090c2507517abc7a9cb32452aabc8d1c8a0aee75ce63618ccd901542415f2db02205bb1d22cb6e8173e91dc82780481ea55867b8e753c35424da664f1d2662ecb1301210254c54648226a45dd2ad79f736ebf7d5f0fc03b6f8f0e6d4a61df4e531aaca431a7011900"
        ]

    def test_segwit_tx_from_raw(self):
        for tx in self.raw_segwit_tx:
            tx_from_raw = Transaction.from_raw(tx)
            self.assertEqual(tx_from_raw.to_hex(), tx)


if __name__ == "__main__":
    unittest.main()

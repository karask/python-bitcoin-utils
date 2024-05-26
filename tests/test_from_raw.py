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


class TestFromRaw(unittest.TestCase):
    def setUp(self):
        setup("mainnet")
        self.raw_coinbase_tx = "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff5103de940c184d696e656420627920536563506f6f6c29003b04003540adfabe6d6d95774a0bdc80e4c5864f6260f220fb71643351fbb46be5e71f4cabcd33245b2802000000000000000000601e4e000000ffffffff04220200000000000017a9144961d8e473caba262a450745c71c88204af3ff6987865a86290000000017a9146582f2551e2a47e1ae8b03fb666401ed7c4552ef870000000000000000266a24aa21a9ede553068307fd2fd504413d02ead44de3925912cfe12237e1eb85ed12293a45e100000000000000002b6a2952534b424c4f434b3a4fe216d3726a27ba0fb8b5ccc07717f7753464e51e9b0faac4ca4e1d005b0f4e0120000000000000000000000000000000000000000000000000000000000000000000000000"

    def test_coinbase_tx_from_raw(self):
        tx_from_raw = Transaction.from_raw(self.raw_coinbase_tx)

        self.assertEqual(tx_from_raw.to_hex(), self.raw_coinbase_tx)


if __name__ == "__main__":
    unittest.main()

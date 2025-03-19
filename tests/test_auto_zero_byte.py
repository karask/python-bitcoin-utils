# Copyright (C) 2018-2024 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import unittest
from bitcoinutils.setup import setup, get_auto_add_zero_byte, set_auto_add_zero_byte
from bitcoinutils.script import Script
from bitcoinutils.transactions import TxInput, Transaction


class TestAutoZeroByte(unittest.TestCase):
    def setUp(self):
        # Make sure we start with a clean state
        setup('testnet', auto_add_zero_byte=False)
    
    def test_auto_zero_byte_enabled(self):
        # Enable auto zero byte
        set_auto_add_zero_byte(True)
        
        # Create an input with empty script_sig
        txin = TxInput(
            "0" * 64,  # txid
            0,         # txout_index
            Script([]),  # empty script_sig
        )
        
        # Serialize with segwit=True
        bytes_with_segwit = txin.to_bytes(is_for_segwit_tx=True)
        
        # The script_sig should have a '00' byte added
        # Format: [txid(32)][txout_index(4)][script_len(1)][script_sig(1)][sequence(4)]
        # At position 36, we should have script length = 1
        self.assertEqual(bytes_with_segwit[36], 1)
        # At position 37, we should have the '00' byte
        self.assertEqual(bytes_with_segwit[37], 0)
    
    def test_auto_zero_byte_disabled(self):
        # Auto zero byte is disabled by default, but let's make it explicit
        set_auto_add_zero_byte(False)
        
        # Create an input with empty script_sig
        txin = TxInput(
            "0" * 64,  # txid
            0,         # txout_index
            Script([]),  # empty script_sig
        )
        
        # Serialize with segwit=True
        bytes_with_segwit = txin.to_bytes(is_for_segwit_tx=True)
        
        # The script_sig should be empty
        # Format: [txid(32)][txout_index(4)][script_len(1)][sequence(4)]
        # At position 36, we should have script length = 0
        self.assertEqual(bytes_with_segwit[36], 0)
    
    def test_auto_zero_byte_in_transaction(self):
        # Enable auto zero byte for this test
        set_auto_add_zero_byte(True)
        
        # Create a transaction with one input and one output
        txin = TxInput(
            "0" * 64,  # txid
            0,         # txout_index
            Script([]),  # empty script_sig
        )
        
        # Create a simple segwit transaction
        tx = Transaction(
            [txin],
            [],
            has_segwit=True
        )
        
        # Serialize the transaction
        tx_bytes = tx.to_bytes(True)
        
        # Find the position where the script_sig length should be
        # This depends on the transaction structure, but after the segwit marker,
        # flag, and input count, we should have:
        # [txid(32)][txout_index(4)][script_len(1)][script_sig(1)][sequence(4)]
        
        # For a segwit tx, there will be a marker (0x00) and flag (0x01) at position 4-5
        self.assertEqual(tx_bytes[4:6], b"\x00\x01")
        
        # Then the input count (0x01) at position 6
        self.assertEqual(tx_bytes[6], 1)
        
        # Then the txid at positions 7-38 (32 bytes)
        # Then txout_index at positions 39-42 (4 bytes)
        # Then script_sig length at position 43 (should be 1)
        self.assertEqual(tx_bytes[43], 1)
        
        # Then the script_sig itself at position 44 (should be 0x00)
        self.assertEqual(tx_bytes[44], 0)
    
    def test_non_segwit_tx_unchanged(self):
        # Enable auto zero byte for this test
        set_auto_add_zero_byte(True)
        
        # Create an input with empty script_sig
        txin = TxInput(
            "0" * 64,  # txid
            0,         # txout_index
            Script([]),  # empty script_sig
        )
        
        # Serialize with segwit=False (for a non-segwit transaction)
        bytes_without_segwit = txin.to_bytes(is_for_segwit_tx=False)
        
        # The script_sig should still be empty for non-segwit transactions
        # At position 36, we should have script length = 0
        self.assertEqual(bytes_without_segwit[36], 0)


if __name__ == "__main__":
    unittest.main()
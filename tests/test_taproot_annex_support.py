# Copyright (C) 2018-2025 The python-bitcoin-utils developers
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
from bitcoinutils.setup import setup
from bitcoinutils.utils import h_to_b
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import PrivateKey, PublicKey
from bitcoinutils.script import Script
from bitcoinutils.constants import SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY

class TestTaprootAnnex(unittest.TestCase):
    """Unit tests for Taproot annex support in signature hash calculations."""

    def setUp(self):
        # Setup the network
        setup("testnet")
        
        # Create sample transaction data with a valid testnet private key
        self.priv_key = PrivateKey("cVdte9ei2xsVjmZSPtyucG43YZgNkmKTqhwiUA8M4Fc3LdPJxPmZ")
        self.pub_key = self.priv_key.get_public_key()
        self.previous_tx_id = "6ecd66d88b1a976cde70ebbef69e903c5bc8c46f0d3e0fb546b216dbba720e0e"
        self.output_index = 0
        self.amount = 100000  # in satoshis
        self.script_pubkey = Script(['OP_1', self.pub_key.to_x_only_hex()])
        
        # Create a transaction
        self.tx_input = TxInput(self.previous_tx_id, self.output_index)
        self.tx_output = TxOutput(self.amount - 1000, Script(['OP_1', self.pub_key.to_x_only_hex()]))
        self.tx = Transaction([self.tx_input], [self.tx_output])
        
    def test_taproot_digest_with_annex(self):
        """Test that the digest changes when annex is provided."""
        script_pubkeys = [self.script_pubkey.to_bytes()]
        amounts = [self.amount]
        
        # Calculate digest without annex
        digest_without_annex = self.tx.get_transaction_taproot_digest(
            0, False, script_pubkeys, amounts, 0, None, 0xc0, SIGHASH_ALL
        )
        
        # Calculate digest with annex
        annex = bytes([0x50, 0x01, 0x02, 0x03])  # Simple annex with required 0x50 prefix
        digest_with_annex = self.tx.get_transaction_taproot_digest(
            0, False, script_pubkeys, amounts, 0, None, 0xc0, SIGHASH_ALL, annex
        )
        
        # Digests should be different
        self.assertNotEqual(digest_without_annex, digest_with_annex)
        
    def test_invalid_annex_format(self):
        """Test that invalid annex format raises appropriate errors."""
        script_pubkeys = [self.script_pubkey.to_bytes()]
        amounts = [self.amount]
        
        # Test annex without 0x50 prefix
        invalid_annex = bytes([0x51, 0x01, 0x02, 0x03])  # Incorrect prefix
        with self.assertRaises(ValueError) as context:
            self.tx.get_transaction_taproot_digest(
                0, False, script_pubkeys, amounts, 0, None, 0xc0, SIGHASH_ALL, invalid_annex
            )
        self.assertTrue("annex must start with 0x50" in str(context.exception))
        
        # Test empty annex
        empty_annex = bytes([])
        with self.assertRaises(ValueError) as context:
            self.tx.get_transaction_taproot_digest(
                0, False, script_pubkeys, amounts, 0, None, 0xc0, SIGHASH_ALL, empty_annex
            )
        self.assertTrue("annex must start with 0x50" in str(context.exception))
        
        # Test invalid annex type
        with self.assertRaises(ValueError) as context:
            self.tx.get_transaction_taproot_digest(
                0, False, script_pubkeys, amounts, 0, None, 0xc0, SIGHASH_ALL, "not bytes"
            )
        self.assertTrue("annex must be bytes" in str(context.exception))
        
    def test_annex_with_different_sighash_types(self):
        """Test that annex works with different sighash types."""
        script_pubkeys = [self.script_pubkey.to_bytes()]
        amounts = [self.amount]
        annex = bytes([0x50, 0xaa, 0xbb, 0xcc])
        
        # Test with SIGHASH_ALL
        digest_all = self.tx.get_transaction_taproot_digest(
            0, False, script_pubkeys, amounts, 0, None, 0xc0, SIGHASH_ALL, annex
        )
        
        # Test with SIGHASH_NONE
        digest_none = self.tx.get_transaction_taproot_digest(
            0, False, script_pubkeys, amounts, 0, None, 0xc0, SIGHASH_NONE, annex
        )
        
        # Test with SIGHASH_SINGLE
        digest_single = self.tx.get_transaction_taproot_digest(
            0, False, script_pubkeys, amounts, 0, None, 0xc0, SIGHASH_SINGLE, annex
        )
        
        # Digests should be different for different sighash types
        self.assertNotEqual(digest_all, digest_none)
        self.assertNotEqual(digest_all, digest_single)
        self.assertNotEqual(digest_none, digest_single)
        
    def test_script_path_with_annex(self):
        """Test that annex works with script path spending."""
        script_pubkeys = [self.script_pubkey.to_bytes()]
        amounts = [self.amount]
        annex = bytes([0x50, 0xdd, 0xee, 0xff])
        test_script = Script(['OP_TRUE'])
        
        # Calculate digest with key path
        key_path_digest = self.tx.get_transaction_taproot_digest(
            0, False, script_pubkeys, amounts, 0, None, 0xc0, SIGHASH_ALL, annex
        )
        
        # Calculate digest with script path
        script_path_digest = self.tx.get_transaction_taproot_digest(
            0, True, script_pubkeys, amounts, 1, test_script, 0xc0, SIGHASH_ALL, annex
        )
        
        # Digests should be different between key path and script path
        self.assertNotEqual(key_path_digest, script_path_digest)

if __name__ == '__main__':
    unittest.main()
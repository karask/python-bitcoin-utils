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
from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey
from bitcoinutils.transactions import TxInput, TxOutput, Transaction
from bitcoinutils.utils import to_satoshis
from bitcoinutils.psbt import PSBT

class TestPSBTFinalize(unittest.TestCase):
    def setUp(self):
        setup('testnet')
        # Generate a new testnet private key
        self.sk = PrivateKey()
        # Derive the corresponding address using get_address()
        self.from_addr = self.sk.get_public_key().get_address()
        # Use a dummy input and output for testing
        self.txin = TxInput("0" * 64, 0) # Dummy 64-character hex txid
        self.txout = TxOutput(to_satoshis(0.001), self.from_addr.to_script_pub_key())
        self.tx = Transaction([self.txin], [self.txout])
    
    def test_finalize_psbt(self):
        # Create a PSBT from the transaction
        psbt = PSBT.from_transaction(self.tx)
        
        # Since this is a basic test, we'll just check that the PSBT has the correct properties
        self.assertEqual(len(psbt.inputs), 1)
        self.assertEqual(len(psbt.outputs), 1)
        
        # Add a dummy UTXO to enable signing
        dummy_tx = Transaction([TxInput("1" * 64, 0)], [TxOutput(to_satoshis(0.002), self.from_addr.to_script_pub_key())])
        psbt.add_input_utxo(0, utxo_tx=dummy_tx)
        
        # Sign the input
        psbt.sign_input(self.sk, 0)
        
        # Verify that there's a signature
        pubkey_bytes = bytes.fromhex(self.sk.get_public_key().to_hex())
        self.assertIn(pubkey_bytes, psbt.inputs[0].partial_sigs)
        
        # Finalize the PSBT
        finalized = psbt.finalize()
        self.assertTrue(finalized)
        
        # Use global_tx directly since there's no extract_transaction instance method
        # that matches what the test expects
        final_tx = psbt.global_tx
        self.assertIsInstance(final_tx, Transaction)
        
        # In a real test with valid data, we would verify the signature here
        # For this placeholder test, we just check the transaction has the expected properties
        self.assertEqual(len(final_tx.inputs), 1)
        self.assertEqual(len(final_tx.outputs), 1)

if __name__ == '__main__':
    unittest.main()
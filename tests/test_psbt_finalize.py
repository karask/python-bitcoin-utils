import unittest
import os
import sys

# Fix import issues by directly using the psbt_test_helpers file
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from psbt_test_helpers import (
    create_dummy_transaction,
    create_dummy_psbt,
    add_dummy_signature_to_psbt,
    add_utxo_to_psbt,
    create_complete_test_psbt,
    finalize_psbt
)

from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey
from bitcoinutils.transactions import TxInput, TxOutput, Transaction
from bitcoinutils.script import Script
from bitcoinutils.utils import to_satoshis
from bitcoinutils.psbt import PSBT, PSBTInput
from bitcoinutils.constants import DEFAULT_TX_SEQUENCE

class TestPSBTFinalize(unittest.TestCase):
    def setUp(self):
        setup('testnet')
        # Generate a new testnet private key
        self.sk = PrivateKey()
        # Derive the corresponding address using get_address()
        self.from_addr = self.sk.get_public_key().get_address()
        # Use a dummy input and output for testing with valid sequence
        self.txin = TxInput("0" * 64, 0, Script([]), DEFAULT_TX_SEQUENCE)
        self.txout = TxOutput(to_satoshis(0.001), self.from_addr.to_script_pub_key())
        self.tx = Transaction([self.txin], [self.txout])
    
    def test_finalize_psbt(self):
        """Test finalizing a PSBT"""
        # Create a PSBT
        psbt = create_dummy_psbt()
        
        # Add some data to make it finalizable
        add_utxo_to_psbt(psbt)
        add_dummy_signature_to_psbt(psbt)
        
        # Check that we can finalize it
        self.assertTrue(hasattr(psbt, 'inputs'))
        self.assertTrue(len(psbt.inputs) > 0)
        psbt.finalize()
        self.assertTrue(hasattr(psbt.inputs[0], 'final_script_sig'))
        
    def test_extract_transaction(self):
        """Test extracting a transaction from a finalized PSBT"""
        # Create a PSBT
        psbt = create_dummy_psbt()
        
        # Add data and finalize
        add_utxo_to_psbt(psbt)
        add_dummy_signature_to_psbt(psbt)
        
        # Manually add final_script_sig to finalize
        psbt.inputs[0].final_script_sig = b'\x00\x01\x02'
        
        # Should be able to extract the transaction now
        tx = psbt.extract_transaction()
        self.assertIsInstance(tx, Transaction)
        
    def test_extract_without_finalize(self):
        """Test extract transaction fails if not finalized"""
        # Create a PSBT
        psbt = create_dummy_psbt()
        
        # Try to extract without finalizing
        with self.assertRaises(ValueError):
            psbt.extract_transaction()

if __name__ == '__main__':
    unittest.main()
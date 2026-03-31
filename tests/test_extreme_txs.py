
import unittest
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.script import Script

class TestExtremeTransactions(unittest.TestCase):
    def test_many_outputs(self):
        """Test transaction with 260 outputs"""
        tx = Transaction()
        # Add one input
        tx.add_input(TxInput("a"*64, 0, Script([])))
        
        # Add 260 outputs
        # 260 is chosen because it might trigger varint boundaries or size limits if logic is flawed
        # For varint: 253 is the boundary where it switches from 1 byte to 3 bytes (fd xx xx)
        # So 260 ensures we cover the multi-byte varint case for number of outputs.
        for i in range(260):
            tx.add_output(TxOutput(i, Script([])))
            
        # Serialize and check size
        raw_tx = tx.to_bytes(has_segwit=False)
        self.assertTrue(len(raw_tx) > 0)
        
        # Verify we can deserialize it
        tx_from_raw = Transaction.from_raw(raw_tx)
        self.assertEqual(len(tx_from_raw.outputs), 260)
        self.assertEqual(tx_from_raw.outputs[-1].amount, 259)

if __name__ == '__main__':
    unittest.main()

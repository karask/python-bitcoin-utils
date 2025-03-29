import unittest
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.script import Script
from bitcoinutils.utils import b_to_h, h_to_b

class TestAutomaticWitnessHandling(unittest.TestCase):

    def test_mixed_input_witness_serialization(self):
        """Test that transactions with both SegWit and non-SegWit inputs
        automatically add empty witnesses for non-SegWit inputs"""
        
        # Create a transaction with two inputs
        tx = Transaction(
            inputs=[
                TxInput("0" * 64, 0),  # non-witness input
                TxInput("1" * 64, 1)   # witness input
            ],
            outputs=[
                TxOutput(10000, Script(["OP_RETURN", "test"]))
            ],
            has_segwit=True,  # This is a SegWit transaction
            witnesses=[
                # Only provide witness data for the second input
                TxWitnessInput(["aa", "bb"])
            ]
        )
        
        # Get the serialized transaction 
        serialized_hex = tx.serialize()
        
        # Deserialize to check the structure
        tx_deserialized = Transaction.from_raw(serialized_hex)
        
        # Verify that the transaction has two inputs
        self.assertEqual(len(tx_deserialized.inputs), 2)
        
        # Verify that the transaction has the SegWit marker
        self.assertTrue(tx_deserialized.has_segwit)
        
        # Verify that only one witness was provided (since one was empty)
        self.assertEqual(len(tx_deserialized.witnesses), 1)
        
        # Calculate txid and wtxid
        txid = tx.get_txid()
        wtxid = tx.get_wtxid()
        
        # Txid and wtxid should be different for SegWit transactions
        self.assertNotEqual(txid, wtxid)

    def test_empty_witness_serialization(self):
        """Test that a transaction with only non-SegWit inputs but marked as
        SegWit automatically adds empty witnesses for all inputs"""
        
        # Create a transaction with two non-witness inputs
        tx = Transaction(
            inputs=[
                TxInput("0" * 64, 0),
                TxInput("1" * 64, 1)
            ],
            outputs=[
                TxOutput(10000, Script(["OP_RETURN", "test"]))
            ],
            has_segwit=True,  # Mark as SegWit transaction
            witnesses=[]  # But provide no witnesses
        )
        
        # Get the serialized transaction
        serialized_hex = tx.serialize()
        
        # Deserialize to check the structure
        tx_deserialized = Transaction.from_raw(serialized_hex)
        
        # Verify that the transaction has two inputs
        self.assertEqual(len(tx_deserialized.inputs), 2)
        
        # Verify that the transaction has the SegWit marker
        self.assertTrue(tx_deserialized.has_segwit)
        
        # Verify that there are no witnesses in the deserialized tx
        # (because they were all empty and would be omitted during parsing)
        self.assertEqual(len(tx_deserialized.witnesses), 0)
        
        # Calculate txid and wtxid
        txid = tx.get_txid()
        wtxid = tx.get_wtxid()
        
        # Txid and wtxid should still be different
        self.assertNotEqual(txid, wtxid)

if __name__ == '__main__':
    unittest.main()
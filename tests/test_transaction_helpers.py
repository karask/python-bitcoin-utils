
import unittest
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.script import Script

class TestTransactionHelpers(unittest.TestCase):
    def setUp(self):
        self.tx_in = TxInput("txid", 0, Script(["OP_0"]))
        self.tx_out = TxOutput(1000, Script(["OP_1"]))
        self.tx = Transaction()

    def test_add_input(self):
        self.tx.add_input(self.tx_in)
        self.assertEqual(len(self.tx.inputs), 1)
        self.assertEqual(self.tx.inputs[0], self.tx_in)

    def test_add_input_segwit(self):
        self.tx.has_segwit = True
        self.tx.add_input(self.tx_in)
        self.assertEqual(len(self.tx.inputs), 1)
        self.assertEqual(len(self.tx.witnesses), 1)
        self.assertIsInstance(self.tx.witnesses[0], TxWitnessInput)

    def test_remove_input(self):
        self.tx.add_input(self.tx_in)
        self.tx.remove_input(0)
        self.assertEqual(len(self.tx.inputs), 0)

    def test_remove_input_segwit(self):
        self.tx.has_segwit = True
        self.tx.add_input(self.tx_in) # adds witness
        self.tx.remove_input(0) # should remove witness
        self.assertEqual(len(self.tx.inputs), 0)
        self.assertEqual(len(self.tx.witnesses), 0)

    def test_update_input(self):
        self.tx.add_input(self.tx_in)
        new_in = TxInput("new_txid", 1, Script(["OP_2"]))
        self.tx.update_input(0, new_in)
        self.assertEqual(self.tx.inputs[0], new_in)

    def test_add_output(self):
        self.tx.add_output(self.tx_out)
        self.assertEqual(len(self.tx.outputs), 1)
        self.assertEqual(self.tx.outputs[0], self.tx_out)

    def test_remove_output(self):
        self.tx.add_output(self.tx_out)
        self.tx.remove_output(0)
        self.assertEqual(len(self.tx.outputs), 0)

    def test_update_output(self):
        self.tx.add_output(self.tx_out)
        new_out = TxOutput(2000, Script(["OP_3"]))
        self.tx.update_output(0, new_out)
        self.assertEqual(self.tx.outputs[0], new_out)

if __name__ == '__main__':
    unittest.main()

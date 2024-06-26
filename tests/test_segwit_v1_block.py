import unittest
import os
import sys

root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if root_path not in sys.path:
    sys.path.append(root_path)

from bitcoinutils.block import Block, BlockHeader
from bitcoinutils.script import Script

class TestBlock(unittest.TestCase):
    def setUp(self): 
        self.magic = 'f9beb4d9'
        self.block_size = 2092571
        self.header = BlockHeader(
            version=657317888,
            previous_block_hash= "000000000000000000017b9853ee0ba881839fad59e47c5c547a50d9b82a173e",
            merkle_root="5dffb9054aacc413570c85fc0a693fa0c34ea03f33a7345cc08dfc7d3fcfcc3d",
            timestamp=1686834363,
            target_bits=386228333,
            nonce=436214390
        )
        self.transaction_count = 3059
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(current_dir, 'segwit_v1_block.txt')
        data = ""
        with open(file_path, 'r') as file:
            data = file.read()
        self.block = Block.from_raw(data)

    def test_magic_number(self):
        expected_magic = bytes.fromhex(self.magic)
        self.assertEqual(self.block.magic, expected_magic, "Magic number does not match.")

    def test_transaction_count(self):
        self.assertEqual(self.block.transaction_count, self.transaction_count, "Transaction count is incorrect.")

    def test_header_fields(self):
        self.assertEqual(self.block.header.version, self.header.version, "Block version is incorrect.")
        self.assertEqual(self.block.header.previous_block_hash.hex(), self.header.previous_block_hash, "Previous block hash is incorrect.")
        self.assertEqual(self.block.header.merkle_root.hex(), self.header.merkle_root, "Merkle root is incorrect.")
        self.assertEqual(self.block.header.timestamp, self.header.timestamp, "Timestamp is incorrect.")
        self.assertEqual(self.block.header.target_bits, self.header.target_bits, "Target bits are incorrect.")
        self.assertEqual(self.block.header.nonce, self.header.nonce, "Nonce is incorrect.")

    def test_block_size(self):
        self.assertEqual(self.block.get_block_size(), self.block_size, "Block size is incorrect.")

    def test_coinbase(self):
        self.assertEqual(len(self.block.get_coinbase_transaction().outputs),3, "Coinbase transaction should have exactly two outputs.")
        self.assertEqual(self.block.get_coinbase_transaction().outputs[0].amount,649937184, "Output amount in coinbase transaction is incorrect.")
        script_pubkey = Script(['OP_HASH160' , '4b09d828dfc8baaba5d04ee77397e04b1050cc73','OP_EQUAL'])
        self.assertEqual(self.block.get_coinbase_transaction().outputs[0].script_pubkey, script_pubkey, "scriptSig in the coinbase transaction is incorrect.")

    def test_taproot_transaction(self):
        taproot_transactions = []
        for transaction in self.block.transactions:
            for output in transaction.outputs:
                if output.script_pubkey.get_script()[0].startswith('OP_1'):  # 1-byte for '51', 64-bytes for pubkey
                    taproot_transactions.append(transaction)
    
        taproot_transaction = taproot_transactions[0]
        number_of_outputs = 4
        script_pubkey = Script(['OP_1','d14e6eec69162c53b7d3e08aff17eddc6a0cb4de69c3198588c44909267ed207'])

        self.assertEqual(len(taproot_transaction.outputs), number_of_outputs, "Number of inputs in the last transaction is incorrect.")
        self.assertEqual(taproot_transaction.outputs[0].script_pubkey, script_pubkey, "Unlocking script does not match expected.")
        
if __name__ == "__main__":
    unittest.main()
    
    

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
        self.block_size = 828162
        self.header = BlockHeader(
            version=571932672,
            previous_block_hash="00000000000000000003a2ff4c1be1692af1627f0c9e624dfcbeb9e8078f7884",
            merkle_root="261dae5ea37f11628c4fedaece0afe013e7ed83bd935001eedfa92e4e9290ecf",
            timestamp=1657510926,
            target_bits=386508719,
            nonce=3812188189
        )
        self.transaction_count = 1126
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(current_dir, 'segwit_v0_block.txt')
        data = ""
        with open(file_path, 'r') as file:
            data = file.read()
        self.block = Block.from_raw(data)

    def test_magic_number(self):
        expected_magic = bytes.fromhex(self.magic)
        self.assertEqual(self.block.magic, expected_magic, "Magic number does not match.")

    def test_transaction_count(self):
        self.assertEqual(self.block.transaction_count, self.transaction_count, "Transaction count is incorrect.")

    # In test_segwit_v0_block.py, modify the test_header_fields method:

def test_header_fields(self):
    """Check that the header fields match the expected values."""
    # Reverse the hex representation to match the expected format
    prev_hash = self.block.header.previous_block_hash.hex()
    prev_hash_reversed = ''.join(reversed([prev_hash[i:i+2] for i in range(0, len(prev_hash), 2)]))
    
    merkle_root = self.block.header.merkle_root.hex()
    merkle_root_reversed = ''.join(reversed([merkle_root[i:i+2] for i in range(0, len(merkle_root), 2)]))
    
    self.assertEqual(prev_hash_reversed, self.header.previous_block_hash, "Previous block hash is incorrect.")
    self.assertEqual(merkle_root_reversed, self.header.merkle_root, "Merkle root is incorrect.")
    self.assertEqual(self.block.header.timestamp, self.header.timestamp, "Timestamp is incorrect.")
    self.assertEqual(self.block.header.target_bits, self.header.bits, "Target bits is incorrect.")
    self.assertEqual(self.block.header.nonce, self.header.nonce, "Nonce is incorrect.")

    def test_block_size(self):
        self.assertEqual(self.block.get_block_size(), self.block_size, "Block size is incorrect.")

    def test_coinbase(self):
        self.assertEqual(len(self.block.get_coinbase_transaction().outputs),2, "Coinbase transaction should have exactly two outputs.")
        self.assertEqual(self.block.get_coinbase_transaction().outputs[0].amount,631156988, "Output amount in coinbase transaction is incorrect.")
        script_pubkey = Script(['OP_DUP', 'OP_HASH160', '5e9b23809261178723055968d134a947f47e799f', 'OP_EQUALVERIFY', 'OP_CHECKSIG'])
        self.assertEqual(self.block.get_coinbase_transaction().outputs[0].script_pubkey, script_pubkey, "scriptSig in the coinbase transaction is incorrect.")

    def test_segwit_transaction(self):
        segwit_transaction = self.block.get_witness_transactions()[-1]
        number_of_inputs = 1  
        input_txid = 'f52328bffb4c211682c3c209e71d26adce358fd3ad7221f6864e3dd27fd9eb32'
        script_sig = Script(['00149dfe77d2088687a6f1b43150bd281f5f8bf71fb6'])

        self.assertEqual(len(segwit_transaction.inputs), number_of_inputs, "Number of inputs in the last transaction is incorrect.")
        self.assertEqual(segwit_transaction.inputs[0].txid, input_txid, "Input's TXID does not match expected.")
        self.assertEqual(segwit_transaction.inputs[0].script_sig, script_sig, "Unlocking script does not match expected.")
        
if __name__ == "__main__":
    unittest.main()
    
    

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
        self.block_size = 49179
        self.header = BlockHeader(
            version=1,
            previous_block_hash="000000000000055f3f26d836b1ceb4b556779c19ad5f882780cbd728a6bbb4d9",
            merkle_root="54becb5d40869af91e26c199a6289fc60514ca58746833e1f726f853dbd19780",
            timestamp=1314349597,
            target_bits=436816518,
            nonce=1461376631
        )
        self.transaction_count = 162
        current_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(current_dir, 'legacy_block.txt')
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
        self.assertEqual(len(self.block.get_coinbase_transaction().outputs),1, "Coinbase transaction should have exactly one output.")
        self.assertEqual(self.block.get_coinbase_transaction().outputs[0].amount,5004776366, "Output amount in coinbase transaction is incorrect.")
        script_pubkey = Script(['045cdf46d10c67a5696cf3d1ec0cee09af6b9cba80c6802fbeec8b0335b0dfb17f536783ad49baf9a0ee0b4d3a4aa66f96ca5c79fecfd6151e828e90bf8fb3016e', 'OP_CHECKSIG'])
        self.assertEqual(self.block.get_coinbase_transaction().outputs[0].script_pubkey, script_pubkey, "scriptSig in the coinbase transaction is incorrect.")

    def test_last_transaction(self):
        last_transaction = self.block.transactions[-1]

        number_of_inputs = 1  
        input_txid = 'c1077858b6ee8a8ac9e8510c6da102cd96aacaeca45a2b108dd04d4b4f45a9e2'
        script_sig = Script(['3044022048b8cdb970d0fc9c5eb22c86d7abe3eb3038d1033b89948cb171e3e0c166bf0b022068b26f973c597420e8e327d7b3f6e50d1a04354111f7194831e740c33501eb6f01', '0478a4289102c1a391e606f3a28fa1ff5602ae49982f847b085a026a0211ffe6af1a8c191c7873e5f6598610f0f6e39281756f24a9ddff10d9bd1f7d8ba7475286'])

        self.assertEqual(len(last_transaction.inputs), number_of_inputs, "Number of inputs in the last transaction is incorrect.")
        self.assertEqual(last_transaction.inputs[0].txid, input_txid, "Input's TXID does not match expected.")
        self.assertEqual(last_transaction.inputs[0].script_sig, script_sig, "Unlocking script does not match expected.")
        
if __name__ == "__main__":
    unittest.main()
    
    

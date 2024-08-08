import os
import struct
import sys

root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if root_path not in sys.path:
    sys.path.append(root_path)

from bitcoinutils.block import Block
from bitcoinutils.constants import BLOCK_MAGIC_NUMBER

def main():
    filename = '' # Give .dat file path to run example 
    try:
        with open(filename, 'rb') as file:
            while True:
                # Read the magic number and block size (first 8 bytes: 4 bytes magic, 4 bytes size)
                preamble = file.read(8)
                if len(preamble) < 8:
                    # If less than 8 bytes were read, it's the end of the file
                    break
                
                # Unpack the header to get magic number and size
                magic, size = struct.unpack('<4sI', preamble)
                magic_hex = magic.hex()

                if magic_hex not in BLOCK_MAGIC_NUMBER:
                    raise ValueError(f"Unknown or unsupported network magic number: {magic_hex}")

                print("Network:", BLOCK_MAGIC_NUMBER[magic_hex])
                
                # Read the block data based on the size specified
                block_data = file.read(size)
                if len(block_data) < size:
                    # If the block data is less than the size specified, it means the file is truncated
                    print("Truncated block data.")
                    break
                
                # Concatenate the header and block data to parse it as a raw block
                raw_block = preamble + block_data
                
                # Use the from_raw method of the Block class to parse the block
                block = Block.from_raw(raw_block)
                
                # Output some information about the block (example: hash, number of transactions)
                print("Block Hash:", block.get_block_header().get_block_hash())
                print("Number of Transactions:", block.get_transactions_count())
    
    except FileNotFoundError:
        print(f"Error: The file '{filename}' does not exist.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    main()
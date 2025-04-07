import os
import struct
import sys

# Dynamically add the root path to sys.path
root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if root_path not in sys.path:
    sys.path.append(root_path)

from bitcoinutils.block import Block
from bitcoinutils.constants import BLOCK_MAGIC_NUMBER

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_blkNNNNN.dat>")
        return

    filename = sys.argv[1]

    try:
        with open(filename, 'rb') as file:
            block_height = 0
            while True:
                # Read 8 bytes: 4 for magic number and 4 for block size
                preamble = file.read(8)
                if len(preamble) < 8:
                    print("End of file reached.")
                    break

                magic, size = struct.unpack('<4sI', preamble)
                magic_hex = magic.hex()

                if magic_hex not in BLOCK_MAGIC_NUMBER:
                    raise ValueError(f"Unknown or unsupported network magic number: {magic_hex}")

                network = BLOCK_MAGIC_NUMBER[magic_hex]
                print(f"\n[{network}] Block #{block_height}")

                block_data = file.read(size)
                if len(block_data) < size:
                    print("Warning: Truncated block data.")
                    break

                raw_block = preamble + block_data
                block = Block.from_raw(raw_block)

                # Output block info
                print("Block Hash:", block.get_block_header().get_block_hash())
                print("Transactions:", block.get_transactions_count())

                block_height += 1

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    main()

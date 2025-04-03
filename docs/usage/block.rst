Block Module
===========

The `block` module provides functionality for working with Bitcoin blocks. It allows parsing, creating, and analyzing Bitcoin blocks, including their headers and transactions.

Overview
--------

A Bitcoin block consists of a block header and a list of transactions. The block header contains metadata about the block, such as the version, previous block hash, merkle root, timestamp, difficulty target, and nonce. The transactions are the actual data stored in the blockchain.

This module allows you to:

- Parse blocks from raw hex data
- Access block header fields
- Extract and work with transactions in a block
- Parse SegWit blocks (both v0 and v1)

Basic Usage
----------

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.block import Block

    # Setup the network
    setup('testnet')

    # Parse a block from hex data
    block_hex = "0100000001..." # Hex representation of a block
    block = Block.from_hex(block_hex)

    # Get block information
    print(f"Block hash: {block.get_hash()}")
    print(f"Previous block hash: {block.get_prev_block_hash()}")
    print(f"Merkle root: {block.get_merkle_root()}")
    print(f"Block version: {block.get_version()}")
    print(f"Block timestamp: {block.get_timestamp()}")
    print(f"Block difficulty target: {block.get_bits()}")
    print(f"Block nonce: {block.get_nonce()}")
    
    # Get transactions
    txs = block.get_transactions()
    print(f"Number of transactions: {len(txs)}")
    
    # Print the first transaction (coinbase)
    if txs:
        print(f"Coinbase transaction: {txs[0].serialize()}")

Parsing Blocks
-----------

The Block class provides methods to parse blocks from different sources:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.block import Block
    from bitcoinutils.utils import h_to_b

    # Setup the network
    setup('testnet')

    # From a hex string
    block_hex = "0100000001..." # Hex representation of a block
    block = Block.from_hex(block_hex)

    # From bytes
    block_bytes = h_to_b(block_hex)
    block = Block.from_bytes(block_bytes)

    # From a file
    with open('block.dat', 'rb') as f:
        block_data = f.read()
        block = Block.from_bytes(block_data)

Block Header
----------

The block header contains metadata about the block. You can access these fields using getter methods:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.block import Block

    # Setup the network
    setup('testnet')

    # Parse a block
    block_hex = "0100000001..." # Hex representation of a block
    block = Block.from_hex(block_hex)

    # Access header fields
    version = block.get_version()
    prev_block_hash = block.get_prev_block_hash()
    merkle_root = block.get_merkle_root()
    timestamp = block.get_timestamp()
    bits = block.get_bits()
    nonce = block.get_nonce()

    # Print header information
    print(f"Block version: {version}")
    print(f"Previous block hash: {prev_block_hash}")
    print(f"Merkle root: {merkle_root}")
    print(f"Timestamp: {timestamp}")
    print(f"Bits: {bits}")
    print(f"Nonce: {nonce}")

    # Get the block hash (double SHA-256 of the header)
    block_hash = block.get_hash()
    print(f"Block hash: {block_hash}")

Working with Transactions
-----------------------

The Block class allows you to access the transactions in the block:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.block import Block

    # Setup the network
    setup('testnet')

    # Parse a block
    block_hex = "0100000001..." # Hex representation of a block
    block = Block.from_hex(block_hex)

    # Get all transactions
    txs = block.get_transactions()
    
    # Process transactions
    for i, tx in enumerate(txs):
        print(f"Transaction {i}:")
        print(f"  TXID: {tx.get_txid()}")
        print(f"  Version: {tx.get_version()}")
        print(f"  Locktime: {tx.get_locktime()}")
        print(f"  Number of inputs: {len(tx.get_inputs())}")
        print(f"  Number of outputs: {len(tx.get_outputs())}")

    # Get the coinbase transaction (first transaction in a block)
    coinbase_tx = txs[0]
    print(f"Coinbase transaction ID: {coinbase_tx.get_txid()}")

    # Check if the merkle root is valid
    calculated_merkle_root = block.calculate_merkle_root()
    stored_merkle_root = block.get_merkle_root()
    print(f"Merkle root valid: {calculated_merkle_root == stored_merkle_root}")

SegWit Blocks
-----------

SegWit blocks have a special structure with a witness commitment in the coinbase transaction. The Block class can handle these:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.block import Block

    # Setup the network
    setup('testnet')

    # Parse a SegWit block
    segwit_block_hex = "0000002001..." # Hex representation of a SegWit block
    block = Block.from_hex(segwit_block_hex)

    # Check if it's a SegWit block (version >= 0x20000000)
    is_segwit = (block.get_version() & 0xE0000000) == 0x20000000
    print(f"Is SegWit block: {is_segwit}")

    # Get transactions with witness data
    txs = block.get_transactions()
    
    # Check for witness data in transactions
    for i, tx in enumerate(txs):
        has_witness = any(txin.witness for txin in tx.get_inputs())
        print(f"Transaction {i} has witness data: {has_witness}")

Block Validation
-------------

You can perform some basic validation on a block:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.block import Block
    import time

    # Setup the network
    setup('testnet')

    # Parse a block
    block_hex = "0100000001..." # Hex representation of a block
    block = Block.from_hex(block_hex)

    # Validate block hash
    prev_block_hash = "000000000000000000023..." # Known previous block hash
    if block.get_prev_block_hash() != prev_block_hash:
        print("Invalid previous block hash")
    
    # Check timestamp (must be less than 2 hours in the future)
    current_time = int(time.time())
    if block.get_timestamp() > current_time + 7200:
        print("Block timestamp too far in the future")
    
    # Validate merkle root
    calculated_merkle_root = block.calculate_merkle_root()
    if calculated_merkle_root != block.get_merkle_root():
        print("Invalid merkle root")
    
    # Verify coinbase transaction
    txs = block.get_transactions()
    if not txs or not txs[0].is_coinbase():
        print("Missing or invalid coinbase transaction")

Creating a Block
-------------

While not commonly used outside of mining, you can also create a block:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.block import Block
    from bitcoinutils.transactions import Transaction
    import time

    # Setup the network
    setup('testnet')

    # Create a coinbase transaction
    coinbase_tx = Transaction.create_coinbase("03...")

    # Add other transactions
    txs = [coinbase_tx, tx1, tx2, ...]

    # Create block header
    version = 1
    prev_block_hash = "000000000000000000023..."
    merkle_root = "..." # Calculate from transactions
    timestamp = int(time.time())
    bits = 0x1d00ffff  # Difficulty target
    nonce = 0  # Starting nonce for mining

    # Create the block
    block = Block(version, prev_block_hash, merkle_root, timestamp, bits, nonce, txs)

    # Serialize the block
    block_hex = block.serialize()
    print(f"Block hex: {block_hex}")

Practical Applications
-------------------

Some practical applications of the block module include:

1. **Block Explorer Functionality**:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.block import Block
    from bitcoinutils.proxy import NodeProxy

    # Setup the network
    setup('testnet')

    # Connect to a node
    proxy = NodeProxy('user', 'password')

    # Get the latest block hash
    latest_hash = proxy.get_best_block_hash()

    # Get the block data
    block_data = proxy.get_block(latest_hash, verbose=False)

    # Parse the block
    block = Block.from_hex(block_data)

    # Display block information
    print(f"Block hash: {block.get_hash()}")
    print(f"Block time: {block.get_timestamp()}")
    print(f"Transactions: {len(block.get_transactions())}")

2. **Transaction Verification**:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.block import Block
    from bitcoinutils.utils import merkle_root

    # Setup the network
    setup('testnet')

    # Parse a block
    block_hex = "0100000001..." # Hex representation of a block
    block = Block.from_hex(block_hex)

    # Get transaction IDs
    tx_ids = [tx.get_txid() for tx in block.get_transactions()]

    # Verify a specific transaction is in the block
    tx_id_to_verify = "1234..."
    if tx_id_to_verify in tx_ids:
        print(f"Transaction {tx_id_to_verify} is in the block")
        
        # Get the transaction
        tx_index = tx_ids.index(tx_id_to_verify)
        tx = block.get_transactions()[tx_index]
        
        # Process the transaction
        print(f"Transaction details:")
        print(f"  Inputs: {len(tx.get_inputs())}")
        print(f"  Outputs: {len(tx.get_outputs())}")
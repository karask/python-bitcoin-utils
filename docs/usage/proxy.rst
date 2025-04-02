Proxy Module
===========

The `proxy` module allows interaction with a Bitcoin node through RPC calls. It provides a convenient way to query blockchain information, submit transactions, and perform wallet operations.

NodeProxy Class
-------------

The main class in the proxy module is `NodeProxy`, which provides a wrapper around Bitcoin Core's JSON-RPC interface.

Basic Usage
----------

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.proxy import NodeProxy

    # Setup the network
    setup('testnet')

    # Connect to a Bitcoin node
    proxy = NodeProxy('username', 'password', host='127.0.0.1', port=18332)

    # Get blockchain information
    info = proxy.get_blockchain_info()
    print(f"Current blockchain height: {info['blocks']}")

    # Get the balance of the wallet
    balance = proxy.get_balance()
    print(f"Wallet balance: {balance}")

    # Send a raw transaction
    tx_hex = "0100000001..."
    tx_id = proxy.send_raw_transaction(tx_hex)
    print(f"Transaction submitted with ID: {tx_id}")

Connecting to a Bitcoin Node
--------------------------

You can connect to a Bitcoin node by creating a `NodeProxy` instance:

.. code-block:: python

    from bitcoinutils.proxy import NodeProxy

    # Connect to a local Bitcoin Core node
    proxy = NodeProxy(
        rpcuser='your_rpc_username',
        rpcpassword='your_rpc_password',
        host='127.0.0.1',  # Default is localhost
        port=18332,        # 18332 for testnet, 8332 for mainnet
        use_https=False    # Whether to use HTTPS for the connection
    )

    # Test the connection
    try:
        network_info = proxy.get_network_info()
        print(f"Connected to Bitcoin Core version: {network_info['version']}")
    except Exception as e:
        print(f"Connection failed: {e}")

Common RPC Methods
----------------

The `NodeProxy` class provides methods that correspond to Bitcoin Core's RPC commands. Here are some of the most commonly used methods:

Blockchain Information
^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    # Get blockchain info
    blockchain_info = proxy.get_blockchain_info()
    print(f"Chain: {blockchain_info['chain']}")
    print(f"Blocks: {blockchain_info['blocks']}")
    print(f"Headers: {blockchain_info['headers']}")
    
    # Get block hash at a specific height
    block_hash = proxy.get_block_hash(height=123456)
    
    # Get block information
    block = proxy.get_block(block_hash)
    
    # Get raw transaction
    tx = proxy.get_raw_transaction("transaction_id", verbose=True)

Wallet Operations
^^^^^^^^^^^^^^^

.. code-block:: python

    # Get wallet balance
    balance = proxy.get_balance()
    
    # Get unspent transaction outputs (UTXOs)
    utxos = proxy.list_unspent()
    
    # Create a new address
    new_address = proxy.get_new_address()
    
    # Send bitcoins to an address
    txid = proxy.send_to_address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", 0.001)

Transaction Operations
^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    # Create a raw transaction
    tx_inputs = [{"txid": "previous_txid", "vout": 0}]
    tx_outputs = {"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx": 0.001}
    raw_tx = proxy.create_raw_transaction(tx_inputs, tx_outputs)
    
    # Sign a raw transaction
    signed_tx = proxy.sign_raw_transaction(raw_tx)
    
    # Send a raw transaction
    tx_id = proxy.send_raw_transaction(signed_tx["hex"])
    
    # Get transaction info
    tx_info = proxy.get_transaction(tx_id)

Network Information
^^^^^^^^^^^^^^^^^

.. code-block:: python

    # Get network information
    net_info = proxy.get_network_info()
    print(f"Version: {net_info['version']}")
    print(f"Subversion: {net_info['subversion']}")
    print(f"Connections: {net_info['connections']}")
    
    # Get network statistics
    net_stats = proxy.get_network_stats()
    
    # Get peer information
    peer_info = proxy.get_peer_info()

Error Handling
-----------

It's important to handle errors that might occur during RPC calls:

.. code-block:: python

    try:
        # Attempt to get information about a non-existent transaction
        tx_info = proxy.get_transaction("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
    except Exception as e:
        print(f"Error: {e}")

Custom RPC Methods
---------------

You can call any RPC method that your Bitcoin Core node supports, even if it's not explicitly defined in the NodeProxy class:

.. code-block:: python

    # Call a custom RPC method
    result = proxy.call('estimatesmartfee', 6)  # Estimate fee for confirmation within 6 blocks
    
    # Or use the direct __call__ implementation
    result = proxy('estimatesmartfee', 6)

Working with Testnet
------------------

To work with the testnet network:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.proxy import NodeProxy

    # Setup the network for testnet
    setup('testnet')

    # Connect to a testnet node
    proxy = NodeProxy('username', 'password', port=18332)  # Note the testnet port

    # Get some testnet coins from a faucet
    faucet_address = proxy.get_new_address()
    print(f"Request testnet coins to be sent to: {faucet_address}")

Security Considerations
--------------------

When using the proxy module, keep these security considerations in mind:

1. **RPC Credentials**: Always protect your RPC username and password. Don't hardcode them in your scripts.

2. **Network Access**: By default, Bitcoin Core only accepts RPC connections from localhost. If you're connecting from another machine, ensure you've properly configured Bitcoin Core's `rpcallowip` setting.

3. **HTTPS**: For remote connections, consider using HTTPS by setting `use_https=True`.

4. **Transaction Validation**: Always validate transactions before broadcasting them to the network.

Example: Creating and Sending a Transaction
----------------------------------------

Here's a complete example of creating and sending a transaction using the proxy module:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.proxy import NodeProxy
    from bitcoinutils.keys import PrivateKey, P2pkhAddress
    from bitcoinutils.transactions import Transaction, TxInput, TxOutput

    # Setup network
    setup('testnet')

    # Connect to node
    proxy = NodeProxy('username', 'password', port=18332)

    # Get unspent outputs
    unspent = proxy.list_unspent()
    
    if len(unspent) > 0:
        # Get the first unspent output
        utxo = unspent[0]
        
        # Create a transaction input
        txin = TxInput(utxo['txid'], utxo['vout'])
        
        # Create a recipient address
        recipient_addr = P2pkhAddress('mzF2sbdxcMqKFLoakdBcvZpUXMjgiXGZW1')
        
        # Calculate amount (subtract fee)
        amount = utxo['amount'] - 0.0001  # Subtract fee
        
        # Create a transaction output
        txout = TxOutput(amount, recipient_addr.to_script_pub_key())
        
        # Create transaction
        tx = Transaction([txin], [txout])
        
        # Get private key for the unspent output
        priv_key = PrivateKey('your_private_key_wif')
        
        # Sign the input
        sig = priv_key.sign_input(tx, 0, P2pkhAddress(utxo['address']).to_script_pub_key())
        txin.script_sig = sig
        
        # Serialize the transaction
        signed_tx_hex = tx.serialize()
        
        # Send the transaction
        txid = proxy.send_raw_transaction(signed_tx_hex)
        print(f"Transaction sent! TXID: {txid}")
    else:
        print("No unspent outputs available.")

Troubleshooting
-------------

If you encounter issues with the proxy module:

1. **Connection Refused**: Make sure your Bitcoin Core node is running and accepting RPC connections.

2. **Authentication Failed**: Verify your RPC username and password are correct.

3. **Method Not Found**: Ensure the RPC method you're trying to call is supported by your Bitcoin Core version.

4. **Transaction Rejected**: If your transaction is rejected, check for issues like insufficient funds, invalid inputs, or non-standard scripts.

5. **RPC Timeout**: For operations that may take a long time, increase the timeout period when instantiating NodeProxy: `NodeProxy(rpcuser, rpcpassword, timeout=60)`.
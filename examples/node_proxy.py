# Copyright (C) 2018-2025 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.


from bitcoinutils.setup import setup
from bitcoinutils.proxy import NodeProxy


def main():
    # always remember to setup the network
    setup("regtest")

    # get a node proxy using default host and port
    proxy = NodeProxy("rpcuser", "rpcpw")

    # call the node's getblockcount JSON-RPC method
    count = proxy.getblockcount()

    # call the node's getblockhash JSON-RPC method
    block_hash = proxy.getblockhash(count)

    # call the node's getblock JSON-RPC method and print result
    block = proxy.getblock(block_hash)
    
    print("--- Block Information ---")
    print(f"Height: {block['height']}")
    print(f"Hash: {block['hash']}")
    print(f"Transactions: {len(block['tx'])}")
    print(f"Difficulty: {block['difficulty']}")

    print("\n--- Blockchain Information ---")
    binfo = proxy.getblockchaininfo()
    print(f"Chain: {binfo['chain']}")
    print(f"Blocks: {binfo['blocks']}")
    print(f"Size on disk: {binfo['size_on_disk']} bytes")

    print("\n--- Network Information ---")
    ninfo = proxy.getnetworkinfo()
    print(f"Version: {ninfo['version']}")
    print(f"Subversion: {ninfo['subversion']}")
    print(f"Connections: {ninfo['connections']}")

    print("\n--- Mempool Information ---")
    minfo = proxy.getmempoolinfo()
    print(f"Size: {minfo['size']} transactions")
    print(f"Bytes: {minfo['bytes']} bytes")

    print("\n--- Wallet Information ---")
    try:
        # These commands require a loaded wallet
        balance = proxy.getbalance()
        print(f"Balance: {balance} BTC")
        
        new_addr = proxy.getnewaddress()
        print(f"New address: {new_addr}")
    except Exception as e:
        print(f"Wallet commands failed (no wallet loaded?): {e}")


if __name__ == "__main__":
    main()

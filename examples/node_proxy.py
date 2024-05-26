# Copyright (C) 2018-2024 The python-bitcoin-utils developers
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
    setup("testnet")

    # get a node proxy using default host and port
    proxy = NodeProxy("rpcuser", "rpcpw").get_proxy()

    # call the node's getblockcount JSON-RPC method
    count = proxy.getblockcount()

    # call the node's getblockhash JSON-RPC method
    block_hash = proxy.getblockhash(count)

    # call the node's getblock JSON-RPC method and print result
    block = proxy.getblock(block_hash)
    print(block)

    # print only the difficulty of the network
    print(block["difficulty"])


if __name__ == "__main__":
    main()

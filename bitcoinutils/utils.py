# Copyright (C) 2018-2020 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from binascii import hexlify, unhexlify
from bitcoinutils.constants import SATOSHIS_PER_BITCOIN



'''
Converts from any number type (int/float/Decimal) to satoshis (int)
'''
def to_satoshis(num):
    # we need to round because of how floats are stored insternally:
    # e.g. 0.29 * 100000000 = 28999999.999999996
    return int( round(num * SATOSHIS_PER_BITCOIN) )


'''
Counts bytes and returns them with their compact size (or varint) prepended.
Accepts bytes and returns bytes. The length should be specified in
little-endian (which is why we reverse the array bytes).

https://bitcoin.org/en/developer-reference#compactsize-unsigned-integers
'''
def prepend_compact_size(data):
    prefix = b''
    size = len(data)
    if size >= 0 and size <= 252:
        prefix = unhexlify(format(size, '02x').encode())
    elif size >= 253 and size <= 0xffff:
        prefix = b'\xfd' + unhexlify(format(size, '04x'))[::-1]
    elif size >= 0x10000 and size <= 0xffffffff:
        prefix = b'\xfe' + unhexlify(format(size, '08x'))[::-1]
    elif size >= 0x100000000 and size <= 0xffffffffffffffff:
        prefix = b'\xff' + unhexlify(format(size, '016x'))[::-1]
    else:
        raise ValueError("Data size not between 0 and 0xffffffffffffffff")

    return prefix + data


'''
Takes raw transaction (serialized hex) and deconstructs it to display which
hex correspond to which part of a transaction's structure
TODO maybe use pack/unpack instead? ..also fix varints first? ..also check
markers if is is segwit first?
'''
#def deconstruct_raw_tx(rawtx):
#    temp = unhexlify(rawtx)
#    # works directly on hex thus all lengths are doubled
#    version = rawtx[0:8]
#    temp = temp[8:]
#    # not varint
#    txin_num = rawtx[0:2]
#    temp = temp[2:]
#    txins = []
#    for i in range(0, int(txin_num, 16)):
#        txins = [ temp[0:64] ]
#        tx
#    print(version)
#
#    return True
#




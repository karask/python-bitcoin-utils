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



def to_satoshis(num):
    '''
    Converts from any number type (int/float/Decimal) to satoshis (int)
    '''
    # we need to round because of how floats are stored insternally:
    # e.g. 0.29 * 100000000 = 28999999.999999996
    return int( round(num * SATOSHIS_PER_BITCOIN) )


def prepend_varint(data):
    '''
    Counts bytes and returns them with their varint (or compact size) prepended.
    Accepts bytes and returns bytes.
    '''
    varint_bytes = encode_varint( len(data) )
    return varint_bytes + data


def encode_varint(i):
    '''
    Encode a potentially very large integer into varint bytes. The length should be
    specified in little-endian.

    https://bitcoin.org/en/developer-reference#compactsize-unsigned-integers
    '''
    if i < 253:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' +  i.to_bytes(2, 'little')
    elif i < 0x100000000:
        return b'\xfe' +  i.to_bytes(4, 'little')
    elif i < 0x10000000000000000:
        return b'\xff' +  i.to_bytes(8, 'little')
    else:
        raise ValueError("Integer is too large: %d" % i)


def is_address_bech32(address):
    '''
    Returns if an address (string) is bech32 or not
    TODO improve by checking if valid, etc.
    '''
    if (address.startswith('bc') or
        address.startswith('tb')):
        return True

    return False


def vi_to_int(byteint):
    '''
    Converts varint bytes to int
    '''
    if not isinstance(byteint, (bytes)):
        raise Exception("Byteint must be a list or defined as bytes")

    ni = byteint[0]
    if ni < 253:
        return ni, 1
    if ni == 253:  # integer of 2 bytes
        size = 2
    elif ni == 254:  # integer of 4 bytes
        size = 4
    else:  # integer of 8 bytes
        size = 8

    return int.from_bytes(byteint[1:1+size][::-1], 'big'), size + 1


def to_bytes(string, unhexlify=True):
    '''
	Converts a hex string to bytes
    '''
    if not string:
        return b''
    if unhexlify:
        try:
            if isinstance(string, bytes):
                string = string.decode()
            s = bytes.fromhex(string)
            return s
        except (TypeError, ValueError):
            pass
    if isinstance(string, bytes):
        return string
    else:
        return bytes(string, 'utf8')



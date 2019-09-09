# Copyright (C) 2018 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import struct
import copy
import hashlib
from binascii import unhexlify, hexlify

import bitcoinutils.keys


# Bitcoin's op codes. Complete list at: https://en.bitcoin.it/wiki/Script
OP_CODES = {
    # constants
    'OP_0'                  : b'\x00',
    'OP_FALSE'              : b'\x00',
    'OP_PUSHDATA1'          : b'\x4c',
    'OP_PUSHDATA2'          : b'\x4d',
    'OP_PUSHDATA4'          : b'\x4e',
    'OP_1NEGATE'            : b'\x4f',
    'OP_1'                  : b'\x51',
    'OP_TRUE'               : b'\x51',
    'OP_2'                  : b'\x52',
    'OP_3'                  : b'\x53',
    'OP_4'                  : b'\x54',
    'OP_5'                  : b'\x55',
    'OP_6'                  : b'\x56',
    'OP_7'                  : b'\x57',
    'OP_8'                  : b'\x58',
    'OP_9'                  : b'\x59',
    'OP_10'                 : b'\x5a',
    'OP_11'                 : b'\x5b',
    'OP_12'                 : b'\x5c',
    'OP_13'                 : b'\x5d',
    'OP_14'                 : b'\x5e',
    'OP_15'                 : b'\x5f',
    'OP_16'                 : b'\x60',

    # flow control
    'OP_NOP'                : b'\x61',
    'OP_IF'                 : b'\x63',
    'OP_NOTIF'              : b'\x64',
    'OP_ELSE'               : b'\x67',
    'OP_ENDIF'              : b'\x68',
    'OP_VERIFY'             : b'\x69',
    'OP_RETURN'             : b'\x6a',

    # stack
    'OP_TOALTSTACK'         : b'\x6b',
    'OP_FROMALTSTACK'       : b'\x6c',
    'OP_IFDUP'              : b'\x73',
    'OP_DEPTH'              : b'\x74',
    'OP_DROP'               : b'\x75',
    'OP_DUP'                : b'\x76',
    'OP_NIP'                : b'\x77',
    'OP_OVER'               : b'\x78',
    'OP_PICK'               : b'\x79',
    'OP_ROLL'               : b'\x7a',
    'OP_ROT'                : b'\x7b',
    'OP_SWAP'               : b'\x7c',
    'OP_TUCK'               : b'\x7d',
    'OP_2DROP'              : b'\x6d',
    'OP_2DUP'               : b'\x6e',
    'OP_3DUP'               : b'\x6f',
    'OP_2OVER'              : b'\x70',
    'OP_2ROT'               : b'\x71',
    'OP_2SWAP'              : b'\x72',

    # splice
    #'OP_CAT'                : b'\x7e',
    #'OP_SUBSTR'             : b'\x7f',
    #'OP_LEFT'               : b'\x80',
    #'OP_RIGHT'              : b'\x81',
    'OP_SIZE'               : b'\x82',

    # bitwise logic
    #'OP_INVERT'             : b'\x83',
    #'OP_AND'                : b'\x84',
    #'OP_OR'                 : b'\x85',
    #'OP_XOR'                : b'\x86',
    'OP_EQUAL'              : b'\x87',
    'OP_EQUALVERIFY'        : b'\x88',

    # arithmetic
    'OP_1ADD'               : b'\x8b',
    'OP_1SUB'               : b'\x8c',
    #'OP_2MUL'               : b'\x8d',
    #'OP_2DIV'               : b'\x8e',
    'OP_NEGATE'             : b'\x8f',
    'OP_ABS'                : b'\x90',
    'OP_NOT'                : b'\x91',
    'OP_0NOTEQUAL'          : b'\x92',
    'OP_ADD'                : b'\x93',
    'OP_SUB'                : b'\x94',
    #'OP_MUL'                : b'\x95',
    #'OP_DIV'                : b'\x96',
    #'OP_MOD'                : b'\x97',
    #'OP_LSHIFT'             : b'\x98',
    #'OP_RSHIFT'             : b'\x99',
    'OP_BOOLAND'            : b'\x9a',
    'OP_BOOLOR'             : b'\x9b',
    'OP_NUMEQUAL'           : b'\x9c',
    'OP_NUMEQUALVERIFY'     : b'\x9d',
    'OP_NUMNOTEQUAL'        : b'\x9e',
    'OP_LESSTHAN'           : b'\x9f',
    'OP_GREATERTHAN'        : b'\xa0',
    'OP_LESSTHANOREQUAL'    : b'\xa1',
    'OP_GREATERTHANOREQUAL' : b'\xa2',
    'OP_MIN'                : b'\xa3',
    'OP_MAX'                : b'\xa4',
    'OP_WITHIN'             : b'\xa5',

    # crypto
    'OP_RIPEMD160'          : b'\xa6',
    'OP_SHA1'               : b'\xa7',
    'OP_SHA256'             : b'\xa8',
    'OP_HASH160'            : b'\xa9',
    'OP_HASH256'            : b'\xaa',
    'OP_CODESEPARATOR'      : b'\xab',
    'OP_CHECKSIG'           : b'\xac',
    'OP_CHECKSIGVERIFY'     : b'\xad',
    'OP_CHECKMULTISIG'      : b'\xae',
    'OP_CHECKMULTISIGVERIFY': b'\xaf',

    # locktime
    'OP_NOP2'               : b'\xb1',
    'OP_CHECKLOCKTIMEVERIFY': b'\xb1',
    'OP_NOP3'               : b'\xb2',
    'OP_CHECKSEQUENCEVERIFY': b'\xb2'


}

class Script:
    """Represents any script in Bitcoin

    A Script contains just a list of OP_CODES and also knows how to serialize
    into bytes

    Attributes
    ----------
    script : list
        the list with all the script OP_CODES and data

    Methods
    -------
    to_bytes()
        returns a serialized byte version of the script

    Raises
    ------
    ValueError
        If string data is too large or integer is negative
    """

    def __init__(self, script):
        """See Script description"""

        self.script = script


    @classmethod
    def copy(cls, script):
        """Deep copy of Script"""
        scripts = copy.deepcopy(script.script)
        return cls(scripts)


    def _op_push_data(self, data):
        """Converts data to appropriate OP_PUSHDATA OP code including length

        0x01-0x4b           -> just length plus data bytes
        0x4c-0xff           -> OP_PUSHDATA1 plus 1-byte-length plus data bytes
        0x0100-0xffff       -> OP_PUSHDATA2 plus 2-byte-length plus data bytes
        0x010000-0xffffffff -> OP_PUSHDATA4 plus 4-byte-length plus data bytes

        Also note that according to standarardness rules (BIP-62) the minimum
        possible PUSHDATA operator must be used!
        """

        # expects data in hexadecimal characters and converts appropriately
        # TODO maybe, for convenience, also accept objects for public keys,
        # addresses, etc. and use isinstance and convert manually
        data_bytes = unhexlify(data)

        if len(data_bytes) < 0x4c:
            return chr(len(data_bytes)).encode() + data_bytes
        elif len(data_bytes) < 0xff:
            return b'\x4c' + chr(len(data_bytes)).encode() + data_bytes
        elif len(data_bytes) < 0xffff:
            return b'\x4d' + struct.pack('<H', len(data_bytes)) + data_bytes
        elif len(data_bytes) < 0xffffffff:
            return b'\x4e' + struct.pack('<I', len(data_bytes)) + data_bytes
        else:
            raise ValueError("Data too large. Cannot push into script")


    def _segwit_op_push_data(self, data):
        # expects data in hexadecimal characters and converts appropriately
        # TODO maybe, for convenience, also accept objects for public keys,
        # addresses, etc. and use isinstance and convert manually
        data_bytes = unhexlify(data)
        return chr(len(data_bytes)).encode() + data_bytes


    def _push_integer(self, integer):
        """Converts integer to bytes; as signed little-endian integer

        Currently supports only positive integers
        """

        if integer < 0:
            raise ValueError('Integer is currently required to be positive.')

        # bytes requires to represent the integer
        number_of_bytes = (integer.bit_length() + 7) // 8

        # convert to little-endian bytes
        integer_bytes = integer.to_bytes(number_of_bytes, byteorder='little')

        # if last bit is set then we need to add sign to signify positive
        # integer
        if integer & (1 << number_of_bytes*8 - 1):
            integer_bytes += b'\x00'

        return self._op_push_data( hexlify(integer_bytes) )


    def to_bytes(self, segwit = False):
        """Converts the script to bytes

        If an OP code the appropriate byte is included according to:
        https://en.bitcoin.it/wiki/Script
        If not consider it data (signature, public key, public key hash, etc.) and
        and include with appropriate OP_PUSHDATA OP code plus length
        """
        script_bytes = b''
        for token in self.script:
            # add op codes directly
            if token in OP_CODES:
                script_bytes += OP_CODES[token]
            # if integer between 0 and 16 add the appropriate op code
            elif type(token) is int and token >= 0 and token <= 16:
                script_bytes += OP_CODES['OP_' + str(token)]
            # it is data, so add accordingly
            else:
                if type(token) is int:
                    script_bytes += self._push_integer(token)
                else:
                    if segwit:
                        # TODO this should be temporariy and replaced by
                        # a method that calculates compactSize/VarInt for
                        # each script element - probably add TxInputWitness
                        # which will know how to serialize
                        script_bytes += self._segwit_op_push_data(token)
                    else:
                        script_bytes += self._op_push_data(token)

        return script_bytes


    def to_hex(self):
        """Converts the script to hexadecimal"""

        b = self.to_bytes()
        return hexlify(b).decode('utf-8')


    def to_p2sh_script_pub_key(self):
        """Converts script to p2sh scriptPubKey (locking script)

        Calculates the hash160 (via the address) of the script and uses it to
        construct a P2SH script.
        """

        address = bitcoinutils.keys.P2shAddress.from_script(self)
        return Script(['OP_HASH160', address.to_hash160(), 'OP_EQUAL'])


    def to_p2wsh_script_pub_key(self):
        """Converts script to p2wsh scriptPubKey (locking script)

        Calculates the sha256 of the script and uses it to construct a P2WSH script.
        """
        sha256 = hashlib.sha256( self.to_bytes() ).digest()
        return Script(['OP_0', hexlify(sha256).decode('utf-8')])



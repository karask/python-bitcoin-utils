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
from binascii import unhexlify, hexlify

import bitcoinutils.keys


# Bitcoin's op codes. Complete list at: https://en.bitcoin.it/wiki/Script
OP_CODES = {
    'OP_DUP'            : b'\x76',
    'OP_EQUAL'          : b'\x87',
    'OP_EQUALVERIFY'    : b'\x88',
    'OP_HASH160'        : b'\xa9',
    'OP_CHECKSIG'       : b'\xac'
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
    """

    def __init__(self, script):
        """See Script description"""

        self.script = script


    def _op_push_data(self, data):
        """Converts data to appropriate OP_PUSHDATA OP code including length

        0x01-0x4b           -> just length plus data bytes
        0x4c-0xff           -> OP_PUSHDATA1 plus 1-byte-length plus data bytes
        0x0100-0xffff       -> OP_PUSHDATA2 plus 2-byte-length plus data bytes
        0x010000-0xffffffff -> OP_PUSHDATA4 plus 4-byte-length plus data bytes

        Also note that according to standarardness rules (BIP-62) the minimum
        possible PUSHDATA operator must be used!
        """
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


    def to_bytes(self):
        """Converts the script to bytes

        If an OP code the appropriate byte is included according to:
        https://en.bitcoin.it/wiki/Script
        If not consider it data (signature, public key, public key hash, etc.) and
        and include with appropriate OP_PUSHDATA OP code plus length
        """
        script_bytes = b''
        for token in self.script:
            if token in OP_CODES:
                script_bytes += OP_CODES[token]
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




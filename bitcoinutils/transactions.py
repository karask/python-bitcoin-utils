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

#import re
#import hashlib
import struct
#from base64 import b64encode, b64decode
from binascii import unhexlify, hexlify
#from base58check import b58encode, b58decode
#from ecdsa import SigningKey, VerifyingKey, SECP256k1, ellipticcurve, numbertheory
#from ecdsa.util import sigencode_string, sigdecode_string
#from sympy.ntheory import sqrt_mod

OP_CODES = {
    'OP_DUP'            : b'\x76',
    'OP_EQUAL'          : b'\x87',
    'OP_EQUALVERIFY'    : b'\x88',
    'OP_HASH160'        : b'\xa9',
    'OP_CHECKSIG'       : b'\xac'
}

def op_push_data(data):
    """Data is hex string ... Blah"""
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

def script_to_bytes(script):
    """..."""
    script_bytes = b''
    for token in script:
        if token in OP_CODES:
            script_bytes += OP_CODES[token]
        else:
            script_bytes += op_push_data(token)
    return script_bytes


DEFAULT_TX_SEQUENCE = b'\xff\xff\xff\xff'
DEFAULT_TX_LOCKTIME = b'\x00\x00\x00\x00'
# TX version 2 was introduced in BIP-68 with relative locktime -- tx v1 do not
# support relative locktime
DEFAULT_TX_VERSION  = b'\x02\x00\x00\x00'
SHATOSHIS_PER_BITCOIN = 100000000

class TxInput:
    """Represents an ECDSA private key.

    Attributes
    ----------
    key : bytes
        the raw key of 32 bytes

    Methods
    -------
    from_wif(wif)
        creates an object from a WIF of WIFC format (string)
    to_wif(compressed=True)
        returns as WIFC (compressed) or WIF format (string)
    to_bytes()
        returns the key's raw bytes
    sign_message(message, compressed=True)
        signs and returns the message with the private key
    get_public_key()
        returns the corresponding PublicKey object
    """

    def __init__(self, txid, txout_index, script_sig=b'',
                 sequence=DEFAULT_TX_SEQUENCE):
        """With no parameters a random key is created

        Parameters
        ----------
        wif : str, optional
            the key in WIF of WIFC format (default None)
        secret_exponent : int, optional
            used to create a specific key deterministically (default None)
        """
        # expected in the format used for displaying Bitcoin hashes
        self.txid = txid
        self.txout_index = txout_index
        self.script_sig = script_sig
        # if user provided a sequence it would be as string (for now...)
        if sequence != DEFAULT_TX_SEQUENCE:
            self.sequence = unhexlify(sequence)
        else:
            self.sequence = sequence


    def stream(self):
        # Internally Bitcoin uses little-endian byte order as it improves
        # speed. Hashes are defined and implemented as big-endian thus
        # those are transmitted in big-endian ordre. However, when hashes are
        # displayed Bitcoin uses little-endian order because it is sometimes
        # convenient to consider hashes as little-endian integers (and not
        # strings)
        # https://bitcoin.stackexchange.com/questions/2063/why-does-the-bitcoin-protocol-use-the-little-endian-notation
        # note struct uses little-endian by default
        # note that we reverse the byte order for the tx hash since the string
        # was displayed in little-endian!
        txid_bytes = unhexlify(self.txid)[::-1]
        txout_bytes = struct.pack('i', self.txout_index)
        script_sig_bytes = script_to_bytes(self.script_sig)
        data = txid_bytes + txout_bytes + \
                struct.pack('B', len(script_sig_bytes)) + \
                script_sig_bytes + self.sequence
        return data

    @classmethod
    def copy(cls, txin):
        return cls(txin.txid, txin.txout_index, txin.script_sig,
                       txin.sequence)



class TxOutput:
    """Represents an ECDSA public key.

    Attributes
    ----------
    key : bytes
        the raw public key of 64 bytes (x, y coordinates of the ECDSA curve

    Methods
    -------
    from_hex(hex_str)
        creates an object from a hex string in SEC format
    from_message_signature(signature)
        NO-OP!
    verify_message(address, signature, message)
        Class method that constructs the public key, confirms the address and
        verifies the signature
    to_hex(compressed=True)
        returns the key as hex string (in SEC format - compressed by default)
    to_bytes()
        returns the key's raw bytes
    get_address(compressed=True))
        returns the corresponding Address object
    """


    def __init__(self, amount, script_pubkey):
        """
        Parameters
        ----------
        hex_str : str
            the public key in hex string

        Raises
        ------
        TypeError
            If first byte of public key (corresponding to SEC format) is
            invalid.
        """
        # ...
        self.amount = amount
        self.script_pubkey = script_pubkey


    def stream(self):
        # internally all little-endian except hashes
        # note struct uses little-endian by default
        amount_bytes = struct.pack('Q', int(self.amount * SHATOSHIS_PER_BITCOIN))
        script_bytes = script_to_bytes(self.script_pubkey)
        data = amount_bytes + struct.pack('B', len(script_bytes)) + script_bytes
        return data


    @classmethod
    def copy(cls, txout):
        return cls(txout.amount, txout.script_pubkey)


class Transaction:
    """Represents a Bitcoin address derived from a public key

    Attributes
    ----------
    hash160 : str
        the hash160 string representation of the address; hash160 represents
        two consequtive hashes of the public key, first a SHA-256 and then an
        RIPEMD-160

    Methods
    -------
    from_address(address)
        instantiates an object from address string encoding
    from_hash160(hash160_str)
        instantiates an object from a hash160 hex string
    to_address()
        returns the address's string encoding
    to_hash160()
        returns the address's hash160 hex string representation

    Raises
    ------
    TypeError
        No parameters passed
    ValueError
        If an invalid address or hash160 is provided.
    """

    def __init__(self, inputs=[], outputs=[], locktime=DEFAULT_TX_LOCKTIME,
                 version=DEFAULT_TX_VERSION):
        """
        Parameters
        ----------
        address : str
            the address as a string
        hash160 : str
            the hash160 hex string representation

        Raises
        ------
        TypeError
            No parameters passed
        ValueError
            If an invalid address or hash160 is provided.
        """
        self.inputs = inputs
        self.outputs = outputs

        # if user provided a locktime it would be as string (for now...)
        if locktime != DEFAULT_TX_LOCKTIME:
            self.locktime = unhexlify(locktime)
        else:
            self.locktime = locktime

        self.version = version


    @classmethod
    def copy(cls, tx):
        ins = [TxInput.copy(txin) for txin in tx.inputs]
        outs = [TxOutput.copy(txout) for txout in tx.outputs]
        return cls(ins, outs, tx.locktime, tx.version)


    def stream(self):
        data = self.version
        txin_count_bytes = chr(len(self.inputs)).encode()
        txout_count_bytes = chr(len(self.outputs)).encode()
        data += txin_count_bytes
        for txin in self.inputs:
            data += txin.stream()
        data += txout_count_bytes
        for txout in self.outputs:
            data += txout.stream()
        data += self.locktime
        return data


    def serialize(self):
        return hexlify(self.stream()).decode('utf-8')


def main():
    # READ EXAMPLE SERIALIZATION OF SEGWIT TX:
    # https://medium.com/coinmonks/how-to-create-a-raw-bitcoin-transaction-step-by-step-239b888e87f2
    pass

if __name__ == "__main__":
    main()


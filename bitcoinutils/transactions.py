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

import hashlib
import struct
from binascii import unhexlify, hexlify

from bitcoinutils.constants import DEFAULT_TX_SEQUENCE, DEFAULT_TX_LOCKTIME, \
                      DEFAULT_TX_VERSION, SHATOSHIS_PER_BITCOIN, SIGHASH_ALL
from bitcoinutils.script import OP_CODES, script_to_bytes



class TxInput:
    """Represents a transaction input.

    A transaction input requires a transaction id of a UTXO and the index of
    that UTXO.

    Attributes
    ----------
    txid : str
        the transaction id as a hex string (little-endian as displayed by
        tools)
    txout_index : int
        the index of the UTXO that we want to spend
    script_sig : list (strings)
        the op code and data of the script as string
    sequence : bytes
        the input sequence (for timelocks, RBF, etc.)

    Methods
    -------
    stream()
        converts TxInput to bytes
    copy()
        creates a copy of the object (classmethod)
    """

    def __init__(self, txid, txout_index, script_sig=b'',
                 sequence=DEFAULT_TX_SEQUENCE):
        """See TxInput description"""

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
        """Converts to bytes"""

        # Internally Bitcoin uses little-endian byte order as it improves
        # speed. Hashes are defined and implemented as big-endian thus
        # those are transmitted in big-endian order. However, when hashes are
        # displayed Bitcoin uses little-endian order because it is sometimes
        # convenient to consider hashes as little-endian integers (and not
        # strings)
        # - note that we reverse the byte order for the tx hash since the string
        #   was displayed in little-endian!
        # - note that python's struct uses little-endian by default
        txid_bytes = unhexlify(self.txid)[::-1]
        txout_bytes = struct.pack('<L', self.txout_index)
        script_sig_bytes = script_to_bytes(self.script_sig)
        data = txid_bytes + txout_bytes + \
                struct.pack('B', len(script_sig_bytes)) + \
                script_sig_bytes + self.sequence
        return data

    @classmethod
    def copy(cls, txin):
        """Deep copy of TxInput"""

        return cls(txin.txid, txin.txout_index, txin.script_sig,
                       txin.sequence)



class TxOutput:
    """Represents a transaction output

    Attributes
    ----------
    amount : float
        the value we want to send to this output (in BTC)
    script_pubkey : list (string)
        the script that will lock this amount

    Methods
    -------
    stream()
        converts TxInput to bytes
    copy()
        creates a copy of the object (classmethod)
    """


    def __init__(self, amount, script_pubkey):
        """See TxOutput description"""

        self.amount = amount
        self.script_pubkey = script_pubkey


    def stream(self):
        """Converts to bytes"""

        # internally all little-endian except hashes
        # note struct uses little-endian by default
        # 0.29*100000000 results in 28999999.999999996 so we round to the
        # closest integer -- this is because the result is represented as
        # fractions
        amount_bytes = struct.pack('<Q', round(self.amount * SHATOSHIS_PER_BITCOIN))
        script_bytes = script_to_bytes(self.script_pubkey)
        data = amount_bytes + struct.pack('B', len(script_bytes)) + script_bytes
        return data


    @classmethod
    def copy(cls, txout):
        """Deep copy of TxOutput"""

        return cls(txout.amount, txout.script_pubkey)


class Transaction:
    """Represents a Bitcoin transaction

    Attributes
    ----------
    inputs : list (TxInput)
        A list of all the transaction inputs
    outputs : list (TxOutput)
        A list of all the transaction outputs
    locktime : bytes
        The transaction's locktime parameter
    version : bytes
        The transaction version

    Methods
    -------
    stream()
        Converts Transaction to bytes
    serialize()
        Converts Transaction to hex string
    copy()
        creates a copy of the object (classmethod)
    get_transaction_digest(txin_index, script, sighash)
        returns the transaction input's digest that is to be signed according
        to sighash
    """

    def __init__(self, inputs=[], outputs=[], locktime=DEFAULT_TX_LOCKTIME,
                 version=DEFAULT_TX_VERSION):
        """See Transaction description"""
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
        """Deep copy of Transaction"""

        ins = [TxInput.copy(txin) for txin in tx.inputs]
        outs = [TxOutput.copy(txout) for txout in tx.outputs]
        return cls(ins, outs, tx.locktime, tx.version)


    def get_transaction_digest(self, txin_index, script, sighash=SIGHASH_ALL):
        """Returns the transaction's digest for signing.

        SIGHASH types (see constants.py):
            SIGHASH_ALL
            SIGHASH_NONE
            SIGHASH_SINGLE
            SIGHASH_ANYONECANPAY (only combined with one of the above)

        Attributes
        ----------
        txin_index : int
            The index of the input that we wish to sign
        script : list (string)
            The scriptPubKey of the UTXO that we want to spend
        sighash : int
            The type of the signature hash to be created
        """

        # clone transaction to modify without messing up the tx
        tmp_tx = Transaction.copy(self)

        # make sure all input scriptSigs are empty
        for txin in tmp_tx.inputs:
            txin.script_sig = b''

        # TODO Delete script's OP_CODESEPARATORs, if any

        # the temporary transaction's scriptSig needs to be set to the
        # scriptPubKey of the UTXO we are trying to spend
        tmp_tx.inputs[txin_index].script_sig = script

        #
        # by default SIGHASH_ALL will be used
        #
        # TODO: here manage NONE SINGLE ANYONECANPAY
        #if sighash=SIGHASH_ALL use stream... not good for other SIGHASHes

        # get the byte stream of the temporary transaction
        tx_for_signing = tmp_tx.stream()

        # add sighash bytes to be hashed
        # Note that although sighash is one byte it is hashed as a 4 byte value.
        # There is no real reason for this other than that the original implementation
        # of Bitcoin stored sighash as an integer (which serializes as a 4
        # bytes), i.e. it should be converted to one byte before serialization.
        # It is converted to 1 byte before serializing to send to the network
        tx_for_signing += struct.pack('<i', sighash)

        # create transaction digest -- note double hashing
        tx_digest = hashlib.sha256( hashlib.sha256(tx_for_signing).digest()).digest()

        return tx_digest


    def stream(self):
        """Converts to bytes"""

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
        """Converts to hex string"""

        return hexlify(self.stream()).decode('utf-8')


def main():
    # READ EXAMPLE SERIALIZATION OF SEGWIT TX:
    # https://medium.com/coinmonks/how-to-create-a-raw-bitcoin-transaction-step-by-step-239b888e87f2
    pass

if __name__ == "__main__":
    main()


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

import math
import hashlib
import struct
from binascii import unhexlify, hexlify
from decimal import Decimal

from bitcoinutils.constants import DEFAULT_TX_SEQUENCE, DEFAULT_TX_LOCKTIME, \
                    DEFAULT_TX_VERSION, NEGATIVE_SATOSHI, \
                    EMPTY_TX_SEQUENCE, SIGHASH_ALL, SIGHASH_NONE, \
                    SIGHASH_SINGLE, SIGHASH_ANYONECANPAY, \
                    ABSOLUTE_TIMELOCK_SEQUENCE, REPLACE_BY_FEE_SEQUENCE, \
                    TYPE_ABSOLUTE_TIMELOCK, TYPE_RELATIVE_TIMELOCK, \
                    TYPE_REPLACE_BY_FEE, SATOSHIS_PER_BITCOIN
from bitcoinutils.script import Script



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

    def __init__(self, txid, txout_index, script_sig=Script([]), sequence=DEFAULT_TX_SEQUENCE):
        """See TxInput description"""

        # expected in the format used for displaying Bitcoin hashes
        self.txid = txid
        self.txout_index = txout_index
        self.script_sig = script_sig

        # if user provided a sequence it would be as string (for now...)
        if type(sequence) is str:
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
        script_sig_bytes = self.script_sig.to_bytes()
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
    amount : Decimal
        the value we want to send to this output
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

        if not isinstance(amount, Decimal):
            raise TypeError("Amount needs to be a Python Decimal object")
        self.amount = amount
        self.script_pubkey = script_pubkey


    def stream(self):
        """Converts to bytes"""

        # internally all little-endian except hashes
        # note struct uses little-endian by default

        amount_bytes = struct.pack('<q', int(self.amount * SATOSHIS_PER_BITCOIN))
        script_bytes = self.script_pubkey.to_bytes()
        data = amount_bytes + struct.pack('B', len(script_bytes)) + script_bytes
        return data


    @classmethod
    def copy(cls, txout):
        """Deep copy of TxOutput"""

        return cls(txout.amount, txout.script_pubkey)


class Sequence:
    """Helps setting up appropriate sequence. Used to provide the sequence to
    transaction inputs and to scripts.

    Attributes
    ----------
    value : int
        The value of the block height or the 512 seconds increments
    seq_type : int
        Specifies the type of sequence (TYPE_RELATIVE_TIMELOCK |
        TYPE_ABSOLUTE_TIMELOCK | TYPE_REPLACE_BY_FEE
    is_type_block : bool
        If type is TYPE_RELATIVE_TIMELOCK then this specifies its type 
        (block height or 512 secs increments)

    Methods
    -------
    for_input_sequence()
        Serializes the relative sequence as required in a transaction
    for_script()
        Returns the appropriate integer for a script; e.g. for relative timelocks

    Raises
    ------
    ValueError
        if the value is not within range of 2 bytes.
    """

    def __init__(self, seq_type, value=None, is_type_block=True):
        self.seq_type = seq_type
        self.value = value
        if self.seq_type == TYPE_RELATIVE_TIMELOCK and (self.value < 1 or self.value > 0xffff):
            raise ValueError('Sequence should be between 1 and 65535')
        self.is_type_block = is_type_block

    def for_input_sequence(self):
        """Creates a relative timelock sequence value as expected from 
        TxInput sequence attribute"""
        if self.seq_type == TYPE_ABSOLUTE_TIMELOCK:
            return ABSOLUTE_TIMELOCK_SEQUENCE

        if self.seq_type == TYPE_REPLACE_BY_FEE:
            return REPLACE_BY_FEE_SEQUENCE

        if self.seq_type == TYPE_RELATIVE_TIMELOCK:
            # most significant bit is already 0 so relative timelocks are enabled
            seq = 0
            # if not block height type set 23 bit
            if not self.is_type_block:
                seq |= 1 << 22
            # set the value
            seq |= self.value
            seq_bytes = seq.to_bytes(4, byteorder='little')
            return seq_bytes



    def for_script(self):
        """Creates a relative/absolute timelock sequence value as expected in scripts"""
        if self.seq_type == TYPE_REPLACE_BY_FEE:
            raise ValueError('RBF is not to be included in a script.')

        script_integer = self.value

        # if not block-height type then set 23 bit
        if self.seq_type == TYPE_RELATIVE_TIMELOCK and not self.is_type_block:
            script_integer |= 1 << 22

        return script_integer


class Locktime:
    """Helps setting up appropriate locktime.

    Attributes
    ----------
    value : int
        The value of the block height or the 512 seconds increments

    Methods
    -------
    for_transaction()
        Serializes the locktime as required in a transaction

    Raises
    ------
    ValueError
        if the value is not within range of 2 bytes.
    """

    def __init__(self, value):
        self.value = value

    def for_transaction(self):
        """Creates a timelock as expected from Transaction"""

        locktime_bytes = self.value.to_bytes(4, byteorder='little')
        return locktime_bytes



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
    has_segwit : bool
        Specifies a tx that includes segwit inputs
    witnesses : list (Script)
        The witness scripts that correspond to the inputs


    Methods
    -------
    stream()
        Converts Transaction to bytes
    serialize()
        Converts Transaction to hex string
    get_txid()
        Calculates txid and returns it
    get_hash()
        Calculates tx hash (wtxid) and returns it
    get_wtxid()
        Calculates tx hash (wtxid) and returns it
    get_size()
        Calculates the tx size
    get_vsize()
        Calculates the tx segwit size
    copy()
        creates a copy of the object (classmethod)
    get_transaction_digest(txin_index, script, sighash)
        returns the transaction input's digest that is to be signed according
    get_transaction_segwit_digest(txin_index, script, amount, sighash)
        returns the transaction input's segwit digest that is to be signed
        according to sighash
    """

    def __init__(self, inputs=[], outputs=[], locktime=DEFAULT_TX_LOCKTIME,
                 version=DEFAULT_TX_VERSION, has_segwit=False, witnesses=[]):
        """See Transaction description"""
        self.inputs = inputs
        self.outputs = outputs
        self.has_segwit = has_segwit
        self.witnesses = witnesses

        # if user provided a locktime it would be as string (for now...)
        if type(locktime) is str:
            self.locktime = unhexlify(locktime)
        else:
            self.locktime = locktime

        self.version = version


    @classmethod
    def copy(cls, tx):
        """Deep copy of Transaction"""

        ins = [TxInput.copy(txin) for txin in tx.inputs]
        outs = [TxOutput.copy(txout) for txout in tx.outputs]
        wits = [Script.copy(witness) for witness in tx.witnesses]
        return cls(ins, outs, tx.locktime, tx.version, tx.has_segwit, wits)


    def get_transaction_digest(self, txin_index, script, sighash=SIGHASH_ALL):
        """Returns the transaction's digest for signing.

        |  SIGHASH types (see constants.py):
        |      SIGHASH_ALL - signs all inputs and outputs (default)
        |      SIGHASH_NONE - signs all of the inputs
        |      SIGHASH_SINGLE - signs all inputs but only txin_index output
        |      SIGHASH_ANYONECANPAY (only combined with one of the above)
        |      - with ALL - signs all outputs but only txin_index input
        |      - with NONE - signs only the txin_index input
        |      - with SINGLE - signs txin_index input and output

        Attributes
        ----------
        txin_index : int
            The index of the input that we wish to sign
        script : list (string)
            The scriptPubKey of the UTXO that we want to spend
        sighash : int
            The type of the signature hash to be created
        """

        # clone transaction to modify without messing up the real transaction
        tmp_tx = Transaction.copy(self)

        # make sure all input scriptSigs are empty
        for txin in tmp_tx.inputs:
            txin.script_sig = Script([])

        #
        # TODO Deal with (delete?) script's OP_CODESEPARATORs, if any
        # Very early versions of Bitcoin were using a different design for
        # scripts that were flawed. OP_CODESEPARATOR has no purpose currently
        # but we could not delete it for compatibility purposes. If it exists
        # in a script it needs to be removed.
        #

        # the temporary transaction's scriptSig needs to be set to the
        # scriptPubKey of the UTXO we are trying to spend - this is required to
        # get the correct transaction digest (which is then signed)
        tmp_tx.inputs[txin_index].script_sig = script

        #
        # by default we sign all inputs/outputs (SIGHASH_ALL is used)
        #

        # whether 0x0n or 0x8n, bitwise AND'ing will result to n
        if (sighash & 0x1f) == SIGHASH_NONE:
            # do not include outputs in digest (i.e. do not sign outputs)
            tmp_tx.outputs = []

            # do not include sequence of other inputs (zero them for digest)
            # which means that they can be replaced
            for i in range(len(tmp_tx.inputs)):
                if i != txin_index:
                    tmp_tx.inputs[i].sequence = EMPTY_TX_SEQUENCE

        elif (sighash & 0x1f) == SIGHASH_SINGLE:
            # only sign the output that corresponds to txin_index

            if txin_index >= len(tmp_tx.outputs):
                raise ValueError('Transaction index is greater than the \
                                 available outputs')

            # keep only output that corresponds to txin_index -- delete all outputs
            # after txin_index and zero out all outputs upto txin_index
            txout = tmp_tx.outputs[txin_index]
            tmp_tx.outputs = []
            for i in range(txin_index):
                tmp_tx.outputs.append( TxOutput(NEGATIVE_SATOSHI, Script([])) )
            tmp_tx.outputs.append(txout)

            # do not include sequence of other inputs (zero them for digest)
            # which means that they can be replaced
            for i in range(len(tmp_tx.inputs)):
                if i != txin_index:
                    tmp_tx.inputs[i].sequence = EMPTY_TX_SEQUENCE

        # bitwise AND'ing 0x8n to 0x80 will result to true
        if sighash & SIGHASH_ANYONECANPAY:
            # ignore all other inputs from the signature which means that
            # anyone can add new inputs
            tmp_tx.inputs = [tmp_tx.inputs[txin_index]]

        # get the byte stream of the temporary transaction
        tx_for_signing = tmp_tx.stream(False)

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


    def get_transaction_segwit_digest(self, txin_index, script, amount, sighash=SIGHASH_ALL):
        """Returns the segwit transaction's digest for signing.

                |  SIGHASH types (see constants.py):
                |      SIGHASH_ALL - signs all inputs and outputs (default)
                |      SIGHASH_NONE - signs all of the inputs
                |      SIGHASH_SINGLE - signs all inputs but only txin_index output
                |      SIGHASH_ANYONECANPAY (only combined with one of the above)
                |      - with ALL - signs all outputs but only txin_index input
                |      - with NONE - signs only the txin_index input
                |      - with SINGLE - signs txin_index input and output

                Attributes
                ----------
                txin_index : int
                    The index of the input that we wish to sign
                script : list (string)
                    The scriptPubKey of the UTXO that we want to spend
                amount : Decimal
                    The amount of the UTXO to spend is included in the
                    signature for segwit
                sighash : int
                    The type of the signature hash to be created
                """

        # clone transaction to modify without messing up the real transaction
        tmp_tx = Transaction.copy(self)

        # TODO consult ref. impl. in BIP-143 and update if needed
        # requires cleanup and further explanations
        hash_prevouts = b'\x00' * 32
        hash_sequence = b'\x00' * 32
        hash_outputs = b'\x00' * 32

        # Judging the signature type
        basic_sig_hash_type = (sighash & 0x1f)
        anyone_can_pay = sighash& 0xf0 == SIGHASH_ANYONECANPAY
        sign_all = (basic_sig_hash_type != SIGHASH_SINGLE) and (basic_sig_hash_type != SIGHASH_NONE)

        # Hash all input
        if not anyone_can_pay:
            hash_prevouts = b''
            for txin in tmp_tx.inputs:
                hash_prevouts += unhexlify(txin.txid)[::-1] + \
                                    struct.pack('<L', txin.txout_index)
            hash_prevouts = hashlib.sha256(hashlib.sha256(hash_prevouts).digest()).digest()

        # Hash all input sequence
        if not anyone_can_pay and sign_all:
            hash_sequence = b''
            for txin in tmp_tx.inputs:
                hash_sequence += txin.sequence
            hash_sequence = hashlib.sha256(hashlib.sha256(hash_sequence).digest()).digest()

        if sign_all:
            # Hash all output
            hash_outputs = b''
            for txout in tmp_tx.outputs:
                amount_bytes = struct.pack('<q', int(txout.amount *
                                                     SATOSHIS_PER_BITCOIN))
                script_bytes = txout.script_pubkey.to_bytes()
                hash_outputs += amount_bytes + struct.pack('B', len(script_bytes)) + script_bytes
            hash_outputs = hashlib.sha256(hashlib.sha256(hash_outputs).digest()).digest()
        elif basic_sig_hash_type == SIGHASH_SINGLE and txin_index < len(tmp_tx.outputs):
            # Hash one output
            txout = tmp_tx.outputs[txin_index]
            amount_bytes = struct.pack('<q', int(txout.amount *
                                                 SATOSHIS_PER_BITCOIN))
            script_bytes = txout.script_pubkey.to_bytes()
            hash_outputs = amount_bytes + struct.pack('B', len(script_bytes)) + script_bytes
            hash_outputs = hashlib.sha256(hashlib.sha256(hash_outputs).digest()).digest()

        # add sighash bytes to be hashed
        tx_for_signing = self.version

        # add sighash bytes to be hashed
        tx_for_signing += hash_prevouts + hash_sequence

        # add tx txin
        txin = self.inputs[txin_index]
        tx_for_signing += unhexlify(txin.txid)[::-1] + \
                          struct.pack('<L', txin.txout_index)

        # add tx sign
        tx_for_signing += struct.pack('B', len(script.to_bytes()))
        tx_for_signing += script.to_bytes()

        # add txin amount
        tx_for_signing += struct.pack('<q', int(amount * SATOSHIS_PER_BITCOIN))

        # add tx sequence
        tx_for_signing += txin.sequence

        # add txouts hash
        tx_for_signing += hash_outputs

        # add locktime
        tx_for_signing += self.locktime

        # add sighash type
        tx_for_signing += struct.pack('<i', sighash)

        return hashlib.sha256(hashlib.sha256(tx_for_signing).digest()).digest()


    def stream(self, has_segwit):
        """Converts to bytes"""

        data = self.version
        if has_segwit:
            # marker
            data += b'\x00'
            # flag
            data += b'\x01'

        txin_count_bytes = chr(len(self.inputs)).encode()
        txout_count_bytes = chr(len(self.outputs)).encode()
        data += txin_count_bytes
        for txin in self.inputs:
            data += txin.stream()
        data += txout_count_bytes
        for txout in self.outputs:
            data += txout.stream()
        if has_segwit:
            for witness in self.witnesses:
                # add witnesses script Count
                witnesses_count_bytes = chr(len(witness.script)).encode()
                data += witnesses_count_bytes
                data += witness.to_bytes(True)
        data += self.locktime
        return data


    def get_txid(self):
        """Hashes the serialized (bytes) tx to get a unique id"""

        data = self.stream(False)
        hash = hashlib.sha256( hashlib.sha256(data).digest() ).digest()
        # note that we reverse the hash for display purposes
        return hexlify(hash[::-1]).decode('utf-8')


    def get_wtxid(self):
        """Hashes the serialized (bytes) tx including segwit marker and witnesses"""

        return get_hash()


    def get_hash(self):
        """Hashes the serialized (bytes) tx including segwit marker and witnesses"""

        data = self.stream(self.has_segwit)
        hash = hashlib.sha256( hashlib.sha256(data).digest() ).digest()
        # note that we reverse the hash for display purposes
        return hexlify(hash[::-1]).decode('utf-8')


    def get_size(self):
        """Gets the size of the transaction"""

        return len(self.stream(self.has_segwit))


    def get_vsize(self):
        """Gets the virtual size of the transaction.

        For non-segwit txs this is identical to get_size(). For segwit txs the
        marker and witnesses length needs to be reduced to 1/4 of its original
        length. Thus it is substructed from size and then it is divided by 4
        before added back to size to produce vsize (always rounded up).

        https://en.bitcoin.it/wiki/Weight_units
        """
        # return size if non segwit
        if not self.has_segwit:
            return self.get_size()

        marker_size = 2

        wit_size = 0
        data = b''

        # count witnesses data
        for witness in self.witnesses:
            # add witnesses script Count
            witnesses_count_bytes = chr(len(witness.script)).encode()
            data = witnesses_count_bytes
            data += witness.to_bytes(True)
        wit_size = len(data)
        # TODO when TxInputWitness is created it will contain it's own len or
        # size method

        size = self.get_size() - (marker_size + wit_size)
        vsize = size + (marker_size + wit_size) / 4

        return int( math.ceil(vsize) )


    def serialize(self):
        """Converts to hex string"""

        return hexlify(self.stream(self.has_segwit)).decode('utf-8')


def main():
    pass

if __name__ == "__main__":
    main()


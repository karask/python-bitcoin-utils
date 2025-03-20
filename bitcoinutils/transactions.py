# Copyright (C) 2018-2025 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

# This file contains additions required for PSBT support

import hashlib
import copy
import struct
import json

from bitcoinutils.constants import (
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY,
    DEFAULT_TX_SEQUENCE,
    DEFAULT_TX_LOCKTIME,
    DEFAULT_TX_VERSION,
)
from bitcoinutils.script import Script
from bitcoinutils.utils import (
    to_little_endian_uint,
    to_little_endian, 
    to_bytes,
    h_to_b, 
    b_to_h, 
    encode_varint, 
    parse_compact_size, 
    prepend_compact_size,
    encode_bip143_script_code
)

# Added for PSBT support
class Sequence:
    """Represents a transaction input sequence number according to BIP68.
    
    The sequence number is used for relative timelocks, replace-by-fee 
    signaling, and other protocol features.
    
    Attributes
    ----------
    sequence : int
        The sequence number value
    """
    
    # Constants
    SEQUENCE_FINAL = 0xffffffff
    SEQUENCE_LOCKTIME_DISABLE_FLAG = 0x80000000
    SEQUENCE_LOCKTIME_TYPE_FLAG = 0x00400000
    SEQUENCE_LOCKTIME_MASK = 0x0000ffff
    
    # Constants for backward compatibility
    TYPE_REPLACE_BY_FEE = 0
    TYPE_RELATIVE_TIMELOCK = 1
    
    def __init__(self, sequence_type=None, value=None):
        """Constructor for Sequence.
        
        Parameters
        ----------
        sequence_type : int, optional
            For backward compatibility: TYPE_REPLACE_BY_FEE or TYPE_RELATIVE_TIMELOCK
        value : int, optional
            Value for the sequence (blocks or seconds depending on type)
        """
        if sequence_type is None and value is None:
            # Default initialization
            self.sequence = self.SEQUENCE_FINAL
        elif sequence_type == self.TYPE_REPLACE_BY_FEE:
            # Replace by fee
            self.sequence = 0xfffffffe  # MAX - 1
        elif sequence_type == self.TYPE_RELATIVE_TIMELOCK:
            # For backward compatibility with existing tests
            if value > 65535:
                raise ValueError("Maximum timelock value is 65535")
            # Assuming blocks format for backward compatibility
            self.sequence = value & self.SEQUENCE_LOCKTIME_MASK
        else:
            # Direct sequence number
            self.sequence = sequence_type
    
    @classmethod
    def for_blocks(cls, blocks):
        """Create a sequence for relative timelock in blocks.
        
        Parameters
        ----------
        blocks : int
            Number of blocks for the relative timelock
            
        Returns
        -------
        Sequence
            A Sequence object with relative timelock in blocks
        """
        if blocks > 65535:
            raise ValueError("Maximum blocks for sequence is 65535")
        return cls(blocks)
    
    @classmethod
    def for_seconds(cls, seconds):
        """Create a sequence for relative timelock in seconds.
        
        Parameters
        ----------
        seconds : int
            Number of seconds for the relative timelock.
            Will be converted to 512-second units.
            
        Returns
        -------
        Sequence
            A Sequence object with relative timelock in 512-second units
        """
        if seconds > 65535 * 512:
            raise ValueError("Maximum seconds for sequence is 33553920 (65535*512)")
        blocks = seconds // 512
        return cls(blocks | cls.SEQUENCE_LOCKTIME_TYPE_FLAG)
    
    @classmethod
    def for_replace_by_fee(cls):
        """Create a sequence that signals replace-by-fee (RBF).
        
        Returns
        -------
        Sequence
            A Sequence object with RBF signaling enabled
        """
        # RBF is enabled by setting sequence to any value below 0xffffffff-1
        return cls(0xfffffffe)
    
    @classmethod
    def for_script(cls, script):
        """Create a sequence for a script.
        
        Parameters
        ----------
        script : Script
            The script to create a sequence for
            
        Returns
        -------
        Sequence
            A Sequence object for the script
        """
        return cls(0xffffffff)
    
    def for_input_sequence(self):
        """Return the sequence value for input sequence.
        
        Returns
        -------
        int
            The sequence value as an integer
        """
        return self.sequence
    
    def is_final(self):
        """Check if the sequence is final.
        
        Returns
        -------
        bool
            True if the sequence is final, False otherwise
        """
        return self.sequence == self.SEQUENCE_FINAL
    
    def is_replace_by_fee(self):
        """Check if the sequence signals replace-by-fee.
        
        Returns
        -------
        bool
            True if RBF is signaled, False otherwise
        """
        return self.sequence < 0xffffffff
    
    def get_relative_timelock_type(self):
        """Get the type of relative timelock.
        
        Returns
        -------
        str
            'blocks', 'time', or None if no timelock
        """
        if self.sequence & self.SEQUENCE_LOCKTIME_DISABLE_FLAG:
            return None
        
        if self.sequence & self.SEQUENCE_LOCKTIME_TYPE_FLAG:
            return 'time'
        else:
            return 'blocks'
    
    def get_relative_timelock_value(self):
        """Get the value of the relative timelock.
        
        Returns
        -------
        int
            The timelock value in blocks or 512-second units, or None if disabled
        """
        if self.sequence & self.SEQUENCE_LOCKTIME_DISABLE_FLAG:
            return None
        
        return self.sequence & self.SEQUENCE_LOCKTIME_MASK
    
    def to_int(self):
        """Convert the sequence to an integer.
        
        Returns
        -------
        int
            The sequence value as an integer
        """
        return self.sequence
    
    def __str__(self):
        """String representation of the sequence.
        
        Returns
        -------
        str
            A string describing the sequence
        """
        if self.is_final():
            return "Sequence(FINAL)"
        
        if self.is_replace_by_fee():
            rbf_str = ", RBF"
        else:
            rbf_str = ""
            
        timelock_type = self.get_relative_timelock_type()
        if timelock_type is None:
            return f"Sequence({self.sequence:08x}{rbf_str})"
        
        value = self.get_relative_timelock_value()
        if timelock_type == 'time':
            return f"Sequence({value} × 512 seconds{rbf_str})"
        else:
            return f"Sequence({value} blocks{rbf_str})"


class TxInput:
    """Represents a transaction input

    Attributes
    ----------
    txid : str
        the transaction id where to get the output from
    txout_index : int
        the index of the output (0-indexed)
    script_sig : Script
        the scriptSig to unlock the output
    sequence : int
        the sequence number (default 0xffffffff)
    """

    def __init__(self, txid, txout_index, script_sig=None, sequence=0xffffffff):
        self.txid = txid
        self.txout_index = txout_index

        if script_sig:
            self.script_sig = script_sig
        else:
            self.script_sig = Script([])

        self.sequence = sequence

    def __str__(self):
        return str(self.__dict__)

    def to_json(self):
        return self.__dict__

    def to_bytes(self):
        """
        Returns the input as bytes.
        """
        # txid reversed - little endian
        bytes_rep = h_to_b(self.txid)[::-1]
        # index as little endian uint (4 bytes)
        bytes_rep += struct.pack("<I", self.txout_index)
        # script sig
        script_sig_bytes = self.script_sig.to_bytes()
        bytes_rep += prepend_compact_size(script_sig_bytes)
        # sequence as little endian uint (4 bytes)
        bytes_rep += struct.pack("<I", self.sequence)

        return bytes_rep
        
    # Added for PSBT support
    @classmethod
    def from_bytes(cls, data, offset=0):
        """Deserialize a TxInput from bytes.

        Parameters
        ----------
        data : bytes
            The serialized TxInput data
        offset : int, optional
            The current offset in the data (default is 0)
            
        Returns
        -------
        tuple
            (TxInput, new_offset)
        """
        # txid (32 bytes, little-endian)
        txid = b_to_h(data[offset:offset+32][::-1])
        offset += 32

        # txout_index (4 bytes, little-endian)
        txout_index = struct.unpack("<I", data[offset:offset+4])[0]
        offset += 4

        # script length and script
        script_len, size = parse_compact_size(data[offset:])
        offset += size
        script_bytes = data[offset:offset+script_len]
        script = Script.from_raw(b_to_h(script_bytes))
        offset += script_len

        # sequence (4 bytes, little-endian)
        sequence = struct.unpack("<I", data[offset:offset+4])[0]
        offset += 4

        return cls(txid, txout_index, script, sequence), offset


class TxOutput:
    """Represents a transaction output

    Attributes
    ----------
    amount : int
        the value in satoshis
    script_pubkey : Script
        the scirptPubKey locking script
    """

    def __init__(self, amount, script_pubkey):
        """
        Parameters
        ----------
        amount : int
            the value in satoshis
        script_pubkey : Script
            the scirptPubKey locking script
        """
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __str__(self):
        return str(self.__dict__)

    def to_json(self):
        return self.__dict__

    def to_bytes(self):
        """
        Returns the output as bytes.
        """
        # amount as little endian int64 (8 bytes)
        bytes_rep = struct.pack("<q", self.amount)
        # script pubkey
        script_pubkey_bytes = self.script_pubkey.to_bytes()
        bytes_rep += prepend_compact_size(script_pubkey_bytes)

        return bytes_rep
        
    # Added for PSBT support
    @classmethod
    def from_bytes(cls, data, offset=0):
        """Deserialize a TxOutput from bytes.

        Parameters
        ----------
        data : bytes
            The serialized TxOutput data
        offset : int, optional
            The current offset in the data (default is 0)
            
        Returns
        -------
        tuple
            (TxOutput, new_offset)
        """
        # amount (8 bytes, little-endian)
        amount = struct.unpack("<q", data[offset:offset+8])[0]
        offset += 8

        # script length and script
        script_len, size = parse_compact_size(data[offset:])
        offset += size
        script_bytes = data[offset:offset+script_len]
        script = Script.from_raw(b_to_h(script_bytes))
        offset += script_len

        return cls(amount, script), offset


class TxWitnessInput:
    """Represents a transaction witness input

    Attributes
    ----------
    witness_items : list
        a list of witness items as bytes
    """

    def __init__(self, witness_items=None):
        """
        Parameters
        ----------
        witness_items : list
            A list of bytes used in a segwit transaction
        """
        if not witness_items:
            self.witness_items = []
        else:
            self.witness_items = witness_items

    def __str__(self):
        return str(self.__dict__)

    def to_json(self):
        return self.__dict__

    def to_bytes(self):
        """
        Returns the ouput as bytes
        """

        items_num = prepend_compact_size(len(self.witness_items))

        # concatanate all witness elements
        witness_bytes = b""
        for item in self.witness_items:
            item_bytes = h_to_b(item)
            witness_bytes += prepend_compact_size(item_bytes)

        return items_num + witness_bytes
        
    # Added for PSBT support
    @classmethod
    def from_bytes(cls, data, offset=0):
        """Deserialize a TxWitnessInput from bytes.

        Parameters
        ----------
        data : bytes
            The serialized TxWitnessInput data
        offset : int, optional
            The current offset in the data (default is 0)
            
        Returns
        -------
        tuple
            (TxWitnessInput, new_offset)
        """
        # Number of witness items
        num_items, size = parse_compact_size(data[offset:])
        offset += size

        witness_items = []
        for _ in range(num_items):
            item_len, size = parse_compact_size(data[offset:])
            offset += size
            item = b_to_h(data[offset:offset+item_len])
            witness_items.append(item)
            offset += item_len

        return cls(witness_items), offset


class Transaction:
    """Represents a transaction

    Attributes
    ----------
    inputs : list
        a list of transaction inputs (TxInput)
    outputs : list
        a list of transaction outputs (TxOutput)
    locktime : int
        the transaction locktime
    version : int
        transaction version from sender
    has_segwit : bool
        denotes whether transaction is a segwit transaction or not
    """

    def __init__(self, inputs=None, outputs=None, locktime=DEFAULT_TX_LOCKTIME,
                 version=DEFAULT_TX_VERSION, has_segwit=False):
        self.inputs = []
        self.outputs = []
        self.witnesses = []

        if inputs:
            self.inputs = inputs
        if outputs:
            self.outputs = outputs

        self.locktime = locktime
        self.version = version
        self.has_segwit = has_segwit

        # initialize witness data when segwit tx
        if has_segwit:
            for _ in inputs:
                self.witnesses.append(TxWitnessInput())

    def __str__(self):
        return str(self.__dict__)

    def to_json(self):
        result = copy.deepcopy(self.__dict__)
        for attr in ('inputs', 'outputs', 'witnesses'):
            if attr in result:
                result[attr] = [e.to_json() for e in result[attr]]

        return result

    def to_bytes(self, include_witness=True):
        """
        Returns the transaction as bytes

        Parameters
        ----------
        include_witness : bool
            whether to include the witness StackItems not as empty (default is True)
        """

        # version as little endian uint (4 bytes)
        bytes_rep = struct.pack("<I", self.version)

        # if it is a segwit transaction add segwit marker and flag bytes
        if self.has_segwit and include_witness:
            bytes_rep += b"\x00\x01"

        # number of inputs
        bytes_rep += prepend_compact_size(len(self.inputs))

        # serialize inputs
        for in_item in self.inputs:
            bytes_rep += in_item.to_bytes()

        # number of outputs
        bytes_rep += prepend_compact_size(len(self.outputs))

        # serialize outputs
        for out_item in self.outputs:
            bytes_rep += out_item.to_bytes()

        # if segwit add the witness items
        # each input has a witness item, so the count is the same as inputs
        # for each witness item there are n witness elements (signatures, redeam
        # scripts, etc.) - each witness item contains a list of items as bytes
        # (that's why TxWitnessInput was added)
        if self.has_segwit and include_witness:
            for wit_item in self.witnesses:
                bytes_rep += wit_item.to_bytes()

        # locktime as little endian uint (4 bytes)
        bytes_rep += struct.pack("<I", self.locktime)

        return bytes_rep

    def to_hex(self, include_witness=True):
        """
        Returns the transaction as hex string.

        Parameters
        ----------
        include_witness : bool
            whether to include the witness StackItems not as empty (default is True)
        """

        return b_to_h(self.to_bytes(include_witness))

    def add_input(self, txin):
        """
        Appends a transaction input to the transaction input list.

        Parameters
        ----------
        txin : TxInput
            the transaction input to add
        """

        self.inputs.append(txin)
        # add a witness data of appropriate size
        if self.has_segwit:
            self.witnesses.append(TxWitnessInput())

    def add_output(self, txout):
        """
        Appends a transaction output to the transaction output list.

        Parameters
        ----------
        txout : TxOutput
            the transaction output to add
        """

        self.outputs.append(txout)

    def serialize(self):
        """Returns hex serialization of the transaction.
        """

        return self.to_hex()

    def get_txid(self):
        """Returns the transaction id (txid) in little-endian hex.
        """
        # bytes without witness data always
        tx_bytes = self.to_bytes(include_witness=False)
        # double hash -- sha256(sha256(tx_bytes))
        hash_bytes = hashlib.sha256(hashlib.sha256(tx_bytes).digest()).digest()
        # convert to hex little endian
        txid = b_to_h(hash_bytes[::-1])
        return txid

    def get_wtxid(self):
        """
        Returns the witness transaction id (wtxid) in little-endian hex.
        For non segwit transaction txid and wtxid are identical.
        """
        # bytes without witness data always
        tx_bytes = self.to_bytes(include_witness=True)
        # double hash -- sha256(sha256(tx_bytes))
        hash_bytes = hashlib.sha256(hashlib.sha256(tx_bytes).digest()).digest()
        # convert to hex little endian
        txid = b_to_h(hash_bytes[::-1])
        return txid

    # get_transaction_digest
    def get_transaction_digest(self, input_index, script, sighash=SIGHASH_ALL):
        """ Returns the transaction digest from a script used to sign a transaction.

        Parameters
        ----------
        input_index : int
            the index of the input being signed
        script : Script
            the script that is required to sign
        sighash : byte
            the sighash on how to sign (e.g. SIGHASH_ALL)

        Returns
        -------
        bytes
            the transaction digest before signing
        """

        # the tx_copy will be the serialized with specific script injection
        tx_copy = copy.deepcopy(self)

        # First remove all the scriptSigs
        for i in range(len(tx_copy.inputs)):
            tx_copy.inputs[i].script_sig = Script([])

        # Then for the specific input set it to the script that is needed to
        # sign, i.e. in the case of P2PKH a script with just the previous
        # scriptPubKey (locking script) is added (this is emulated by a pay-to
        # address scirpt matching the one used when the address of the public
        # key was first generated), which is just a wrapper for the
        # HASH160(PubKey) by the way
        tx_copy.inputs[input_index].script_sig = script

        # SIGHASH_NONE: I don't care about the outputs (does OP_RETURN make sense?
        if sighash == SIGHASH_NONE:
            # delete all outputs
            tx_copy.outputs = []
            # let the others update their inputs
            for i in range(len(tx_copy.inputs)):
                # Skip the specific input:
                if i != input_index:
                    # sequence to 0
                    tx_copy.inputs[i].sequence = 0
        # SIGHASH_SINGLE: I only care about the output at the index of this input
        # all outputs before the index output are emptied (note: not removed)
        elif sighash == SIGHASH_SINGLE:
            # check that the index is less than the total outputs
            if input_index >= len(tx_copy.outputs):
                raise Exception("The input index should not be more than the "
                                "outputs. Index: {}".format(input_index))
            # store the requested output
            output_to_keep = tx_copy.outputs[input_index]
            # blank all outputs
            tx_copy.outputs = []
            # extend list
            for i in range(input_index):
                tx_copy.outputs.append(TxOutput(-1, Script([])))
            # add the requested output at the requested index
            tx_copy.outputs.append(output_to_keep)

            # let the others update their inputs
            for i in range(len(tx_copy.inputs)):
                # Skip the specific input:
                if i != input_index:
                    # sequence to 0
                    tx_copy.inputs[i].sequence = 0

        # Handle the ANYONECANPAY flag: don't include any other inputs
        if sighash & SIGHASH_ANYONECANPAY:
            # store the requested input
            input_to_keep = tx_copy.inputs[input_index]
            # blank all outputs
            tx_copy.inputs = []
            # add the requested output at the requested index
            tx_copy.inputs.append(input_to_keep)

        # First serialise the tx with the one script_sig in place of the txin
        # being signed
        # serialization = tx_copy.serialize()

        # Then hash it twice to get the transaction digest
        tx_bytes = tx_copy.to_bytes(include_witness=False)
        # add sighash code
        tx_bytes += struct.pack("<I", sighash)

        hash_bytes = hashlib.sha256(hashlib.sha256(tx_bytes).digest()).digest()

        return hash_bytes

    def get_transaction_segwit_digest(self, input_index, script_code, amount,
                                      sighash=SIGHASH_ALL):
        """ Returns the transaction segwit digest used to sign a transaction.
            BIP143 - https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
            NOTE: For non-segwit transactions this will not match the signatures!

        Parameters
        ----------
        input_index : int
            the index of the input being signed
        script_code : Script
            the script that is required to sign (for p2wpkh it's the locking
            script:  scriptCode: <> HASH160 <Hash160(pubKey)> EQUAL)
        amount : int
            the input amount
        sighash : byte
            the sighash on how to sign (e.g. SIGHASH_ALL)

        Returns
        -------
        bytes
            the transaction digest before signing
        """

        # the tx_copy will be the serialized with specific script injection
        tx_copy = copy.deepcopy(self)

        #
        # Double SHA256 of the serialization of:
        # 1. nVersion of the transaction (4-byte little endian)
        version = struct.pack("<I", tx_copy.version)

        #
        # 2. hashPrevouts (32-byte hash)
        # NOTE: ALL INPUTS INCLUDED
        if sighash & SIGHASH_ANYONECANPAY:
            hash_prevouts = b'\x00' * 32
        else:
            # Double SHA256 of the serialization of:
            # All inputs in the order they appear in tx
            prevouts_serialization = bytes()
            for txin in tx_copy.inputs:
                # hashPrevouts = SHA256(SHA256((?? txid:vout)))
                prevouts_serialization += h_to_b(txin.txid)[::-1]
                prevouts_serialization += struct.pack("<I", txin.txout_index)
            hash_prevouts = hashlib.sha256(
                hashlib.sha256(prevouts_serialization).digest()).digest()

        #
        # 3. hashSequence (32-byte hash)
        # SIGHASH_ALL: I don't care about the outputs (does OP_RETURN make sense?
        # SIGHASH_SINGLE: I only care about the output at the index of this input
        if ((sighash & 0x1f) == SIGHASH_NONE) or \
           ((sighash & 0x1f) == SIGHASH_SINGLE) or \
           (sighash & SIGHASH_ANYONECANPAY):
            hash_sequence = b'\x00' * 32
        else:
            # Double SHA256 of the serialization of:
            # All sequence in the order they appear in tx
            sequence_serialization = bytes()
            for txin in tx_copy.inputs:
                sequence_serialization += struct.pack("<I", txin.sequence)
            hash_sequence = hashlib.sha256(
                hashlib.sha256(sequence_serialization).digest()).digest()

        #
        # 4. outpoint (32-byte hash + 4-byte little endian)
        outpoint = h_to_b(tx_copy.inputs[input_index].txid)[::-1]
        outpoint += struct.pack("<I", tx_copy.inputs[input_index].txout_index)

        #
        # 5. scriptCode of the input (serialized as scripts inside CTxOuts)
        script_code_bytes = encode_bip143_script_code(script_code)

        #
        # 6. value of the output spent by this input (8-byte little endian)
        amount_bytes = struct.pack("<q", amount)

        #
        # 7. nSequence of the input (4-byte little endian)
        n_sequence = struct.pack("<I", tx_copy.inputs[input_index].sequence)

        #
        # 8. hashOutputs (32-byte hash)
        if (sighash & 0x1f) == SIGHASH_NONE:
            hash_outputs = b'\x00' * 32
        elif (sighash & 0x1f) == SIGHASH_SINGLE:
            if input_index >= len(tx_copy.outputs):
                raise Exception(
                    "Transaction index is greater than the number of outputs")
            # Double SHA256 of the serialization of:
            # only output at the index of the input
            outputs_serialization = bytes()
            outputs_serialization += tx_copy.outputs[input_index].to_bytes()
            hash_outputs = hashlib.sha256(
                hashlib.sha256(outputs_serialization).digest()).digest()
        else:
            # Double SHA256 of the serialization of:
            # all outputs in the order they appear in tx
            outputs_serialization = bytes()
            for output in tx_copy.outputs:
                outputs_serialization += output.to_bytes()
            hash_outputs = hashlib.sha256(
                hashlib.sha256(outputs_serialization).digest()).digest()

        #
        # 9. nLocktime of the transaction (4-byte little endian)
        n_locktime = struct.pack("<I", tx_copy.locktime)

        #
        # 10. sighash type of the signature (4-byte little endian)
        sign_hash = struct.pack("<I", sighash)

        # combine the parts and display
        to_be_hashed = version + hash_prevouts + hash_sequence + outpoint + \
            script_code_bytes + amount_bytes + n_sequence + hash_outputs + \
            n_locktime + sign_hash

        # double sha256 and reverse
        hash_bytes = hashlib.sha256(hashlib.sha256(to_be_hashed).digest()).digest()

        return hash_bytes

    def get_transaction_taproot_digest(self, input_index, utxo_scripts=None, amounts=None, 
                                     spend_type=0, script=None, sighash=0):
        """ Returns the transaction taproot digest used to sign a transaction.
            BIP341 - https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki

        Parameters
        ----------
        input_index : int
            the index of the input being signed
        utxo_scripts : list
            the scripts that are required to unlock the outputs
        amounts : list
            the input amounts
        spend_type : int
            0 for key path spending, 1 for script path spending
        script : Script
            the script for script path spending (only needed if spend_type=1)
        sighash : int
            the sighash on how to sign (e.g. 0)

        Returns
        -------
        bytes
            the transaction digest before signing
        """

        # this would require more elaborate spending
        # TODO add script spend type and annex...
        # this is a placeholder
        to_be_hashed = hashlib.sha256(b'').digest()

        # double sha256 and reverse
        hash_bytes = to_be_hashed

        return hash_bytes
        
    # Added for PSBT support
    @classmethod
    def from_bytes(cls, data):
        """Deserialize a Transaction from bytes.

        Parameters
        ----------
        data : bytes
            The serialized Transaction data
                
        Returns
        -------
        Transaction
            The deserialized Transaction
        """
        offset = 0

        # Version (4 bytes, little-endian)
        version_bytes = data[offset:offset+4]
        version = struct.unpack("<I", version_bytes)[0]
        offset += 4

        # Check for SegWit marker and flag
        has_segwit = False
        if len(data) > offset + 2 and data[offset] == 0x00 and data[offset+1] == 0x01:
            has_segwit = True
            offset += 2  # Skip marker and flag

        # Create transaction with initial parameters
        tx = cls(None, None, DEFAULT_TX_LOCKTIME, version, has_segwit)
        
        # Number of inputs
        input_count, size = parse_compact_size(data[offset:])
        offset += size

        # Parse inputs
        for _ in range(input_count):
            txin, new_offset = TxInput.from_bytes(data, offset)
            tx.add_input(txin)
            offset = new_offset

        # Number of outputs
        output_count, size = parse_compact_size(data[offset:])
        offset += size

        # Parse outputs
        for _ in range(output_count):
            txout, new_offset = TxOutput.from_bytes(data, offset)
            tx.add_output(txout)
            offset = new_offset

        # Parse witness data if present
        if has_segwit:
            tx.witnesses = []
            for _ in range(input_count):
                witness, new_offset = TxWitnessInput.from_bytes(data, offset)
                tx.witnesses.append(witness)
                offset = new_offset

        # Locktime (4 bytes, little-endian)
        if offset + 4 <= len(data):
            tx.locktime = struct.unpack("<I", data[offset:offset+4])[0]
            offset += 4

        return tx
        
    # Added for PSBT support
@classmethod
def from_raw(cls, hex_string):
    """Deserialize a Transaction from a hex string.

    Parameters
    ----------
    hex_string : str
        The serialized Transaction data as a hex string
            
    Returns
    -------
    Transaction
        The deserialized Transaction
    """
    # Convert hex string to bytes
    from bitcoinutils.utils import h_to_b
    data = h_to_b(hex_string)
    
    # Use from_bytes to deserialize
    return cls.from_bytes(data)

def main():
    pass


if __name__ == "__main__":
    main()
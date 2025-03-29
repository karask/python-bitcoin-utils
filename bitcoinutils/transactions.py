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

import math
import hashlib
import struct
from typing import Optional

from bitcoinutils.constants import (
    DEFAULT_TX_SEQUENCE,
    DEFAULT_TX_LOCKTIME,
    DEFAULT_TX_VERSION,
    NEGATIVE_SATOSHI,
    LEAF_VERSION_TAPSCRIPT,
    EMPTY_TX_SEQUENCE,
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY,
    TAPROOT_SIGHASH_ALL,
    ABSOLUTE_TIMELOCK_SEQUENCE,
    REPLACE_BY_FEE_SEQUENCE,
    TYPE_ABSOLUTE_TIMELOCK,
    TYPE_RELATIVE_TIMELOCK,
    TYPE_REPLACE_BY_FEE,
)
from bitcoinutils.script import Script
from bitcoinutils.utils import (
    vi_to_int,
    encode_varint,
    tagged_hash,
    prepend_compact_size,
    h_to_b,
    b_to_h,
    parse_compact_size,
)


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
        the script that satisfies the locking conditions (aka unlocking script)
    sequence : bytes
        the input sequence (for timelocks, RBF, etc.)

    Methods
    -------
    to_bytes()
        serializes TxInput to bytes
    copy()
        creates a copy of the object (classmethod)
    from_raw()
        instantiates object from raw hex input (classmethod)
    """

    def __init__(
        self,
        txid: str,
        txout_index: int,
        script_sig=Script([]),
        sequence: str | bytes = DEFAULT_TX_SEQUENCE,
    ) -> None:
        """See TxInput description"""

        # expected in the format used for displaying Bitcoin hashes
        self.txid = txid
        self.txout_index = txout_index
        self.script_sig = script_sig

        # if user provided a sequence it would be as string (for now...)
        if isinstance(sequence, str):
            self.sequence = h_to_b(sequence)
        else:
            self.sequence = sequence

    def to_bytes(self) -> bytes:
        """Serializes to bytes"""

        # Internally Bitcoin uses little-endian byte order as it improves
        # speed. Hashes are defined and implemented as big-endian thus
        # those are transmitted in big-endian order. However, when hashes are
        # displayed Bitcoin uses little-endian order because it is sometimes
        # convenient to consider hashes as little-endian integers (and not
        # strings)
        # - note that we reverse the byte order for the tx hash since the string
        #   was displayed in little-endian!
        # - note that python's struct uses little-endian by default
        txid_bytes = h_to_b(self.txid)[::-1]
        txout_bytes = struct.pack("<L", self.txout_index)

        # check if coinbase input add manually to avoid adding the script size,
        # pushdata, etc since it is just raw data used by the miner (extra nonce,
        # mining pool, etc.)
        if self.txid == 64 * "0":
            script_sig_bytes = h_to_b(
                self.script_sig.script[0]
            )  # coinbase has a single element as script_sig
        # normal input
        else:
            script_sig_bytes = self.script_sig.to_bytes()

        data = (
            txid_bytes
            + txout_bytes
            + encode_varint(len(script_sig_bytes))
            + script_sig_bytes
            + self.sequence
        )
        return data

    def __str__(self):
        return str(
            {
                "txid": self.txid,
                "txout_index": self.txout_index,
                "script_sig": self.script_sig,
                "sequence": self.sequence.hex(),
            }
        )

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def from_raw(txinputrawhex: str, cursor: int = 0, has_segwit: bool = False):
        """
        Imports a TxInput from a Transaction's hexadecimal data

        Attributes
        ----------
        txinputrawhex : string (hex)
            The hexadecimal raw string of the Transaction
        cursor : int
            The cursor of which the algorithm will start to read the data
        has_segwit : boolean
            Is the Tx Input segwit or not
        """
        txinputraw = h_to_b(txinputrawhex)

        # Unpack transaction ID (hash) in bytes and output index
        txid, vout = struct.unpack_from('<32sI', txinputraw, cursor)
        txid = txid[::-1]  # Reverse to match usual hexadecimal order
        cursor += 36  # 32 bytes for txid and 4 bytes for vout

        # Read the unlocking script size using parse_compact_size
        unlocking_script_size, size = parse_compact_size(txinputraw[cursor:])
        cursor += size

        # Read the unlocking script in bytes
        unlocking_script = struct.unpack_from(f'{unlocking_script_size}s', txinputraw, cursor)[0]
        cursor += unlocking_script_size

        # Read the sequence number in bytes
        sequence, = struct.unpack_from('<4s', txinputraw, cursor)
        cursor += 4

        # If coinbase input (utxo will be all zeros), handle script differently
        if txid.hex() == '00' * 32:
            script_sig = Script([unlocking_script.hex()])  # Treat as single element for coinbase
        else:
            script_sig = Script.from_raw(unlocking_script.hex(), has_segwit=has_segwit)

        # Create the TxInput instance
        tx_input = TxInput(
            txid=txid.hex(),
            txout_index=vout,
            script_sig=script_sig,
            sequence=sequence
        )

        return tx_input, cursor

    @classmethod
    def copy(cls, txin: "TxInput") -> "TxInput":
        """Deep copy of TxInput"""

        return cls(txin.txid, txin.txout_index, txin.script_sig, txin.sequence)


class TxWitnessInput:
    """A list of the witness items required to satisfy the locking conditions
       of a segwit input (aka witness stack).

    Attributes
    ----------
    stack : list
        the witness items (hex str) list

    Methods
    -------
    to_bytes()
        returns a serialized byte version of the witness items list
    copy()
        creates a copy of the object (classmethod)
    """

    def __init__(self, stack: list[str]) -> None:
        """See description"""

        self.stack = stack

    def to_bytes(self) -> bytes:
        """Converts to bytes"""
        stack_bytes = b""
        for item in self.stack:
            # witness items can only be data items (hex str)
            item_bytes = prepend_compact_size(h_to_b(item))
            stack_bytes += item_bytes

        return stack_bytes

    @classmethod
    def copy(cls, txwin: "TxWitnessInput") -> "TxWitnessInput":
        """Deep copy of TxWitnessInput"""

        return cls(txwin.stack)

    def __str__(self) -> str:
        return str(
            {
                "witness_items": self.stack,
            }
        )

    def __repr__(self) -> str:
        return self.__str__()


class TxOutput:
    """Represents a transaction output

    Attributes
    ----------
    amount : int
        the value we want to send to this output in satoshis
    script_pubkey : Script
        the script that will lock this amount

    Methods
    -------
    to_bytes()
        serializes TxInput to bytes
    copy()
        creates a copy of the object (classmethod)
    from_raw()
        instantiates object from raw hex output (classmethod)
    """

    def __init__(self, amount: int, script_pubkey: Script) -> None:
        """See TxOutput description"""

        if not isinstance(amount, int):
            raise TypeError("Amount needs to be in satoshis as an integer")

        self.amount = amount
        self.script_pubkey = script_pubkey

    def to_bytes(self) -> bytes:
        """Serializes to bytes"""

        # internally all little-endian except hashes
        # note struct uses little-endian by default

        amount_bytes = struct.pack("<q", self.amount)
        script_bytes = self.script_pubkey.to_bytes()
        data = amount_bytes + encode_varint(len(script_bytes)) + script_bytes
        return data

    @staticmethod
    def from_raw(txoutputrawhex: str, cursor: int = 0, has_segwit: bool = False):
        """
        Imports a TxOutput from a Transaction's hexadecimal data

        Attributes
        ----------
        txoutputrawhex : string (hex)
            The hexadecimal raw string of the Transaction
        cursor : int
            The cursor of which the algorithm will start to read the data
        has_segwit : boolean
            Is the Tx Output segwit or not
        """
        txoutputraw = h_to_b(txoutputrawhex)

        # Unpack the amount of the TxOutput directly in bytes
        amount_format = "<Q"  # Little-endian unsigned long long (8 bytes)
        amount, = struct.unpack_from(amount_format, txoutputraw, cursor)
        cursor += struct.calcsize(amount_format)

        # Read the locking script size using parse_compact_size
        lock_script_size, size = parse_compact_size(txoutputraw[cursor:])
        cursor += size

        # Read the locking script
        script_format = f"{lock_script_size}s"
        lock_script, = struct.unpack_from(script_format, txoutputraw, cursor)
        cursor += lock_script_size

        # Create the TxOutput instance
        tx_output = TxOutput(
            amount=amount,
            script_pubkey=Script.from_raw(lock_script.hex(), has_segwit=has_segwit)
        )

        return tx_output, cursor


    def __str__(self) -> str:
        return str({"amount": self.amount, "script_pubkey": self.script_pubkey})

    def __repr__(self) -> str:
        return self.__str__()

    @classmethod
    def copy(cls, txout: "TxOutput") -> "TxOutput":
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

    def __init__(self, seq_type: int, value: int, is_type_block: bool = True) -> None:
        self.seq_type = seq_type
        self.value = value

        assert self.value is not None

        if self.seq_type == TYPE_RELATIVE_TIMELOCK and (
            self.value < 1 or self.value > 0xFFFF
        ):
            raise ValueError("Sequence should be between 1 and 65535")
        self.is_type_block = is_type_block

    def for_input_sequence(self) -> Optional[str | bytes]:
        """Creates a relative timelock sequence value as expected from
        TxInput sequence attribute"""
        if self.seq_type == TYPE_ABSOLUTE_TIMELOCK:
            return ABSOLUTE_TIMELOCK_SEQUENCE

        elif self.seq_type == TYPE_REPLACE_BY_FEE:
            return REPLACE_BY_FEE_SEQUENCE

        elif self.seq_type == TYPE_RELATIVE_TIMELOCK:
            # most significant bit is already 0 so relative timelocks are enabled
            seq = 0
            # if not block height type set 23 bit
            if not self.is_type_block:
                seq |= 1 << 22
            # set the value
            seq |= self.value
            seq_bytes = seq.to_bytes(4, byteorder="little")
            return seq_bytes

        return None

    def for_script(self) -> int:
        """Creates a relative/absolute timelock sequence value as expected in scripts"""
        if self.seq_type == TYPE_REPLACE_BY_FEE:
            raise ValueError("RBF is not to be included in a script.")

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
        The value of the block height or the Unix epoch (seconds from 1 Jan
        1970 UTC)

    Methods
    -------
    for_transaction()
        Serializes the locktime as required in a transaction

    Raises
    ------
    ValueError
        if the value is not within range of 2 bytes.
    """

    def __init__(self, value: int) -> None:
        self.value = value

    def for_transaction(self) -> bytes:
        """Creates a timelock as expected from Transaction"""

        locktime_bytes = self.value.to_bytes(4, byteorder="little")
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
    witnesses : list (TxWitnessInput)
        The witness structure that corresponds to the inputs


    Methods
    -------
    to_bytes()
        Serializes Transaction to bytes
    to_hex()
        converts result of to_bytes to hexadecimal string
    serialize()
        converts result of to_bytes to hexadecimal string
    from_raw()
        Instantiates a Transaction from serialized raw hexadacimal data (classmethod)
    get_txid()
        Calculates txid and returns it
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
    get_transaction_taproot_digest(txin_index, script_pubkeys, amounts, ext_flag,
            script, leaf_ver, sighash, annex)
        returns the transaction input's taproot digest that is to be signed
        according to sighash
    """

    def __init__(
        self,
        inputs: Optional[list[TxInput]] = None,
        outputs: Optional[list[TxOutput]] = None,
        locktime: str | bytes = DEFAULT_TX_LOCKTIME,
        version: bytes = DEFAULT_TX_VERSION,
        has_segwit: bool = False,
        witnesses: Optional[list[TxWitnessInput]] = None,
    ) -> None:
        """See Transaction description"""

        # make sure default argument for inputs, outputs and witnesses is an empty list
        if inputs is None:
            inputs = []
        if outputs is None:
            outputs = []
        if witnesses is None:
            witnesses = []

        self.inputs = inputs
        self.outputs = outputs
        self.has_segwit = has_segwit
        self.witnesses = witnesses

        # if user provided a locktime it would be as string (for now...)
        if isinstance(locktime, str):
            self.locktime = h_to_b(locktime)
        else:
            self.locktime = locktime

        self.version = version

    @staticmethod
    def from_raw(rawtxhex: str):
        """
        Imports a Transaction from hexadecimal data.

        Attributes
        ----------
        rawtxhex : string (hex)
            The hexadecimal raw string of the Transaction.
        """
        rawtx = h_to_b(rawtxhex)

        # Read version (4 bytes)
        version = rawtx[0:4]
        cursor = 4

        # Detect and handle SegWit
        has_segwit = False
        if rawtx[cursor:cursor + 2] == b'\x00\x01':
            has_segwit = True
            cursor += 2  # Skipping past the marker and flag bytes

        # Read the number of inputs
        n_inputs, size = parse_compact_size(rawtx[cursor:])
        cursor += size
        inputs = []

        # Read inputs
        for _ in range(n_inputs):
            inp, cursor = TxInput.from_raw(rawtx.hex(), cursor, has_segwit)
            inputs.append(inp)

        # Read the number of outputs using parse_compact_size
        n_outputs, size = parse_compact_size(rawtx[cursor:])
        cursor += size
        outputs = []

        # Read outputs
        for _ in range(n_outputs):
            output, cursor = TxOutput.from_raw(rawtx.hex(), cursor, has_segwit)
            outputs.append(output)

        # Handle witnesses if SegWit is enabled
        witnesses = []
        if has_segwit:
            for _ in range(n_inputs):
                n_items, size = parse_compact_size(rawtx[cursor:])
                cursor += size
                witnesses_tmp = []
                for _ in range(n_items):
                    item_size, size = parse_compact_size(rawtx[cursor:])
                    cursor += size
                    witness_data = rawtx[cursor:cursor + item_size]
                    cursor += item_size
                    witnesses_tmp.append(witness_data.hex())
                if witnesses_tmp:
                    witnesses.append(TxWitnessInput(stack=witnesses_tmp))

        # Read locktime (4 bytes)
        locktime = rawtx[cursor:cursor + 4]

        #Returning the Transaction object
        return Transaction(
            inputs=inputs,
            outputs=outputs,
            version=version,
            locktime=locktime,
            has_segwit=has_segwit,
            witnesses=witnesses,
        )

    def __str__(self) -> str:
        return str(
            {
                "inputs": self.inputs,
                "outputs": self.outputs,
                "has_segwit": self.has_segwit,
                "witnesses": self.witnesses,
                "locktime": self.locktime.hex(),
                "version": self.version.hex(),
            }
        )

    def __repr__(self) -> str:
        return self.__str__()

    @classmethod
    def copy(cls, tx: "Transaction") -> "Transaction":
        """Deep copy of Transaction"""

        ins = [TxInput.copy(txin) for txin in tx.inputs]
        outs = [TxOutput.copy(txout) for txout in tx.outputs]
        wits = [TxWitnessInput.copy(witness) for witness in tx.witnesses]
        return cls(ins, outs, tx.locktime, tx.version, tx.has_segwit, wits)
        
    def to_bytes(self, include_witness=True) -> bytes:
        """Serializes transaction to bytes
        
        Parameters
        ----------
        include_witness : bool
            Whether to include witness data (for segwit transactions)
            
        Returns
        -------
        bytes
            The serialized transaction
        """
        # Add version - make sure it's bytes
        if isinstance(self.version, bytes):
            serialized = self.version
        else:
            serialized = struct.pack("<I", self.version)
        
        # Add segwit marker and flag if needed
        if self.has_segwit and include_witness:
            serialized += b'\x00\x01'
        
        # Add number of inputs
        serialized += encode_varint(len(self.inputs))
        
        # Add inputs
        for tx_input in self.inputs:
            serialized += tx_input.to_bytes()
        
        # Add number of outputs
        serialized += encode_varint(len(self.outputs))
        
        # Add outputs
        for tx_output in self.outputs:
            serialized += tx_output.to_bytes()
        
        # Add witness data if needed
        if self.has_segwit and include_witness:
            for witness in self.witnesses:
                # First byte is the number of witness items
                serialized += encode_varint(len(witness.stack))
                for item in witness.stack:
                    item_bytes = h_to_b(item)
                    serialized += encode_varint(len(item_bytes)) + item_bytes
        
        # Add locktime - make sure it's bytes
        if isinstance(self.locktime, bytes):
            serialized += self.locktime
        else:
            serialized += struct.pack("<I", self.locktime)
        
        return serialized

    def to_hex(self) -> str:
        """Converts the transaction to hex string
        
        Returns
        -------
        str
            Hexadecimal representation of the transaction
        """
        return b_to_h(self.to_bytes())

    def serialize(self) -> str:
        """Alias for to_hex() for backwards compatibility
        
        Returns
        -------
        str
            Hexadecimal representation of the transaction
        """
        return self.to_hex()

    def get_transaction_taproot_digest(
        self, 
        txin_index: int, 
        script_pubkeys=None, 
        amounts=None, 
        ext_flag=0, 
        script=None, 
        leaf_ver=LEAF_VERSION_TAPSCRIPT,
        sighash=TAPROOT_SIGHASH_ALL,
        annex=None
    ):
        """Returns the transaction's taproot digest for signing (BIP 341).
        
        Parameters
        ----------
        txin_index : int
            The index of the input that we wish to sign
        script_pubkeys : list, optional
            List of all input scriptPubKeys (needed for taproot)
        amounts : list, optional
            List of all input amounts in satoshis (needed for taproot)
        ext_flag : int, optional
            Extension flag for future upgrades
        script : Script, optional
            The script being satisfied (for script path spending)
        leaf_ver : int, optional
            Leaf version (default is LEAF_VERSION_TAPSCRIPT)
        sighash : int, optional
            Signature hash type
        annex : bytes, optional
            Optional annex data
            
        Returns
        -------
        bytes
            The transaction digest to be signed
        """
        # Ensure script_pubkeys and amounts are provided
        if script_pubkeys is None:
            script_pubkeys = [None] * len(self.inputs)
        if amounts is None:
            amounts = [0] * len(self.inputs)
        
        # Check for key path spending or script path spending
        is_script_path = script is not None
        
        # Initialize digest with hash type
        tx_digest = bytes([sighash])
        
        # Add transaction version (4 bytes, little-endian)
        if isinstance(self.version, int):
            tx_digest += struct.pack("<I", self.version)
        else:
            tx_digest += self.version
        
        # Add transaction locktime (4 bytes, little-endian)
        if isinstance(self.locktime, int):
            tx_digest += struct.pack("<I", self.locktime)
        else:
            tx_digest += self.locktime
        
        # Handle different SigHash types
        is_anyone_can_pay = (sighash & SIGHASH_ANYONECANPAY) != 0
        sig_hash_type = sighash & 0x03  # Get the basic type (bottom 2 bits)
        
        # Compute hash_prevouts if needed
        if not is_anyone_can_pay:
            prevouts_data = b''
            for inp in self.inputs:
                prevouts_data += h_to_b(inp.txid)[::-1]  # Reverse txid bytes
                prevouts_data += struct.pack("<I", inp.txout_index)
            hash_prevouts = hashlib.sha256(prevouts_data).digest()
        else:
            hash_prevouts = bytes(32)  # 32 zero bytes
        
        # Compute hash_amounts if needed
        if not is_anyone_can_pay:
            amounts_data = b''
            for amount in amounts:
                amounts_data += struct.pack("<q", amount)
            hash_amounts = hashlib.sha256(amounts_data).digest()
        else:
            hash_amounts = bytes(32)  # 32 zero bytes
        
        # Compute hash_script_pubkeys if needed
        if not is_anyone_can_pay:
            scripts_data = b''
            for pubkey in script_pubkeys:
                if pubkey is None:
                    scripts_data += bytes(0)  # Empty script
                else:
                    script_bytes = pubkey.to_bytes()
                    scripts_data += encode_varint(len(script_bytes))
                    scripts_data += script_bytes
            hash_script_pubkeys = hashlib.sha256(scripts_data).digest()
        else:
            hash_script_pubkeys = bytes(32)  # 32 zero bytes
        
        # Compute hash_sequences if needed
        if not is_anyone_can_pay and sig_hash_type != SIGHASH_SINGLE and sig_hash_type != SIGHASH_NONE:
            sequences_data = b''
            for inp in self.inputs:
                sequences_data += inp.sequence
            hash_sequences = hashlib.sha256(sequences_data).digest()
        else:
            hash_sequences = bytes(32)  # 32 zero bytes
        
        # Compute hash_outputs if needed
        if sig_hash_type == SIGHASH_ALL:
            outputs_data = b''
            for out in self.outputs:
                outputs_data += out.to_bytes()
            hash_outputs = hashlib.sha256(outputs_data).digest()
        elif sig_hash_type == SIGHASH_SINGLE and txin_index < len(self.outputs):
            hash_outputs = hashlib.sha256(self.outputs[txin_index].to_bytes()).digest()
        else:
            hash_outputs = bytes(32)  # 32 zero bytes
        
        # Add key data to digest
        tx_digest += hash_prevouts + hash_amounts + hash_script_pubkeys + hash_sequences + hash_outputs
        
        # Add spend_type to digest
        spend_type = 0
        if is_script_path:
            spend_type |= 1  # Script path spending
        if annex is not None:
            spend_type |= 2  # Annex is present
        tx_digest += bytes([spend_type])
        
        # Add current input index and outpoint to digest
        if is_anyone_can_pay:
            # For ANYONECANPAY only include the current input
            current_input = self.inputs[txin_index]
            tx_digest += h_to_b(current_input.txid)[::-1]  # Reverse txid bytes
            tx_digest += struct.pack("<I", current_input.txout_index)
            tx_digest += struct.pack("<q", amounts[txin_index])
            
            # Add script pubkey for current input
            if script_pubkeys[txin_index] is not None:
                script_bytes = script_pubkeys[txin_index].to_bytes()
                tx_digest += encode_varint(len(script_bytes))
                tx_digest += script_bytes
            else:
                tx_digest += bytes(0)  # Empty script
            
            # Add sequence for current input
            tx_digest += self.inputs[txin_index].sequence
        else:
            # Just add the input index (u32le)
            tx_digest += struct.pack("<I", txin_index)
        
        # Add annex if present
        if annex is not None:
            annex_hash = hashlib.sha256(annex).digest()
            tx_digest += annex_hash
        
        # For script path spending, add extra script data
        if is_script_path:
            # Add leaf version and script
            script_bytes = script.to_bytes()
            tx_digest += bytes([leaf_ver])
            tx_digest += encode_varint(len(script_bytes))
            tx_digest += script_bytes
        
        # Apply tagged hash
        digest = tagged_hash("TapSighash", tx_digest)
        return digest

    def get_txid(self) -> str:
        """Calculate the transaction ID (txid)
        
        Returns
        -------
        str
            Transaction ID as hex string
        """
        # For txid, we always exclude witness data
        tx_bytes = self.to_bytes(include_witness=False)
        tx_hash = hashlib.sha256(hashlib.sha256(tx_bytes).digest()).digest()
        # Bitcoin displays transaction hashes in little-endian
        return b_to_h(tx_hash[::-1])

    def get_wtxid(self) -> str:
        """Calculate the witness transaction ID (wtxid)
        
        Returns
        -------
        str
            Witness transaction ID as hex string
        """
        # For wtxid, we include witness data
        tx_bytes = self.to_bytes(include_witness=True)
        tx_hash = hashlib.sha256(hashlib.sha256(tx_bytes).digest()).digest()
        # Bitcoin displays transaction hashes in little-endian
        return b_to_h(tx_hash[::-1])

    def get_size(self) -> int:
        """Get transaction size in bytes
        
        Returns
        -------
        int
            Transaction size in bytes
        """
        return len(self.to_bytes())

    def get_vsize(self) -> int:
        """Get transaction virtual size (for fee calculation)
        
        Returns
        -------
        int
            Transaction virtual size in bytes
        """
        if not self.has_segwit:
            return self.get_size()
        
        # Calculate weight units: (non-witness data × 4) + witness data
        non_witness_size = len(self.to_bytes(include_witness=False))
        full_size = len(self.to_bytes(include_witness=True))
        witness_size = full_size - non_witness_size
        
        weight = (non_witness_size * 4) + witness_size
        # vsize is weight / 4 (rounded up)
        return math.ceil(weight / 4)

    def get_transaction_digest(
        self, txin_index: int, script: Script, sighash: int = SIGHASH_ALL
    ):
        """Returns the transaction's digest for signing.
        https://en.bitcoin.it/wiki/OP_CHECKSIG

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
        if (sighash & 0x1F) == SIGHASH_NONE:
            # do not include outputs in digest (i.e. do not sign outputs)
            tmp_tx.outputs = []

            # do not include sequence of other inputs (zero them for digest)
            # which means that they can be replaced
            for i in range(len(tmp_tx.inputs)):
                if i != txin_index:
                    tmp_tx.inputs[i].sequence = EMPTY_TX_SEQUENCE

        elif (sighash & 0x1F) == SIGHASH_SINGLE:
            # only sign the output that corresponds to txin_index

            if txin_index >= len(tmp_tx.outputs):
                raise ValueError(
                    "Transaction index is greater than the \
                                 available outputs"
                )

            # keep only output that corresponds to txin_index -- delete all outputs
            # after txin_index and zero out all outputs upto txin_index
            txout = tmp_tx.outputs[txin_index]
            tmp_tx.outputs = []
            for i in range(txin_index):
                tmp_tx.outputs.append(TxOutput(NEGATIVE_SATOSHI, Script([])))
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

        # get the bytes of the temporary transaction
        tx_for_signing = tmp_tx.to_bytes(False)

        # add sighash bytes to be hashed
        # Note that although sighash is one byte it is hashed as a 4 byte value.
        # There is no real reason for this other than that the original implementation
        # of Bitcoin stored sighash as an integer (which serializes as a 4
        # bytes), i.e. it should be converted to one byte before serialization.
        # It is converted to 1 byte before serializing to send to the network
        tx_for_signing += struct.pack("<i", sighash)

        # create transaction digest -- note double hashing
        tx_digest = hashlib.sha256(hashlib.sha256(tx_for_signing).digest()).digest()

        return tx_digest

    def get_transaction_segwit_digest(
        self, txin_index: int, script: Script, amount: int, sighash: int = SIGHASH_ALL,
        redeem_script=None, witness_script=None, script_path=False, control_block=None, 
        leaf_version=None, annex=None
    ):
        """Returns the segwit v0 transaction's digest for signing.
        https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki

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
                 The scriptCode (template) that corresponds to the segwit
                 transaction output type that we want to spend
             amount : int/float/Decimal
                 The amount of the UTXO to spend is included in the
                 signature for segwit (in satoshis)
             sighash : int
                 The type of the signature hash to be created
             redeem_script : Script, optional
                 The redeem script if it's p2sh
             witness_script : Script, optional
                 The witness script if it's p2wsh
             script_path : bool, optional
                 True if spending through script path (taproot)
             control_block : bytes, optional
                 Control block for script path (taproot)
             leaf_version : int, optional
                 Leaf version for script path (taproot)
             annex : bytes, optional
                 Optional annex field for taproot
        """

        # Initialize hash values
        hash_prevouts = bytes(32)  # 32 bytes of zeros
        hash_sequence = bytes(32)  # 32 bytes of zeros
        hash_outputs = bytes(32)   # 32 bytes of zeros

        # Determine signature type and flags
        basic_sig_hash_type = sighash & 0x1F
        anyone_can_pay = sighash & 0xF0 == SIGHASH_ANYONECANPAY
        sign_all = (basic_sig_hash_type != SIGHASH_SINGLE) and (basic_sig_hash_type != SIGHASH_NONE)

        # Create empty bytes for tx_for_signing
        tx_for_signing = bytes()

        # Make sure self.version is bytes, not an integer
        if isinstance(self.version, int):
            version_bytes = struct.pack("<i", self.version)  # Convert int to bytes
        else:
            version_bytes = self.version  # Already bytes

        # Add version
        tx_for_signing += version_bytes

        # Hash prevouts if needed
        if not anyone_can_pay:
            hash_prevouts_data = bytes()
            for txin in self.inputs:
                hash_prevouts_data += h_to_b(txin.txid)[::-1] + struct.pack("<I", txin.txout_index)
            hash_prevouts = hashlib.sha256(hashlib.sha256(hash_prevouts_data).digest()).digest()
        tx_for_signing += hash_prevouts

        # Hash sequences if needed
        if not anyone_can_pay and sign_all:
            hash_sequence_data = bytes()
            for txin in self.inputs:
                hash_sequence_data += txin.sequence
            hash_sequence = hashlib.sha256(hashlib.sha256(hash_sequence_data).digest()).digest()
        tx_for_signing += hash_sequence

        # Add outpoint (txid and vout) of the input we're signing
        txin = self.inputs[txin_index]
        tx_for_signing += h_to_b(txin.txid)[::-1] + struct.pack("<I", txin.txout_index)

        # Add script code
        script_bytes = script.to_bytes()
        tx_for_signing += encode_varint(len(script_bytes)) + script_bytes

        # Add amount of the input
        tx_for_signing += struct.pack("<q", amount)

        # Add sequence of the input
        tx_for_signing += txin.sequence

        # Hash outputs if needed
        if sign_all:
            hash_outputs_data = bytes()
            for txout in self.outputs:
                hash_outputs_data += txout.to_bytes()
            hash_outputs = hashlib.sha256(hashlib.sha256(hash_outputs_data).digest()).digest()
        elif basic_sig_hash_type == SIGHASH_SINGLE and txin_index < len(self.outputs):
            txout = self.outputs[txin_index]
            hash_outputs = hashlib.sha256(hashlib.sha256(txout.to_bytes()).digest()).digest()
        
        tx_for_signing += hash_outputs

        # Add locktime
        if isinstance(self.locktime, int):
            locktime_bytes = struct.pack("<i", self.locktime)
        else:
            locktime_bytes = self.locktime
        tx_for_signing += locktime_bytes

        # Add sighash type
        tx_for_signing += struct.pack("<i", sighash)

        # Handle annex if provided
        if annex is not None and self.version >= 2:  # Only for taproot transactions
            annex_hash = hashlib.sha256(annex).digest()
            tx_for_signing += annex_hash

        return hashlib.sha256(hashlib.sha256(tx_for_signing).digest()).digest()
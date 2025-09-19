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
from typing import Union
import math
import hashlib
import struct
from io import BytesIO
from typing import Optional, Union

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
    encode_varint,
    tagged_hash,
    prepend_compact_size,
    h_to_b,
    b_to_h,
    parse_compact_size,
)

def i_to_little_endian(value, length):
    return value.to_bytes(length, byteorder='little')

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
        sequence: Union[str, bytes] = DEFAULT_TX_SEQUENCE,
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
    def from_raw(
        txinputrawhex: Union[str, bytes], cursor: int = 0, has_segwit: bool = False
    ):
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
        if isinstance(txinputrawhex, str):
            txinputraw = h_to_b(txinputrawhex)
        elif isinstance(txinputrawhex, bytes):
            txinputraw = txinputrawhex
        else:
            raise TypeError("Input must be a hexadecimal string or bytes")

        # Unpack transaction ID (hash) in bytes and output index
        txid, vout = struct.unpack_from("<32sI", txinputraw, cursor)
        txid = txid[::-1]  # Reverse to match usual hexadecimal order
        cursor += 36  # 32 bytes for txid and 4 bytes for vout

        # Read the unlocking script size using parse_compact_size
        unlocking_script_size, size = parse_compact_size(txinputraw[cursor:])
        cursor += size

        # Read the unlocking script in bytes
        unlocking_script = struct.unpack_from(
            f"{unlocking_script_size}s", txinputraw, cursor
        )[0]
        cursor += unlocking_script_size

        # Read the sequence number in bytes
        (sequence,) = struct.unpack_from("<4s", txinputraw, cursor)
        cursor += 4

        # If coinbase input (utxo will be all zeros), handle script differently
        if txid.hex() == "00" * 32:
            script_sig = Script(
                [unlocking_script.hex()]
            )  # Treat as single element for coinbase
        else:
            script_sig = Script.from_raw(unlocking_script.hex(), has_segwit=has_segwit)

        # Create the TxInput instance
        tx_input = TxInput(
            txid=txid.hex(), txout_index=vout, script_sig=script_sig, sequence=sequence
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
    def from_raw(
        txoutputrawhex: Union[str, bytes], cursor: int = 0, has_segwit: bool = False
    ):
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
        if isinstance(txoutputrawhex, str):
            txoutputraw = h_to_b(txoutputrawhex)
        elif isinstance(txoutputrawhex, bytes):
            txoutputraw = txoutputrawhex
        else:
            raise TypeError("Input must be a hexadecimal string or bytes")

        # Unpack the amount of the TxOutput directly in bytes
        amount_format = "<Q"  # Little-endian unsigned long long (8 bytes)
        (amount,) = struct.unpack_from(amount_format, txoutputraw, cursor)
        cursor += struct.calcsize(amount_format)

        # Read the locking script size using parse_compact_size
        lock_script_size, size = parse_compact_size(txoutputraw[cursor:])
        cursor += size

        # Read the locking script
        script_format = f"{lock_script_size}s"
        (lock_script,) = struct.unpack_from(script_format, txoutputraw, cursor)
        cursor += lock_script_size

        # Create the TxOutput instance
        tx_output = TxOutput(
            amount=amount,
            script_pubkey=Script.from_raw(lock_script.hex(), has_segwit=has_segwit),
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
    
    @classmethod
    def from_bytes(cls, b):
        """Deserialize a TxOutput from bytes."""
        from bitcoinutils.script import Script
        from bitcoinutils.utils import read_varint
        import struct
        from io import BytesIO

        stream = BytesIO(b)

        # Read 8-byte value (little-endian)
        value = struct.unpack('<Q', stream.read(8))[0]

        # Read varint length of scriptPubKey
        script_len, varint_size = read_varint(stream.read(9))  # Read up to 9 bytes for varint
        stream.seek(8 + varint_size)  # Seek back to right after the varint
        
        # Read the script
        script_data = stream.read(script_len)
        
        # Create Script object from the raw bytes
        script_pubkey = Script.from_raw(script_data)

        return cls(value, script_pubkey)

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
    set_witness(txin_index, witness)
        sets the witness for a particular input index
    get_transaction_digest(txin_index, script, sighash)
        returns the transaction input's digest that is to be signed according
    get_transaction_segwit_digest(txin_index, script, amount, sighash)
        returns the transaction input's segwit digest that is to be signed
        according to sighash
    get_transaction_taproot_digest(txin_index, script_pubkeys, amounts, ext_flag,
            script, leaf_ver, sighash)
        returns the transaction input's taproot digest that is to be signed
        according to sighash
    """

    def __init__(
        self,
        inputs: Optional[list[TxInput]] = None,
        outputs: Optional[list[TxOutput]] = None,
        locktime: Union[str, bytes, int] = DEFAULT_TX_LOCKTIME,
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

        # Always store locktime as int
        if isinstance(locktime, str):
            self.locktime = int.from_bytes(h_to_b(locktime), 'little')
        elif isinstance(locktime, bytes):
            self.locktime = int.from_bytes(locktime, 'little')
        else:
            self.locktime = locktime

        self.version = version

    @staticmethod
    def from_raw(rawtxhex: Union[str, bytes]):
        """
        Imports a Transaction from hexadecimal data.

        Attributes
        ----------
        rawtxhex : string (hex)
            The hexadecimal raw string of the Transaction.
        """
        if isinstance(rawtxhex, str):
            rawtx = h_to_b(rawtxhex)
        elif isinstance(rawtxhex, bytes):
            rawtx = rawtxhex
        else:
            raise TypeError("Input must be a hexadecimal string or bytes")

        # Read version (4 bytes)
        version = rawtx[0:4]
        cursor = 4

        # Detect and handle SegWit
        has_segwit = False
        if rawtx[cursor : cursor + 2] == b"\x00\x01":
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

        # Handle witnesses if SegWit is enabled and if they are present i.e. if
        # remaining payload length is greater than last tx field length (locktime)
        has_witness_field = True if len(rawtx) - cursor > 4 else False
        witnesses = []
        if has_segwit and has_witness_field:
            for _ in range(n_inputs):
                n_items, size = parse_compact_size(rawtx[cursor:])
                cursor += size
                witnesses_tmp = []
                for _ in range(n_items):
                    item_size, size = parse_compact_size(rawtx[cursor:])
                    cursor += size
                    witness_data = rawtx[cursor : cursor + item_size]
                    cursor += item_size
                    witnesses_tmp.append(witness_data.hex())
                if witnesses_tmp:
                    witnesses.append(TxWitnessInput(stack=witnesses_tmp))

        # Read locktime (4 bytes)
        locktime = rawtx[cursor : cursor + 4]

        # Returning the Transaction object
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
                "locktime": self.locktime,
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

    # this sets empty witness slots (if necessary)
    # makes length of witness equal to the number of inputs, to prevent expliclty defining empty witness inputs
    # for non segwit inputs
    def set_witness(self, txin_index: int, witness: TxWitnessInput):
        """Safely set a witness at the specified index"""
        if not self.has_segwit:
            raise RuntimeError(
                "Transaction should be segwit in order to set segwit slots"
            )
        witness_len = len(self.witnesses)
        input_len = len(self.inputs)
        if witness_len < input_len:
            # append empty witness inputs if input_len>witness_len
            for _ in range(input_len - witness_len):
                self.witnesses.append(TxWitnessInput([]))

        if txin_index < 0 or txin_index >= len(self.inputs):
            raise IndexError("txin_index out of range")
        self.witnesses[txin_index] = witness

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
        self, txin_index: int, script: Script, amount: int, sighash: int = SIGHASH_ALL
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
        """

        # defaults for BIP143
        hash_prevouts = b"\x00" * 32
        hash_sequence = b"\x00" * 32
        hash_outputs = b"\x00" * 32

        # acquiring the signature type
        basic_sig_hash_type = sighash & 0x1F
        anyone_can_pay = sighash & 0xF0 == SIGHASH_ANYONECANPAY
        sign_all = (basic_sig_hash_type != SIGHASH_SINGLE) and (
            basic_sig_hash_type != SIGHASH_NONE
        )

        # Hash all input
        if not anyone_can_pay:
            hash_prevouts = b""
            for txin in self.inputs:
                hash_prevouts += h_to_b(txin.txid)[::-1] + struct.pack(
                    "<I", txin.txout_index
                )

            hash_prevouts = hashlib.sha256(
                hashlib.sha256(hash_prevouts).digest()
            ).digest()

        # Hash all input sequence
        if not anyone_can_pay and sign_all:
            hash_sequence = b""
            for txin in self.inputs:
                hash_sequence += txin.sequence
            hash_sequence = hashlib.sha256(
                hashlib.sha256(hash_sequence).digest()
            ).digest()

        if sign_all:
            # Hash all output
            hash_outputs = b""
            for txout in self.outputs:
                amount_bytes = struct.pack("<q", txout.amount)
                script_bytes = txout.script_pubkey.to_bytes()
                hash_outputs += (
                    amount_bytes + struct.pack("B", len(script_bytes)) + script_bytes
                )
            hash_outputs = hashlib.sha256(
                hashlib.sha256(hash_outputs).digest()
            ).digest()
        elif basic_sig_hash_type == SIGHASH_SINGLE and txin_index < len(self.outputs):
            # Hash one output
            txout = self.outputs[txin_index]
            amount_bytes = struct.pack("<q", txout.amount)
            script_bytes = txout.script_pubkey.to_bytes()
            hash_outputs = (
                amount_bytes + struct.pack("B", len(script_bytes)) + script_bytes
            )
            hash_outputs = hashlib.sha256(
                hashlib.sha256(hash_outputs).digest()
            ).digest()

        # add sighash version
        tx_for_signing = self.version

        # add hash_prevouts and hash_sequence
        tx_for_signing += hash_prevouts + hash_sequence

        # add tx outpoint (utxo txid + index)
        # Correcting the struct.pack usage from "<L" to "<I" for explicit 4-byte packing
        txin = self.inputs[txin_index]
        tx_for_signing += h_to_b(txin.txid)[::-1] + struct.pack("<I", txin.txout_index)

        # add tx script code
        tx_for_signing += struct.pack("B", len(script.to_bytes()))
        tx_for_signing += script.to_bytes()

        # add txin amount
        tx_for_signing += struct.pack("<q", amount)

        # add tx sequence
        tx_for_signing += txin.sequence

        # add txouts hash
        tx_for_signing += hash_outputs

        # add locktime
        tx_for_signing += self.locktime.to_bytes(4, byteorder="little")

        # add sighash type
        tx_for_signing += struct.pack("<i", sighash)

        return hashlib.sha256(hashlib.sha256(tx_for_signing).digest()).digest()

    # TODO Update doc with TAPROOT_SIGHASH_ALL
    # clean prints after finishing other sighashes
    def get_transaction_taproot_digest(
        self,
        txin_index: int,
        script_pubkeys: list[Script],
        amounts,
        ext_flag=0,
        script=Script([]),
        leaf_ver=LEAF_VERSION_TAPSCRIPT,
        sighash=TAPROOT_SIGHASH_ALL,
    ):
        """Returns the segwit v1 (taproot) transaction's digest for signing.
        https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
        Also consult Bitcoin Core code at: https://github.com/bitcoin/bitcoin/blob/29c36f070618ea5148cd4b2da3732ee4d37af66b/src/script/interpreter.cpp#L1478
        And: https://github.com/bitcoin/bitcoin/blob/b5f33ac1f82aea290b4653af36ac2ad1bf1cce7b/test/functional/test_framework/script.py

            |  SIGHASH types (see constants.py):
            |      TAPROOT_SIGHASH_ALL - signs all inputs and outputs (default)
            |      SIGHASH_ALL - signs all inputs and outputs
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
            script_pubkeys : list(Script)
                The scriptPubkeys that correspond to all the inputs/UTXOs
            amounts : int/float/Decimal
                The amounts that correspond to all the inputs/UTXOs
            ext_flag : int
                Extension mechanism, default is 0; 1 is for script spending (BIP342)
            script : Script object
                The script that we are spending (ext_flag=1)
            leaf_ver : int
                The script version, LEAF_VERSION_TAPSCRIPT for the default tapscript
            sighash : int
                The type of the signature hash to be created
        """

        # clone transaction to modify without messing up the real transaction
        # tmp_tx is not really used for its to_bytes() here
        # TODO we could use self directly to access fields
        tmp_tx = Transaction.copy(self)

        # acquiring the signature type
        # sign_all = sig_hash & 0x03 == SIGHASH_ALL
        sighash_none = sighash & 0x03 == SIGHASH_NONE
        sighash_single = sighash & 0x03 == SIGHASH_SINGLE
        anyone_can_pay = sighash & 0x80 == SIGHASH_ANYONECANPAY

        # add epoch
        tx_for_signing = bytes([0])

        # add sighash type
        tx_for_signing += bytes([sighash])

        # add sighash version
        tx_for_signing += self.version

        # add locktime
        tx_for_signing += self.locktime.to_bytes(4, byteorder="little")

        # defaults
        hash_prevouts = b""
        hash_amounts = b""
        hash_script_pubkeys = b""
        hash_sequences = b""
        hash_outputs = b""

        # Data about the transaction
        if not anyone_can_pay:
            # print('1')
            # the SHA256 of the serialization of all input outpoints
            for txin in tmp_tx.inputs:
                hash_prevouts += h_to_b(txin.txid)[::-1] + struct.pack(
                    "<I",
                    txin.txout_index,
                )
            hash_prevouts = hashlib.sha256(hash_prevouts).digest()
            tx_for_signing += hash_prevouts

            # the SHA256 of the serialization of all input amounts
            for a in amounts:
                # Fix: Handle both int and bytes types for amounts
                if isinstance(a, int):
                    hash_amounts += a.to_bytes(8, "little")
                elif isinstance(a, bytes):
                    # If it's already bytes, ensure it's 8 bytes little-endian
                    if len(a) == 8:
                        hash_amounts += a
                    else:
                        # Convert bytes to int then back to 8-byte little-endian
                        amount_int = int.from_bytes(a, "little")
                        hash_amounts += amount_int.to_bytes(8, "little")
                else:
                    # Handle other numeric types (float, Decimal)
                    amount_int = int(a)
                    hash_amounts += amount_int.to_bytes(8, "little")
            hash_amounts = hashlib.sha256(hash_amounts).digest()
            tx_for_signing += hash_amounts

            # the SHA256 of all spent outputs' scriptPubKeys
            for scr in script_pubkeys:
                s = scr.to_hex()
                script_len = int(len(s) / 2)
                hash_script_pubkeys += bytes([script_len]) + h_to_b(s)
            hash_script_pubkeys = hashlib.sha256(hash_script_pubkeys).digest()
            tx_for_signing += hash_script_pubkeys

            # the SHA256 of the serialization of all input nSequence
            for txin in tmp_tx.inputs:
                hash_sequences += txin.sequence
            hash_sequences = hashlib.sha256(hash_sequences).digest()
            tx_for_signing += hash_sequences

        if not (sighash_none or sighash_single):
            # print('2')
            for txout in tmp_tx.outputs:
                amount_bytes = struct.pack("<Q", txout.amount)
                script_bytes = txout.script_pubkey.to_bytes()
                hash_outputs += (
                    amount_bytes + struct.pack("B", len(script_bytes)) + script_bytes
                )
            hash_outputs = hashlib.sha256(hash_outputs).digest()
            tx_for_signing += hash_outputs

        # Data about this input
        spend_type = ext_flag * 2 + 0  # 0 for hard-coded - no annex_present

        tx_for_signing += bytes([spend_type])

        if anyone_can_pay:
            # print('3')
            txin = tmp_tx.inputs[txin_index]
            # convert txid to big-endian first
            tx_for_signing += h_to_b(txin.txid)[::-1] + struct.pack(
                "<I",
                txin.txout_index,
            )

            # Fix: Handle amount type for anyone_can_pay case
            amount = amounts[txin_index]
            if isinstance(amount, int):
                tx_for_signing += amount.to_bytes(8, "little")
            elif isinstance(amount, bytes):
                if len(amount) == 8:
                    tx_for_signing += amount
                else:
                    amount_int = int.from_bytes(amount, "little")
                    tx_for_signing += amount_int.to_bytes(8, "little")
            else:
                amount_int = int(amount)
                tx_for_signing += amount_int.to_bytes(8, "little")

            script_pubkey = script_pubkeys[txin_index].to_hex()
            script_len = int(len(script_pubkey) / 2)
            tx_for_signing += bytes([script_len]) + h_to_b(script_pubkey)

            tx_for_signing += txin.sequence
        else:
            # print('4')
            tx_for_signing += txin_index.to_bytes(4, "little")

        # TODO if annex is present it should be added here
        # length of annex should use compact_size

        # Data about this output
        if sighash_single:
            # print('5')
            txout = tmp_tx.outputs[txin_index]
            amount_bytes = struct.pack("<Q", txout.amount)
            script_bytes = txout.script_pubkey.to_bytes()
            hash_output = (
                amount_bytes + struct.pack("B", len(script_bytes)) + script_bytes
            )
            tx_for_signing += hashlib.sha256(hash_output).digest()

        if ext_flag == 1:  # script spending path (Signature Message Extension BIP-342)
            # committing the tapleaf hash - makes it safe to reuse keys for separate
            # scripts in the same output
            leaf_ver = (
                LEAF_VERSION_TAPSCRIPT  # pass as a parameter if a new version comes
            )
            tx_for_signing += tagged_hash(
                bytes([leaf_ver]) + prepend_compact_size(script.to_bytes()), "TapLeaf"
            )

            # key version - type of public key used for this signature, currently only 0
            tx_for_signing += bytes([0])

            # code separator position - records position of when the last
            # OP_CODESEPARATOR was executed; not supported for now, we always
            # use 0xffffffff
            tx_for_signing += b"\xff\xff\xff\xff"

        # tag hash the digest and return
        return tagged_hash(tx_for_signing, "TapSighash")

    def to_bytes(self, has_segwit: bool) -> bytes:
        """Serializes to bytes"""

        data = self.version
        # we just check the flag and not actual witnesses so that
        # the unsigned transactions also have the segwit marker/flag
        # TODO make sure that this does not cause problems and delete comment
        if has_segwit:  # and self.witnesses:
            # marker
            data += b"\x00"
            # flag
            data += b"\x01"

        txin_count_bytes = encode_varint(len(self.inputs))
        txout_count_bytes = encode_varint(len(self.outputs))
        data += txin_count_bytes
        for txin in self.inputs:
            data += txin.to_bytes()
        data += txout_count_bytes
        for txout in self.outputs:
            data += txout.to_bytes()
        if has_segwit:
            for witness in self.witnesses:
                # add witnesses script Count
                witnesses_count_bytes = encode_varint(len(witness.stack))
                data += witnesses_count_bytes
                data += witness.to_bytes()
        data += i_to_little_endian(self.locktime, 4)
        return data

    def get_txid(self) -> str:
        """Hashes the serialized (bytes) tx to get a unique id"""

        data = self.to_bytes(False)
        hash = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        # note that we reverse the hash for display purposes
        return b_to_h(hash[::-1])

    def get_wtxid(self) -> str:
        """Hashes the serialized (bytes) tx including segwit marker and witnesses"""

        return self._get_hash()

    def _get_hash(self) -> str:
        """Hashes the serialized (bytes) tx including segwit marker and witnesses"""

        data = self.to_bytes(self.has_segwit)
        hash = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        # note that we reverse the hash for display purposes
        return b_to_h(hash[::-1])

    def get_size(self) -> int:
        """Gets the size of the transaction"""

        return len(self.to_bytes(self.has_segwit))

    def get_vsize(self) -> int:
        """
        Gets the virtual size of the transaction.

        For non-segwit txs this is identical to get_size(). For segwit txs the
        marker and witnesses length needs to be reduced to 1/4 of its original
        length. Thus it is subtracted from size and then it is divided by 4
        before being added back to size to produce vsize (always rounded up).

        https://en.bitcoin.it/wiki/Weight_units
        """
        # return size if non-segwit
        if not self.has_segwit:
            return self.get_size()

        marker_size = 2
        data = b""

        # count witness data
        for witness in self.witnesses:
            # add witness stack count
            witnesses_count_bytes = chr(len(witness.stack)).encode()
            data += witnesses_count_bytes
            data += witness.to_bytes()

        wit_size = len(data)

        size = self.get_size() - (marker_size + wit_size)
        vsize = size + (marker_size + wit_size) / 4

        return int(math.ceil(vsize))

    def to_hex(self) -> str:
        """Converts object to hexadecimal string."""
        return b_to_h(self.to_bytes(self.has_segwit))

    def serialize(self) -> str:
        """Alias for to_hex()."""
        return self.to_hex()

    @staticmethod
    def from_bytes(tx_bytes):
        """
        Minimal inline deserializer for Transaction from bytes.
        Only for testing — not full-featured!
        """
        stream = BytesIO(tx_bytes)
        return Transaction._parse_from_stream(stream)

    @classmethod
    def _parse_from_stream(cls, stream):
        """
        Parse a Bitcoin transaction from a byte stream (PSBT raw transaction).
        """
        def read_varint(s):
            i = s.read(1)[0]
            if i == 0xfd:
                return struct.unpack('<H', s.read(2))[0]
            elif i == 0xfe:
                return struct.unpack('<I', s.read(4))[0]
            elif i == 0xff:
                return struct.unpack('<Q', s.read(8))[0]
            else:
                return i

        version = struct.unpack('<I', stream.read(4))[0]
        marker = stream.read(1)

        if marker == b'\x00':  # segwit marker
            flag = stream.read(1)
            is_segwit = True
        else:
            is_segwit = False
            stream.seek(-1, 1)  # rewind one byte

        input_count = read_varint(stream)
        inputs = []
        for _ in range(input_count):
            txid = stream.read(32)[::-1].hex()
            vout = struct.unpack('<I', stream.read(4))[0]
            script_len = read_varint(stream)
            script_sig_bytes = stream.read(script_len)
            sequence = stream.read(4)
            
            # FIX: Create proper TxInput object instead of dictionary
            script_sig = Script.from_raw(script_sig_bytes.hex(), has_segwit=is_segwit)
            tx_input = TxInput(
                txid=txid,
                txout_index=vout,
                script_sig=script_sig,
                sequence=sequence
            )
            inputs.append(tx_input)

        output_count = read_varint(stream)
        outputs = []
        for _ in range(output_count):
            value = struct.unpack('<Q', stream.read(8))[0]
            script_len = read_varint(stream)
            script_pubkey_bytes = stream.read(script_len)
            
            # FIX: Create proper TxOutput object instead of dictionary
            script_pubkey = Script.from_raw(script_pubkey_bytes.hex(), has_segwit=is_segwit)
            tx_output = TxOutput(
                amount=value,  # This will be accessible as tx_output.amount (int)
                script_pubkey=script_pubkey
            )
            outputs.append(tx_output)

        witnesses = []
        if is_segwit:
            for _ in range(input_count):
                witness_count = read_varint(stream)
                witness_stack = []
                for _ in range(witness_count):
                    item_len = read_varint(stream)
                    witness_item = stream.read(item_len).hex()
                    witness_stack.append(witness_item)
                if witness_stack:
                    witnesses.append(TxWitnessInput(witness_stack))

        locktime_bytes = stream.read(4)

        # Construct and return the transaction with proper objects
        return cls(
            inputs=inputs,
            outputs=outputs,
            locktime=locktime_bytes,
            version=version.to_bytes(4, 'little'),
            has_segwit=is_segwit,
            witnesses=witnesses
        )


def main():
    pass


if __name__ == "__main__":
    main()
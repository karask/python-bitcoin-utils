import struct
import hashlib
from typing import Optional, Union
from datetime import datetime, timezone

from bitcoinutils.utils import h_to_b, parse_compact_size, get_transaction_length

from bitcoinutils.transactions import Transaction

from bitcoinutils.constants import HEADER_SIZE, BLOCK_MAGIC_NUMBER

import os


class BlockHeader:
    """
    Represents a Bitcoin block header. This class encapsulates the details of a block's header
    in the blockchain, which includes essential mining and blockchain continuity information.

    Attributes
    ----------
    version : Optional[int]
        Version of the block protocol.
    previous_block_hash : Optional[bytes]
        256-bit hash of the previous block.
    merkle_root : Optional[bytes]
        256-bit hash based on all of the transactions in the block.
    timestamp : Optional[int]
        Block creation time in seconds since the Unix epoch.
    target_bits : Optional[int]
        Encoded difficulty target as a compact format.
    nonce : Optional[int]
        Arbitrary number that is adjusted to achieve the required proof of work.

    Methods
    -------
    __init__(version, previous_block_hash, merkle_root, timestamp, target_bits, nonce)
        Initializes a new instance of the BlockHeader.
    from_raw(rawhexdata)
        Constructs a BlockHeader object from raw block header data.
    __str__()
        Provides a human-readable representation of the BlockHeader.
    __repr__()
        Provides a precise string representation of the BlockHeader object that could be used to recreate the object.
    get_version()
        Retrieves the version of the block.
    get_previous_block_hash()
        Retrieves the hash of the previous block.
    get_merkle_root()
        Retrieves the Merkle root of the transactions in the block.
    get_timestamp()
        Retrieves the timestamp of when the block was created.
    get_target_bits()
        Retrieves the target bits that encode the mining difficulty target.
    get_nonce()
        Retrieves the nonce used for mining to achieve the block's proof of work.
    format_timestamp()
        Formats the timestamp into a human-readable UTC datetime string.
    """

    def __init__(
        self,
        version: Optional[int] = None,
        previous_block_hash: Optional[bytes] = None,
        merkle_root: Optional[bytes] = None,
        timestamp: Optional[int] = None,
        target_bits: Optional[int] = None,
        nonce: Optional[int] = None,
    ) -> None:
        """
        Initializes a new BlockHeader object with specified attributes for a Bitcoin block.

        Args:
            version (Optional[int]): Version of the block protocol.
            previous_block_hash (Optional[bytes]): The hash of the previous block in the chain.
            merkle_root (Optional[bytes]): The Merkle root hash of the block's transactions.
            timestamp (Optional[int]): The time at which the block was created, measured in seconds since the Unix epoch.
            target_bits (Optional[int]): The compact form of the block's difficulty target.
            nonce (Optional[int]): The nonce used to achieve the desired hash under the difficulty target.
        """

        self.version = version
        self.previous_block_hash = previous_block_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.target_bits = target_bits
        self.nonce = nonce

    @staticmethod
    def from_raw(rawhexdata: Union[str, bytes]):
        """
        Constructs a BlockHeader object from a raw block header data.

        Args:
            rawhexdata (Union[str, bytes]): Raw hexadecimal or byte data representing the block header.

        Returns:
            BlockHeader: An instance of BlockHeader initialized from the provided raw data.

        Raises:
            TypeError: If the input data type is not a string or bytes.
            ValueError: If the length of raw data does not match the expected size of a block header.
        """

        # Checking if rawhexdata is in hex and convert to bytes if necessary
        if isinstance(rawhexdata, str):
            rawdata = h_to_b(rawhexdata)
        elif isinstance(rawhexdata, bytes):
            rawdata = rawhexdata
        else:
            raise TypeError("Input must be a hexadecimal string or bytes")

        # format String for struct packing/unpacking for block header
        header_format = "<"  # little-edian
        header_format += "I"  # version (4 bytes)
        header_format += "32s"  # previous block hash (32 bytes)
        header_format += "32s"  # merkle root (32 bytes)
        header_format += "I"  # timestamp (4 bytes)
        header_format += "I"  # target bits (4 bytes)
        header_format += "I"  # nonce (4 bytes)

        if len(rawdata) != HEADER_SIZE:
            raise ValueError(f"Incorrect data length. Expected {HEADER_SIZE} bytes.")

        (
            version,
            previous_block_hash,
            merkle_root,
            timestamp,
            target_bits,
            nonce,
        ) = struct.unpack(header_format, rawdata)
        previous_block_hash = previous_block_hash[::-1]  # natural byte order
        merkle_root = merkle_root[::-1]  # natural byte order

        return BlockHeader(
            version=version,
            previous_block_hash=previous_block_hash,
            merkle_root=merkle_root,
            timestamp=timestamp,
            target_bits=target_bits,
            nonce=nonce,
        )

    def __str__(self) -> str:
        """
        Returns a string representation of the BlockHeader, presenting all header information in a readable format.

        Returns:
            str: Formatted string representation of the block header that includes all attributes.
        """

        return str(
            {
                "version": self.version,
                "previous block hash": self.previous_block_hash.hex(),
                "merkle root": self.merkle_root.hex(),
                "timestamp": self.timestamp,
                "target bits": self.target_bits,
                "nonce": self.nonce,
            }
        )

    def __repr__(self) -> str:
        return self.__str__()

    def get_version(self) -> Optional[int]:
        """Returns the block version, or None if not set."""
        return self.version if self.version is not None else None

    def get_previous_block_hash(self) -> Optional[bytes]:
        """Returns the previous block hash as bytes, or None if not set."""
        return self.previous_block_hash.hex() if self.previous_block_hash else None

    def get_merkle_root(self) -> Optional[bytes]:
        """Returns the merkle root as bytes, or None if not set."""
        return self.merkle_root.hex() if self.merkle_root else None

    def get_timestamp(self) -> Optional[int]:
        """Returns the block timestamp, or None if not set."""
        return self.timestamp if self.timestamp is not None else None

    def get_target_bits(self) -> Optional[int]:
        """Returns the compact form of the target difficulty (target_bits), or None if not set."""
        return self.target_bits if self.target_bits is not None else None

    def get_nonce(self) -> Optional[int]:
        """Returns the nonce used for mining, or None if not set."""
        return self.nonce if self.nonce is not None else None

    def format_timestamp(self):
        """
        Formats the block's timestamp into a human-readable UTC datetime string.

        Returns:
            str: The formatted UTC datetime string representing the block's timestamp.
        """

        # A timezone-aware datetime object in UTC
        utc_time = datetime.fromtimestamp(self.timestamp, timezone.utc)
        return utc_time.strftime("%Y-%m-%d %H:%M:%S UTC")

    def get_target_bits(self):
        """
        Decodes the compact representation of the target bits into the full target hash
        that a block's hash must be less than or equal to, in order to solve the block.

        Returns:
            str: The target value as a 64-character hexadecimal string, representing
                the full 256-bit target hash used in the proof of work.
        """

        # Extract the exponent (first byte) and coefficient (last three bytes) from the target_bits
        exponent = self.target_bits >> 24
        coefficient = self.target_bits & 0xFFFFFF

        # Calculate the target by shifting the coefficient by (exponent - 3) * 8 bits to the left
        target = coefficient << (8 * (exponent - 3))

        # Convert the target to a hexadecimal string with a fixed length of 64 characters
        target_hex = f"{target:064x}"
        return target_hex

    def serialize_header(self):
        """Serializes the block header in the format required for hashing."""
        # Ensure previous_block_hash and merkle_root are in byte form
        prev_hash = (
            self.previous_block_hash
            if isinstance(self.previous_block_hash, bytes)
            else bytes.fromhex(self.previous_block_hash)
        )
        merkle_root = (
            self.merkle_root
            if isinstance(self.merkle_root, bytes)
            else bytes.fromhex(self.merkle_root)
        )

        # Block header data is serialized in little-endian byte order
        header_data = (
            struct.pack("<I", self.version)
            + prev_hash[::-1]
            + merkle_root[::-1]  # reverse to little-endian
            + struct.pack("<I", self.timestamp)  # reverse to little-endian
            + struct.pack("<I", self.target_bits)
            + struct.pack("<I", self.nonce)
        )
        return header_data

    def get_block_hash(self):
        """Calculates the block hash by double SHA-256 hashing the header."""
        header_data = self.serialize_header()
        hash_one = hashlib.sha256(header_data).digest()
        hash_two = hashlib.sha256(hash_one).digest()
        # Bitcoin block hashes are displayed in big-endian hex, but calculated in little-endian
        return hash_two[::-1].hex()  # reverse to big-endian and convert to hex string


class Block:
    """
    Represents a Bitcoin block, encapsulating the block's fundamental components including
    the block header and a list of transactions.

    Attributes
    ----------
    magic : Optional[bytes]
        Magic value indicating the network for which the block was intended.
    block_size : Optional[int]
        Size of the block in bytes.
    header : Optional[BlockHeader]
        Header information of the block including version, previous block hash, etc.
    transaction_count : Optional[int]
        Number of transactions included in the block.
    transactions : Optional[list[Transaction]]
        A list of transactions contained in the block.

    Methods
    -------
    __init__(magic, block_size, header, transaction_count, transactions)
        Initializes a new instance of the Block class with specified attributes.
    from_raw(rawhexdata)
        Constructs a Block object from a raw block data.
        Raises TypeError if the input is neither bytes nor a hexadecimal string.
        Raises ValueError if the length of raw data does not match the expected size.
    __str__()
        Provides a human-readable representation of the Block, showing all attributes.
    __repr__()
        Provides a precise string representation of the Block object that could be used to recreate the object.
    get_magic_bytes()
        Retrieves the block's magic bytes as a tuple containing the hexadecimal representation and a descriptive string.
        Raises ValueError if the magic bytes are not set.
    get_block_size()
        Retrieves the size of the block in bytes.
    get_block_header()
        Retrieves the BlockHeader object associated with the block.
        Raises ValueError if the block header is not set.
    get_transactions()
        Retrieves the list of Transaction objects contained in the block.
        Raises ValueError if there are no transactions.
    get_transactions_count()
        Retrieves the count of transactions contained in the block.
        Raises ValueError if there are no transactions.
    get_coinbase_transaction()
        Retrieves the first transaction in the block, typically the coinbase transaction.
        Raises ValueError if there are no transactions.
    get_block_reward()
        Calculates the total output amount of the coinbase transaction, representing the block reward.
    get_witness_transactions()
        Returns a list of transactions that include SegWit data.
    get_legacy_transactions()
        Returns a list of transactions that are non-SegWit, legacy-style transactions.
    """

    def __init__(
        self,
        magic: Optional[bytes] = None,
        block_size: Optional[int] = None,
        header: Optional[BlockHeader] = None,
        transaction_count: Optional[int] = None,
        transactions: Optional[list[Transaction]] = None,
    ):
        """
        Initializes a new instance of Block, setting up all the necessary attributes that define a Bitcoin block.

        Args:
            magic (Optional[bytes]): The magic number used to identify the Bitcoin network.
            block_size (Optional[int]): The total size of the block in bytes.
            header (Optional[BlockHeader]): The header of the block containing various metadata.
            transaction_count (Optional[int]): The number of transactions included in this block.
            transactions (Optional[list[Transaction]]): A list of transactions included in the block.
        """

        self.magic = magic
        self.block_size = block_size
        self.header = header
        self.transaction_count = transaction_count
        self.transactions = transactions

    @staticmethod
    def from_raw(rawhexdata: Union[str, bytes]):
        """
        Constructs a Block instance from raw block data in hexadecimal or byte format.

        Args:
            rawhexdata (Union[str, bytes]): The raw data of the block in hexadecimal or bytes format.

        Returns:
            Block: A fully parsed Block object.

        Raises:
            TypeError: If the input is not a string or bytes.
            ValueError: If the input does not meet the expected block structure or size.
        """

        # Checking if rawhexdata is in hex and convert to bytes if necessary
        if isinstance(rawhexdata, str):
            rawdata = h_to_b(rawhexdata)
        elif isinstance(rawhexdata, bytes):
            rawdata = rawhexdata
        else:
            raise TypeError("Input must be a hexadecimal string or bytes")
        magic = rawdata[0:4]
        block_size = struct.unpack("<I", rawdata[4:8])[0]
        block_size = block_size
        header = BlockHeader.from_raw(rawdata[8 : 8 + HEADER_SIZE])

        # Handling the transaction counter which is a CompactSize
        transaction_count, tx_offset = parse_compact_size(rawdata[88:])
        transactions = []
        current_offset = 88 + tx_offset
        for i in range(transaction_count):
            try:
                tx_length = get_transaction_length(rawdata[current_offset:])
                transactions.append(
                    Transaction.from_raw(
                        rawdata[current_offset : current_offset + tx_length].hex()
                    )
                )
                temp = Transaction.from_raw(
                    rawdata[current_offset : current_offset + tx_length].hex()
                )
                current_offset += tx_length

            except Exception as e:
                print(e)
                print(i, transaction_count)
                break

        return Block(magic, block_size, header, transaction_count, transactions)

    def __str__(self) -> str:
        return str(
            {
                "magic": self.magic.hex(),
                "block size": self.block_size,
                "block header": self.header,
                "trasaction count": self.transaction_count,
                "transactions": self.transactions,
            }
        )

    def __repr__(self) -> str:
        return self.__str__()

    def get_magic_bytes(self) -> tuple[str, str]:
        """
        Retrieves the magic bytes and its corresponding network description.

        Returns:
            tuple[str, str]: The hexadecimal representation of the magic bytes and its description.

        Raises:
            ValueError: If the magic bytes are not set.
        """

        if self.magic is None:
            raise ValueError("Magic bytes are not set.")

        magic_hex = self.magic.hex()
        return (magic_hex, BLOCK_MAGIC_NUMBER[magic_hex])

    def get_block_size(self) -> int:
        """
        Retrieves the size of the block in bytes.

        Returns:
            int: The size of the block.
        """

        return self.block_size

    def get_block_header(self) -> BlockHeader:
        """
        Retrieves the header of the block.

        Returns:
            BlockHeader: The block header object.

        Raises:
            ValueError: If the block header is not set.
        """
        if self.header is None:
            raise ValueError("Block header is not set.")
        return self.header

    def get_transactions(self) -> list[Transaction]:
        """
        Retrieves the transactions contained in the block.

        Returns:
            list[Transaction]: A list of transactions.

        Raises:
            ValueError: If there are no transactions in the block.
        """

        if self.transactions is None:
            raise ValueError("No transactions given.")
        return self.transactions

    def get_transactions_count(self) -> int:
        """
        Retrieves the number of transactions in the block.

        Returns:
            int: The number of transactions.

        Raises:
            ValueError: If there are no transactions.
        """

        if self.transactions is None:
            raise ValueError("No transactions given.")
        return self.transaction_count

    def get_coinbase_transaction(self) -> Transaction:
        """
        Retrieves the coinbase transaction from the block, which is the first transaction in the block and contains the block reward.

        Returns:
            Transaction: The coinbase transaction.

        Raises:
            ValueError: If there are no transactions in the block.
        """

        if self.transactions is None:
            raise ValueError("No transactions given.")
        return self.transactions[0]

    def get_block_reward(self) -> int:
        """
        Calculates the total amount of the block reward by summing the outputs of the coinbase transaction.

        Returns:
            int: The total output amount in the coinbase transaction, representing the block reward.

        Raises:
            ValueError: If there are no transactions in the block.
        """

        if self.transactions is None:
            raise ValueError("No transactions given.")
        coinbase = self.get_coinbase_transaction()

        amount = 0

        for output in coinbase.outputs:
            amount += output.amount

        return amount

    def get_witness_transactions(self) -> list[Transaction]:
        """
        Returns a list of transactions that contain SegWit data.

        Returns:
        -------
        list[Transaction]
            A list of transactions with SegWit data.
        """
        if self.transactions is None:
            raise ValueError("No transactions given.")

        witness_transactions = [tx for tx in self.transactions if tx.has_segwit]
        return witness_transactions

    def get_legacy_transactions(self) -> list[Transaction]:
        """
        Returns a list of legacy transactions.

        Returns:
        -------
        list[Transaction]
            A list of legacy transactions.
        """
        if self.transactions is None:
            raise ValueError("No transactions given.")

        legacy_transactions = [tx for tx in self.transactions if not tx.has_segwit]
        return legacy_transactions

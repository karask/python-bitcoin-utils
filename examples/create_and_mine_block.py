#!/usr/bin/env python3

import json
import time
from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.script import Script
from bitcoinutils.keys import P2trAddress
from bitcoinutils.utils import to_satoshis
from bitcoinutils.block import Block, BlockHeader
import hashlib


def calculate_merkle_root(txid_list):
    """
    Calculates merkel root by hashing pairwise txids till only 1 is left.

    Args:
        txid_list: List of the transaction ids in the block

    Returns:
        (bytes): The merkle root of the block.
    """
    if len(txid_list) == 1:
        return bytes.fromhex(txid_list[0])

    # Convert each txid from big-endian hex to little-endian bytes.
    current_layer = [bytes.fromhex(txid)[::-1] for txid in txid_list]
    
    while len(current_layer) > 1:
        next_layer = []
        for i in range(0, len(current_layer), 2):
            # If there's an odd number, duplicate the last one.
            if i + 1 < len(current_layer):
                pair = current_layer[i] + current_layer[i + 1]
            else:
                pair = current_layer[i] + current_layer[i]
            # Perform double SHA-256 on the concatenated pair.
            next_layer.append(hashlib.sha256(hashlib.sha256(pair).digest()).digest())
        current_layer = next_layer

    # Reverse back to big-endian and return the bytes.
    return current_layer[0][::-1]


def calculate_witness_root_hash(wtxid_list):
    """
    Calculates witness root hash by hashing pairwise wtxids till only 1 is left.

    Args:
        wtxid_list: List of the witness transaction ids in the block

    Returns:
        (bytes): The witness root hash of the block.
    """
    if len(wtxid_list) == 1:
        # For a single txid, return its bytes (big-endian) representation.
        return bytes.fromhex(wtxid_list[0])

    # Convert each txid from big-endian hex to little-endian bytes.
    current_layer = [bytes.fromhex(wtxid)[::-1] for wtxid in wtxid_list]

    while len(current_layer) > 1:
        next_layer = []
        for i in range(0, len(current_layer), 2):
            # If there's an odd number, duplicate the last one.
            if i + 1 < len(current_layer):
                pair = current_layer[i] + current_layer[i + 1]
            else:
                pair = current_layer[i] + current_layer[i]
            # Perform double SHA-256 on the concatenated pair.
            next_layer.append(hashlib.sha256(hashlib.sha256(pair).digest()).digest())
        current_layer = next_layer

    return current_layer[0]


def calculate_witness_commitment(witness_root_hash, witness_reserved_value):
    """
    Calculates the witness commitment by performing a double SHA-256
    on the concatenation of the witness_root_hash and witness_reserved_value.

    Args:
        witness_root_hash(hex): witness root hash of the block
        witness_reserved_value(hex): the reserved value stored in the witness.

    Returns:
        (hex): hex of the witness commitment

    """
    # Convert both hex strings to bytes and concatenate them
    combined = bytes.fromhex(witness_root_hash + witness_reserved_value)

    # Perform double SHA256 hashing
    hash1 = hashlib.sha256(combined).digest()
    hash2 = hashlib.sha256(hash1).digest()
    return hash2.hex()


def create_block(coinbase_tx, tx1):
    # Note: Here I have for simplicity taken just the coinbase tx and another transaction (the test_tx the mempool),
    # more generally we just take the list of tx.

    txid_list = [coinbase_tx.get_txid(), tx1.get_txid()]
    merkle_root = calculate_merkle_root(txid_list)
    prev_block_hash = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000000"
    )
    # version https://learnmeabitcoin.com/technical/block/version/
    version = "40000000"
    version = int.from_bytes(bytes.fromhex(version), byteorder="little")
    timestamp = int(time.time())
    # resource: https://learnmeabitcoin.com/technical/block/bits/
    bits = "1f00ffff"
    bits = int.from_bytes(bytes.fromhex(bits), byteorder="big")

    nonce = 0

    block_header = BlockHeader(
        version,
        previous_block_hash=prev_block_hash,
        merkle_root=merkle_root,
        timestamp=timestamp,
        target_bits=bits,
        nonce=nonce,
    )
    magic = bytes.fromhex("f9beb4d9")
    block_size = None
    transaction_count = len([coinbase_tx, tx1])
    block = Block(
        magic=magic,
        block_size=block_size,
        header=block_header,
        transactions=[coinbase_tx, tx1],
        transaction_count=transaction_count,
    )
    return block


def mine_block(block_header_bytes, target_hex):
    """
    Mine a block by iterating through nonce values.

    Args:
        block_header_bytes (bytes): The 80-byte block header with a placeholder nonce.
        target_hex (str): The difficulty target as a hex string (256-bit number).

    Returns:
        (int, bytes): The nonce value and the corresponding block header hash that meets the target.
    """
    target_int = int(target_hex, 16)
    print("Target (int):", target_int)

    for nonce in range(2**32):
        # Replace the last 4 bytes of the header with the current nonce in little-endian format.
        header_with_nonce = block_header_bytes[:-4] + nonce.to_bytes(
            4, byteorder="little"
        )

        hash_once = hashlib.sha256(header_with_nonce).digest()
        hash_twice = hashlib.sha256(hash_once).digest()

        # Bitcoin displays the block hash in big-endian order.
        block_hash = hash_twice[::-1]
        block_hash_int = int.from_bytes(block_hash, byteorder="big")

        if block_hash_int < target_int:
            print("Success! Nonce found:", nonce)
            return nonce, block_hash

        # Optional: print progress every so often
        if nonce % 1000000 == 0:
            print("Tried nonce:", nonce)

    return None, None


def main():

    # mock transaction details, this transaction would be the first transaction
    # of the block after the coinbase transaction
    tx_details = {
        "txid": "00000a2d1a9e29116b539b85b6e893213b1ed95a08b7526a8d59a4b088fc6571",
        "version": 1,
        "locktime": 0,
        "vin": [
            {
            "txid": "2e4843d552ca9487efd9e69c0359f05375b7de5449eb49510d17a25bb5b15ec0",
            "vout": 1,
            "prevout": {
                "scriptpubkey": "512065fd3d423ea46a70505248db989e7302bfbbdd64ee4193dd9a59f69894f0de48",
                "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 65fd3d423ea46a70505248db989e7302bfbbdd64ee4193dd9a59f69894f0de48",
                "scriptpubkey_type": "v1_p2tr",
                "scriptpubkey_address": "bc1pvh7n6s375348q5zjfrde38nnq2lmhhtyaeqe8hv6t8mf398smeyqnug47s",
                "value": 13413
            },
            "scriptsig": "",
            "scriptsig_asm": "",
            "witness": [
                "29783b151d376d5178451ce14f62b091059021680bff36aec2814e33ecacf130e8aa92d6da23f35be7a8c2245b8f910261d4e6a5169f79d6ff7a3f412981f486"
            ],
            "is_coinbase": False,
            "sequence": 1610616404
            }
        ],
        "vout": [
            {
            "scriptpubkey": "51204b918d31f22461021ed54e354ac9dcbbe94b98edcfd3615b76c068b08222a87f",
            "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 4b918d31f22461021ed54e354ac9dcbbe94b98edcfd3615b76c068b08222a87f",
            "scriptpubkey_type": "v1_p2tr",
            "scriptpubkey_address": "bc1pfwgc6v0jy3ssy8k4fc654jwuh055hx8delfkzkmkcp5tpq3z4pls7tx8q3",
            "value": 2908
            },
            {
            "scriptpubkey": "512065fd3d423ea46a70505248db989e7302bfbbdd64ee4193dd9a59f69894f0de48",
            "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 65fd3d423ea46a70505248db989e7302bfbbdd64ee4193dd9a59f69894f0de48",
            "scriptpubkey_type": "v1_p2tr",
            "scriptpubkey_address": "bc1pvh7n6s375348q5zjfrde38nnq2lmhhtyaeqe8hv6t8mf398smeyqnug47s",
            "value": 8503
            }
        ],
        "size": 205,
        "weight": 616,
        "fee": 2002,
        "status": {
            "confirmed": True,
            "block_height": 834552,
            "block_hash": "00000000000000000001dd0468a70c94f619251d286585cff57aeb4bd9ede330",
            "block_time": 1710355598
        },
        "hex": "01000000000101c05eb1b55ba2170d5149eb4954deb77553f059039ce6d9ef8794ca52d543482e0100000000540e0060025c0b0000000000002251204b918d31f22461021ed54e354ac9dcbbe94b98edcfd3615b76c068b08222a87f372100000000000022512065fd3d423ea46a70505248db989e7302bfbbdd64ee4193dd9a59f69894f0de48014029783b151d376d5178451ce14f62b091059021680bff36aec2814e33ecacf130e8aa92d6da23f35be7a8c2245b8f910261d4e6a5169f79d6ff7a3f412981f48600000000"
    }


    setup("mainnet")
    
    # mock tx1
    tx1 = Transaction()
    tx1 = tx1.from_raw(tx_details["hex"])

    # tx1's wtxid (different from txid)
    wtxid = tx1.get_wtxid();
    print("\nWtx id :", wtxid)

    # address to send the block rewards
    to_addr = "bc1pvh7n6s375348q5zjfrde38nnq2lmhhtyaeqe8hv6t8mf398smeyqnug47s"
    to_addr = P2trAddress(to_addr)

    # create a coinbase transaction which is the first transaction of the block
    # it generates new coins so it does not spent an existing UTXO
    from_txid = "0000000000000000000000000000000000000000000000000000000000000000"

    # The witness reserved value is a 32-byte value that is reserved for future use.
    # and the coinbase transaction must have it in its input's witness
    witness_reserved_value = (
        "0000000000000000000000000000000000000000000000000000000000000000"
    )

    # Constructing the coinbase transaction
    txinp = TxInput(
        txid=from_txid,
        txout_index=0,
        script_sig=Script([witness_reserved_value]),
    )

    # Witness stack contains the list of witness data for the transaction
    # learn more: https://learnmeabitcoin.com/technical/upgrades/segregated-witness/
    witness_stack = [witness_reserved_value]


    # Coinbase wtxid must be set to all zeros to avoid circular reference
    # Learn more: https://learnmeabitcoin.com/technical/transaction/wtxid/
    coinbase_wtxid = "0" * 64

    witness_root_hash = calculate_witness_root_hash([coinbase_wtxid, wtxid])
    witness_root_hash = witness_root_hash.hex()
    print("\nWitness root hash ", witness_root_hash)

    # Calculating the witness commitment hash (double SHA256 of witness_root_hash and witness_reserved_value)
    witness_commitment_hash = calculate_witness_commitment(
        witness_root_hash, witness_reserved_value
    )

    # The commitment is constructed as:
    # commitment = "6a24aa21a9ed" + doublesha256(witness_root_hash, witness_reserved_value)
    # where commitment is made of (source BIP 141): 
    # 1-byte - OP_RETURN (0x6a)
    # 1-byte - Push the following 36 bytes (0x24)
    # 4-byte - Commitment header (0xaa21a9ed)
    # 32-byte - Commitment hash: Double-SHA256(witness root hash|witness reserved value)
    commitment = "6a24"+ "aa21a9ed" + witness_commitment_hash

    print("Witness Commitment :", commitment)
    # note: to_addr defined at the top. Taken from the first transaction
    # coinbase transactions must contain at least two outputs
    # the first output is the block reward and the second output is the commitment
    # The block reward is reward for the miner for mining the block + fees
    # block reward = block subsidy (currently 3.125 BTC) + transaction fees
    # Learn more: https://learnmeabitcoin.com/technical/mining/block-reward/
    txout1 = TxOutput(to_satoshis(3.125+0.01), to_addr.to_script_pub_key())

    # The commitment script is an OP_RETURN which includes:
    # a commitment header: to differentiate that OP_RETURN from others, and 
    # the commitment hash: Double-SHA256(witness root hash|witness reserved value)
    witness_commitment_script = Script(["OP_RETURN", "aa21a9ed" + witness_commitment_hash]);
    print("\nWitness commitment script : ", witness_commitment_script)

    txout2 = TxOutput(to_satoshis(0), witness_commitment_script)
    coinbase_tx = Transaction(
        [txinp],
        [txout1, txout2],
        has_segwit=True,
        witnesses=[TxWitnessInput(witness_stack)],
    )

    # Example difficulty target
    # learn more: https://learnmeabitcoin.com/technical/mining/target/
    # Note, this is even higher then the genesis block example
    # to prevent the mining process from running for a long time
    difficulty_target = (
        "0000ffff00000000000000000000000000000000000000000000000000000000"
    )

    # Creating a block that includes the coinbase transaction and tx1.
    block = create_block(coinbase_tx, tx1)

    print("\nBlock header: ", block.header)

    # getting the block header bytes
    # Note: only the header is hashed and compared to the difficulty in mining
    serialized_header = block.header.serialize_header()
    print("\nSerialized header : ", serialized_header)

    # mining the block using mine_block returns the nonce 
    # nonce is the value in the header that can be changed iteratively
    # to get a hash that is less than the target
    nonce, mined_hash = mine_block(serialized_header, difficulty_target)
    print("\nNONCE: ", nonce)

    # Replace the last 4 bytes of the header with the current nonce in little-endian format.
    serialized_header = serialized_header[:-4] + nonce.to_bytes(4, byteorder="little")

    print("\nHex of serialized header ", serialized_header.hex())
    print("\nCoinbase transaction :", coinbase_tx.to_hex())
    print("\nBlock: ", block)


if __name__ == "__main__":
    main()

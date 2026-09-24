"""Trace transaction Merkle trees and construct a scoped legacy coinbase.

The helpers expose the bytes needed for teaching block construction. They do
not validate a complete candidate block or construct SegWit witness commitments.
"""

from __future__ import annotations

import hashlib
from typing import Any

from bitcoinutils.constants import FINAL_TX_SEQUENCE, SATOSHIS_PER_BITCOIN
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput


_HALVING_INTERVALS = {
    "mainnet": 210_000,
    "testnet": 210_000,
    "testnet4": 210_000,
    "signet": 210_000,
    "regtest": 150,
}
_MAX_MONEY = 21_000_000 * SATOSHIS_PER_BITCOIN


def get_block_subsidy(height: int, network: str = "mainnet") -> int:
    """Return the block subsidy in satoshis at a height on an explicit network.

    Fees are separate. This does not establish that a candidate block has the
    required proof of work or is valid in the selected chain context.
    """
    if type(height) is not int or not 0 <= height <= 0x7FFFFFFF:
        raise ValueError("height must be a non-negative signed 32-bit integer.")
    if network not in _HALVING_INTERVALS:
        raise ValueError("Choose mainnet, testnet, testnet4, signet, or regtest.")

    halvings = height // _HALVING_INTERVALS[network]
    if halvings >= 64:
        return 0
    return (50 * SATOSHIS_PER_BITCOIN) >> halvings


def _height_push(height: int) -> bytes:
    """Encode a non-negative block height as the first CScript item (BIP34)."""
    if height == 0:
        return b"\x00"
    if height <= 16:
        return bytes([0x50 + height])

    encoded = bytearray()
    while height:
        encoded.append(height & 0xFF)
        height >>= 8
    if encoded[-1] & 0x80:
        encoded.append(0)
    return bytes([len(encoded)]) + encoded


def _push_data(data: bytes) -> bytes:
    if len(data) <= 75:
        return bytes([len(data)]) + data
    if len(data) <= 255:
        return b"\x4c" + bytes([len(data)]) + data
    raise ValueError("Coinbase data item is too large.")


def create_coinbase_transaction(
    height: int,
    outputs: list[TxOutput],
    *,
    fees: int = 0,
    network: str = "mainnet",
    extra_nonce: bytes = b"",
    message: bytes = b"",
) -> Transaction:
    """Create a legacy coinbase with BIP34 height and a final input sequence.

    The scriptSig begins with the minimally encoded height. Optional extranonce
    and message are separate data pushes. A short scriptSig is padded to the
    consensus minimum of two bytes. Output value may claim up to subsidy + fees.

    The caller supplies fees and a suitable payout script. This helper does not
    check the UTXO set, block height context, or proof of work. It does not add
    a SegWit witness commitment; use it only with legacy transactions.
    """
    subsidy = get_block_subsidy(height, network)
    if type(fees) is not int or not 0 <= fees <= _MAX_MONEY:
        raise ValueError("fees must be a non-negative satoshi amount.")
    if not isinstance(outputs, list) or not outputs:
        raise ValueError("outputs must be a non-empty list of TxOutput instances.")
    if not all(isinstance(output, TxOutput) for output in outputs):
        raise TypeError("Every coinbase output must be a TxOutput.")
    if any(
        type(output.amount) is not int
        or output.amount < 0
        or output.amount > _MAX_MONEY
        or not isinstance(output.script_pubkey, Script)
        for output in outputs
    ):
        raise ValueError("Coinbase outputs need valid amounts and scripts.")
    total_claim = sum(output.amount for output in outputs)
    if total_claim > _MAX_MONEY:
        raise ValueError("Coinbase outputs exceed the Bitcoin money range.")
    if total_claim > subsidy + fees:
        raise ValueError("Coinbase outputs exceed the subsidy plus supplied fees.")
    if not isinstance(extra_nonce, bytes) or not isinstance(message, bytes):
        raise TypeError("extra_nonce and message must be bytes.")

    script_sig = _height_push(height)
    if extra_nonce:
        script_sig += _push_data(extra_nonce)
    if message:
        script_sig += _push_data(message)
    if len(script_sig) < 2:
        script_sig += b"\x00"
    if len(script_sig) > 100:
        raise ValueError("Coinbase scriptSig must not exceed 100 bytes.")

    coinbase_input = TxInput(
        "00" * 32,
        0xFFFFFFFF,
        Script([script_sig.hex()]),
        FINAL_TX_SEQUENCE,
    )
    return Transaction([coinbase_input], list(outputs))


def trace_merkle_root(transactions: list[Transaction]) -> dict[str, Any]:
    """Return a JSON-friendly trace of Bitcoin's transaction Merkle tree.

    Displayed TXIDs are reversed to internal hash byte order before pairing.
    Each pair is double-SHA256 hashed. An odd final node is paired with itself.
    The mutated flag reports equal *existing* siblings, excluding a synthetic
    odd-leaf duplicate, as in Bitcoin Core's Merkle-root calculation.
    """
    if not isinstance(transactions, list) or not transactions:
        raise ValueError("transactions must be a non-empty list.")
    if not all(isinstance(tx, Transaction) for tx in transactions):
        raise TypeError("Every Merkle leaf must be a Transaction.")

    txids = [tx.get_txid() for tx in transactions]
    current = [bytes.fromhex(txid)[::-1] for txid in txids]
    levels_internal = [[item.hex() for item in current]]
    levels = [[item[::-1].hex() for item in current]]
    pairs: list[dict[str, Any]] = []
    mutated = False
    level = 0

    while len(current) > 1:
        parents = []
        for offset in range(0, len(current), 2):
            left = current[offset]
            duplicated = offset + 1 == len(current)
            right = left if duplicated else current[offset + 1]
            if not duplicated and left == right:
                mutated = True
            preimage = left + right
            parent = hashlib.sha256(hashlib.sha256(preimage).digest()).digest()
            pairs.append({
                "level": level,
                "index": offset // 2,
                "left": left[::-1].hex(),
                "right": right[::-1].hex(),
                "left_internal": left.hex(),
                "right_internal": right.hex(),
                "preimage": preimage.hex(),
                "parent": parent[::-1].hex(),
                "parent_internal": parent.hex(),
                "duplicated": duplicated,
            })
            parents.append(parent)
        current = parents
        levels_internal.append([item.hex() for item in current])
        levels.append([item[::-1].hex() for item in current])
        level += 1

    return {
        "txids": txids,
        "levels": levels,
        "levels_internal": levels_internal,
        "pairs": pairs,
        "root": current[0][::-1].hex(),
        "root_internal": current[0].hex(),
        "mutated": mutated,
    }

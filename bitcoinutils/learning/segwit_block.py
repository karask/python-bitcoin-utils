"""Construct an educational SegWit coinbase and trace its BIP141 commitment."""

from __future__ import annotations

import hashlib
from typing import Any

from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxOutput, TxWitnessInput

from bitcoinutils.learning.block import (
    _trace_merkle_hashes,
    create_coinbase_transaction,
    trace_merkle_root,
)

_COMMITMENT_PREFIX = bytes.fromhex("6a24aa21a9ed")


def create_segwit_coinbase_transaction(
    height: int,
    payout_outputs: list[TxOutput],
    *,
    transactions: list[Transaction],
    fees: int = 0,
    network: str = "mainnet",
    extra_nonce: bytes = b"",
    message: bytes = b"",
    witness_reserved_value: bytes = bytes(32),
) -> tuple[Transaction, dict[str, Any]]:
    """Return ``(coinbase, JSON-friendly trace)`` for an ordered candidate.

    The witness tree starts with a *zero* coinbase leaf and then the selected
    transactions' WTXIDs in block order. Legacy leaves use their TXIDs. The
    commitment output is appended after the caller's payout outputs, making it
    the highest-index matching output as required by BIP141. Existing matching
    outputs are recorded but remain untouched. The final ordinary Merkle tree
    uses the new coinbase TXID followed by selected transaction TXIDs.

    Supplied fees and transactions are assumptions. No UTXO, fee, proof-of-work,
    block-weight, or whole-block consensus validation is performed. Inputs are
    not mutated and no network access is used.
    """
    if not isinstance(payout_outputs, list):
        raise TypeError("payout_outputs must be a list of TxOutput instances.")
    if not isinstance(transactions, list):
        raise TypeError("transactions must be a list of non-coinbase Transaction objects.")
    for tx in transactions:
        if not isinstance(tx, Transaction):
            raise TypeError("Every selected item must be a Transaction.")
        if not tx.inputs:
            raise ValueError("Selected transactions must have at least one input.")
        if tx.inputs[0].txid == "00" * 32:
            raise ValueError("Do not include a coinbase in transactions.")
        if tx.has_segwit and len(tx.witnesses) != len(tx.inputs):
            raise ValueError("SegWit witness slots must be aligned with transaction inputs.")
    if type(witness_reserved_value) is not bytes or len(witness_reserved_value) != 32:
        raise ValueError("witness_reserved_value must be exactly 32 bytes.")

    wtxids = [tx.get_wtxid() for tx in transactions]
    witness_tree = _trace_merkle_hashes(["00" * 32, *wtxids])
    preimage = bytes.fromhex(witness_tree["root_internal"]) + witness_reserved_value
    commitment = hashlib.sha256(hashlib.sha256(preimage).digest()).digest()
    commitment_script = Script(["OP_RETURN", (bytes.fromhex("aa21a9ed") + commitment).hex()])
    # This is the sole output we construct. Earlier matches stay in the supplied
    # payout sequence, but this last one is authoritative by BIP141.
    commitment_output_index = len(payout_outputs)
    coinbase = create_coinbase_transaction(
        height,
        [*payout_outputs, TxOutput(0, commitment_script)],
        fees=fees,
        network=network,
        extra_nonce=extra_nonce,
        message=message,
    )
    coinbase.has_segwit = True
    coinbase.set_witness(0, TxWitnessInput([witness_reserved_value.hex()]))
    existing_indices = [
        index for index, output in enumerate(coinbase.outputs[:-1])
        if output.script_pubkey.to_bytes().startswith(_COMMITMENT_PREFIX)
    ]
    ordinary_tree = trace_merkle_root([coinbase, *transactions])
    trace = {
        "wtxids": wtxids,
        "witness_tree": witness_tree,
        "witness_root": witness_tree["root"],
        "witness_root_internal": witness_tree["root_internal"],
        "witness_reserved_value": witness_reserved_value.hex(),
        "commitment_preimage": preimage.hex(),
        "commitment_hash": commitment.hex(),
        "commitment_script": commitment_script.to_hex(),
        "commitment_output_index": commitment_output_index,
        "existing_commitment_output_indices": existing_indices,
        "coinbase_txid": coinbase.get_txid(),
        "coinbase_wtxid": coinbase.get_wtxid(),
        "ordinary_tree": ordinary_tree,
        "merkle_root": ordinary_tree["root"],
    }
    return coinbase, trace

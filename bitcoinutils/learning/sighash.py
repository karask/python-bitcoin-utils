"""Byte-level BIP143 signing-preimage traces for SegWit v0 lessons."""

from __future__ import annotations

import hashlib
import struct
from typing import Any

from bitcoinutils.constants import (
    SATOSHIS_PER_BITCOIN, SIGHASH_ALL, SIGHASH_ANYONECANPAY,
    SIGHASH_NONE, SIGHASH_SINGLE,
)
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction
from bitcoinutils.utils import encode_varint


SIGHASH_NAMES = {
    SIGHASH_ALL: "SIGHASH_ALL",
    SIGHASH_NONE: "SIGHASH_NONE",
    SIGHASH_SINGLE: "SIGHASH_SINGLE",
    SIGHASH_ALL | SIGHASH_ANYONECANPAY: "SIGHASH_ALL|ANYONECANPAY",
    SIGHASH_NONE | SIGHASH_ANYONECANPAY: "SIGHASH_NONE|ANYONECANPAY",
    SIGHASH_SINGLE | SIGHASH_ANYONECANPAY: "SIGHASH_SINGLE|ANYONECANPAY",
}


def _hash256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def trace_segwit_v0_sighash(
    transaction: Transaction,
    input_index: int,
    script_code: Script,
    previous_amount: int,
    sighash_type: int,
) -> dict[str, Any]:
    """Return an exact BIP143 preimage and its byte-level explanation.

    ``fields`` are ordered, zero-based half-open byte ranges in ``preimage``.
    Component inputs are ``None`` when that component hash is zero by sighash
    rule, rather than the double hash of empty bytes. This is a signing trace,
    not script or whole-transaction validation. The result is JSON-friendly.

    The digest is cross-checked against the core Transaction signer on every
    call; a future change to core serialization cannot silently diverge from
    this educational preimage builder.
    """
    if not isinstance(transaction, Transaction):
        raise TypeError("transaction must be a Transaction.")
    if type(input_index) is not int or not 0 <= input_index < len(transaction.inputs):
        raise ValueError("input_index must select a transaction input.")
    if not isinstance(script_code, Script):
        raise TypeError("script_code must be a Script.")
    if type(previous_amount) is not int or not 0 <= previous_amount <= 21_000_000 * SATOSHIS_PER_BITCOIN:
        raise ValueError("previous_amount must be integer satoshis within the Bitcoin money range.")
    if type(sighash_type) is not int or sighash_type not in SIGHASH_NAMES:
        raise ValueError("Only ALL, NONE, SINGLE, and their ANYONECANPAY variants are supported.")

    txin = transaction.inputs[input_index]
    anyone_can_pay = bool(sighash_type & SIGHASH_ANYONECANPAY)
    base_type = sighash_type & 0x1F
    prevouts_data = b"".join(
        bytes.fromhex(item.txid)[::-1] + struct.pack("<I", item.txout_index)
        for item in transaction.inputs
    ) if not anyone_can_pay else None
    sequence_data = b"".join(item.sequence for item in transaction.inputs) if (
        not anyone_can_pay and base_type == SIGHASH_ALL
    ) else None
    if base_type == SIGHASH_ALL:
        outputs_data = b"".join(output.to_bytes() for output in transaction.outputs)
    elif base_type == SIGHASH_SINGLE and input_index < len(transaction.outputs):
        outputs_data = transaction.outputs[input_index].to_bytes()
    else:
        outputs_data = None

    hash_prevouts = _hash256(prevouts_data) if prevouts_data is not None else bytes(32)
    hash_sequence = _hash256(sequence_data) if sequence_data is not None else bytes(32)
    hash_outputs = _hash256(outputs_data) if outputs_data is not None else bytes(32)
    script_bytes = script_code.to_bytes()
    script_with_length = encode_varint(len(script_bytes)) + script_bytes
    outpoint = bytes.fromhex(txin.txid)[::-1] + struct.pack("<I", txin.txout_index)

    fields: list[dict[str, Any]] = []
    preimage = bytearray()

    def append(name: str, data: bytes) -> None:
        start = len(preimage)
        preimage.extend(data)
        fields.append({
            "name": name, "start": start, "end": len(preimage),
            "size": len(data), "hex": data.hex(),
        })

    append("version", transaction.version)
    append("hashPrevouts", hash_prevouts)
    append("hashSequence", hash_sequence)
    append("outpoint", outpoint)
    append("scriptCode", script_with_length)
    append("amount", struct.pack("<q", previous_amount))
    append("sequence", txin.sequence)
    append("hashOutputs", hash_outputs)
    append("locktime", transaction.locktime)
    append("sighashType", struct.pack("<I", sighash_type))
    digest = _hash256(preimage)
    core_digest = transaction.get_transaction_segwit_digest(
        input_index, script_code, previous_amount, sighash_type
    )
    if digest != core_digest:
        raise RuntimeError("BIP143 trace differs from the core transaction signer.")

    return {
        "sighash": SIGHASH_NAMES[sighash_type],
        "sighash_type": sighash_type,
        "preimage": preimage.hex(),
        "digest": digest.hex(),
        "fields": fields,
        "hashPrevouts": hash_prevouts.hex(),
        "hashSequence": hash_sequence.hex(),
        "hashOutputs": hash_outputs.hex(),
        "prevouts_data": None if prevouts_data is None else prevouts_data.hex(),
        "sequence_data": None if sequence_data is None else sequence_data.hex(),
        "outputs_data": None if outputs_data is None else outputs_data.hex(),
        "outpoint": outpoint.hex(),
        "script_code": script_bytes.hex(),
        "script_code_with_length": script_with_length.hex(),
        "previous_amount": previous_amount,
        "single_output_out_of_range": base_type == SIGHASH_SINGLE and input_index >= len(transaction.outputs),
    }

"""Educational execution traces for native SegWit v0 P2WPKH inputs.

Witness items initialize the stack; they are not Script instructions. The
implied P2PKH script checks the witness program and a BIP143 signature.
This scoped evaluator does not perform full transaction validation.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any

from ecdsa import BadSignatureError, MalformedPointError, SECP256k1, VerifyingKey
from ecdsa.der import UnexpectedDER
from ecdsa.util import sigdecode_der

from bitcoinutils.constants import SATOSHIS_PER_BITCOIN, SIGHASH_ALL
from bitcoinutils.ripemd160 import ripemd160
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxWitnessInput


def trace_p2wpkh_input(
    transaction: Transaction,
    input_index: int,
    previous_script_pubkey: Script,
    amount: int,
) -> dict[str, Any]:
    """Trace a native P2WPKH input with its previous output amount in satoshis.

    The previous Script must serialize as ``0014<20-byte hash>``. The selected
    input must have an empty scriptSig and a two-item witness: signature (DER
    plus 01) and compressed SEC public key. ``transaction.witnesses`` must
    contain one TxWitnessInput per input, including empty legacy slots.

    The JSON-friendly result retains the P2PKH tracer's common fields: success,
    script_type, sighash, final_stack, steps, and error. Stacks are independent
    lists of hex strings, bottom first (empty string is false, 01 is true).
    Steps contain phase, instruction, stack_before, stack_after, and error.
    ``witness`` steps have kind ``witness_load``; ``scriptCode`` steps execute
    the implied script. CHECKSIG includes digest and signature_valid when
    computed. Metadata includes amount, witness_program, and script_code (hex
    without a CompactSize prefix) once those inputs are validated. sighash is
    None until read; sighash_byte then records the actual numeric type byte.
    Failures retain the partial trace and annotate the failing instruction.

    Supports only native P2WPKH, SIGHASH_ALL and compressed keys. Compressed
    keys are a scope/default-policy restriction, not a consensus-validity
    claim. No low-S or NULLFAIL policy check is made. Empty/incorrect signatures
    produce false; malformed nonempty DER signatures halt execution. Inputs
    are not mutated. UTXO existence, amount accuracy, unspent status, fees,
    locktime eligibility, and other inputs/whole transactions are not checked.
    """
    stack: list[bytes] = []
    steps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        "success": False,
        "script_type": "p2wpkh",
        "sighash": None,
        "final_stack": [],
        "steps": steps,
        "error": None,
    }

    def snapshot() -> list[str]:
        return [item.hex() for item in stack]

    def step(phase: str, instruction: str, kind: str) -> dict[str, Any]:
        record = {
            "phase": phase,
            "instruction": instruction,
            "kind": kind,
            "stack_before": snapshot(),
            "stack_after": snapshot(),
            "error": None,
        }
        steps.append(record)
        return record

    def fail(
        code: str, message: str, record: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if record is not None:
            record["stack_after"] = snapshot()
            record["error"] = message
        result["final_stack"] = snapshot()
        result["error"] = {"code": code, "message": message}
        return result

    if not isinstance(transaction, Transaction):
        return fail("INVALID_TRANSACTION", "transaction must be a Transaction instance.")
    if type(input_index) is not int or not 0 <= input_index < len(transaction.inputs):
        return fail("INVALID_INPUT_INDEX", "Choose an integer index within the transaction.")
    if type(amount) is not int or not 0 <= amount <= 21_000_000 * SATOSHIS_PER_BITCOIN:
        return fail("INVALID_AMOUNT", "amount must be integer satoshis within the Bitcoin money range.")
    result["amount"] = amount
    if not isinstance(previous_script_pubkey, Script):
        return fail("INVALID_SCRIPT", "previous_script_pubkey must be a Script instance.")
    try:
        locking_bytes = previous_script_pubkey.to_bytes()
    except (TypeError, ValueError, OverflowError):
        return fail("INVALID_SCRIPT", "The previous locking script cannot be serialized.")
    if len(locking_bytes) != 22 or locking_bytes[:2] != b"\x00\x14":
        return fail("UNSUPPORTED_SCRIPT", "Only native SegWit v0 P2WPKH locking scripts are supported.")
    program = locking_bytes[2:]
    script_code = Script(
        ["OP_DUP", "OP_HASH160", program.hex(), "OP_EQUALVERIFY", "OP_CHECKSIG"]
    )
    result.update(witness_program=program.hex(), script_code=script_code.to_hex())

    script_sig = transaction.inputs[input_index].script_sig
    if not isinstance(script_sig, Script) or script_sig.get_script() != []:
        return fail("NONEMPTY_SCRIPTSIG", "Native P2WPKH requires an exactly empty scriptSig.")
    if not transaction.has_segwit:
        return fail("INVALID_WITNESS", "Enable SegWit serialization on the transaction.")
    if (
        not isinstance(transaction.witnesses, list)
        or len(transaction.witnesses) != len(transaction.inputs)
    ):
        return fail("WITNESS_COUNT_MISMATCH", "Provide one witness slot per input, including empty legacy slots.")
    witness = transaction.witnesses[input_index]
    if not isinstance(witness, TxWitnessInput) or not isinstance(witness.stack, list):
        return fail("INVALID_WITNESS", "The selected witness must be a TxWitnessInput with a stack list.")
    if len(witness.stack) != 2:
        return fail("INVALID_WITNESS_COUNT", "P2WPKH needs exactly two witness items: signature and public key.")

    for token, instruction in zip(witness.stack, ("LOAD_SIGNATURE", "LOAD_PUBLIC_KEY")):
        record = step("witness", instruction, "witness_load")
        if not isinstance(token, str):
            return fail("INVALID_WITNESS_DATA", "Witness items must be hexadecimal strings.", record)
        if len(token) > 1040:
            return fail("WITNESS_ITEM_TOO_LARGE", "Each witness item must be at most 520 bytes.", record)
        if len(token) % 2 or any(c not in "0123456789abcdefABCDEF" for c in token):
            return fail("INVALID_WITNESS_DATA", "Witness items must be hex without separators.", record)
        stack.append(bytes.fromhex(token))
        record.update(value=stack[-1].hex(), stack_after=snapshot())

    # Only this fixed, internally constructed script is interpreted.
    for instruction in script_code.get_script():
        record = step(
            "scriptCode", instruction,
            "opcode" if instruction.startswith("OP_") else "push",
        )
        if instruction == "OP_DUP":
            stack.append(stack[-1])
        elif instruction == "OP_HASH160":
            stack[-1] = ripemd160(hashlib.sha256(stack[-1]).digest())
        elif instruction == program.hex():
            stack.append(program)
        elif instruction == "OP_EQUALVERIFY":
            right, left = stack.pop(), stack.pop()
            if left != right:
                # OP_EQUAL leaves false on the stack when VERIFY fails.
                stack.append(b"")
                return fail("EQUALVERIFY_FAILED", "The public-key hash does not match the witness program.", record)
        elif instruction == "OP_CHECKSIG":
            signature, public_key = stack[-2:]
            if len(public_key) != 33 or public_key[:1] not in (b"\x02", b"\x03"):
                return fail("UNSUPPORTED_PUBLIC_KEY", "This tracer supports only 33-byte compressed SEC public keys.", record)
            if signature:
                result["sighash_byte"] = signature[-1]
                if signature[-1] != SIGHASH_ALL:
                    return fail("UNSUPPORTED_SIGHASH", "Only SIGHASH_ALL (01) is supported.", record)
                result["sighash"] = "SIGHASH_ALL"
                try:
                    sigdecode_der(signature[:-1], SECP256k1.order)
                except UnexpectedDER:
                    return fail("INVALID_SIGNATURE_ENCODING", "Use a strict DER signature followed by 01.", record)
            try:
                key = VerifyingKey.from_string(
                    public_key, curve=SECP256k1, valid_encodings={"compressed"}
                )
            except MalformedPointError:
                return fail("INVALID_PUBLIC_KEY", "The public key is not a valid secp256k1 point.", record)
            valid = False
            if signature:
                try:
                    digest = transaction.get_transaction_segwit_digest(
                        input_index, script_code, amount, SIGHASH_ALL
                    )
                except (TypeError, ValueError, OverflowError, struct.error):
                    return fail("INVALID_TRANSACTION", "The transaction fields cannot produce a SegWit signing digest.", record)
                record["digest"] = digest.hex()
                try:
                    valid = key.verify_digest(signature[:-1], digest, sigdecode=sigdecode_der)
                except BadSignatureError:
                    valid = False
            stack[-2:] = [b"\x01" if valid else b""]
            record.update(signature_valid=valid, stack_after=snapshot())
            if not valid:
                return fail("CHECKSIG_FAILED", "The signature does not authorize this input for the supplied amount.", record)
        record["stack_after"] = snapshot()

    result.update(success=stack == [b"\x01"], final_stack=snapshot())
    return result

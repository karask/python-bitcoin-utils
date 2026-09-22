"""Trace execution of a narrowly scoped legacy P2PKH input.

This is an educational evaluator, not a general Bitcoin Script interpreter or
a complete transaction validator.  It accepts only a standard legacy P2PKH
locking script, a two-push ``scriptSig``, and ``SIGHASH_ALL`` signatures.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ecdsa import BadSignatureError  # type: ignore
from ecdsa.util import sigdecode_der  # type: ignore

from bitcoinutils.constants import SIGHASH_ALL
from bitcoinutils.keys import PublicKey
from bitcoinutils.ripemd160 import ripemd160
from bitcoinutils.script import Script, is_p2pkh
from bitcoinutils.transactions import Transaction


def _stack_hex(stack: list[bytes]) -> list[str]:
    return [item.hex() for item in stack]


def _result(
    success: bool,
    steps: list[dict[str, Any]],
    stack: list[bytes],
    error: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "success": success,
        "script_type": "p2pkh",
        "sighash": "SIGHASH_ALL",
        "final_stack": _stack_hex(stack),
        "steps": steps,
        "error": error,
    }


def _failure(
    code: str,
    message: str,
    steps: list[dict[str, Any]],
    stack: list[bytes],
) -> dict[str, Any]:
    return _result(False, steps, stack, {"code": code, "message": message})


def trace_p2pkh_input(
    transaction: Transaction,
    input_index: int,
    previous_script_pubkey: Script,
) -> dict[str, Any]:
    """Execute and trace one standard legacy P2PKH input.

    Parameters
    ----------
    transaction
        Signed legacy transaction containing the input's ``scriptSig``.
    input_index
        Index of the input being checked.
    previous_script_pubkey
        Locking script of the output that the input claims to spend.

    Returns
    -------
    dict
        A JSON-friendly result containing ``success``, the final stack, every
        instruction with its stack before and after, and a structured error on
        failure.

    Notes
    -----
    This helper does not check whether the previous output exists or is
    unspent, transaction values, locktime, policy, or any non-P2PKH script.
    Only legacy ``SIGHASH_ALL`` signatures are supported.
    """

    steps: list[dict[str, Any]] = []
    stack: list[bytes] = []

    if not isinstance(transaction, Transaction):
        return _failure(
            "INVALID_TRANSACTION",
            "transaction must be a Transaction instance.",
            steps,
            stack,
        )
    if not isinstance(input_index, int) or isinstance(input_index, bool):
        return _failure(
            "INVALID_INPUT_INDEX",
            "Input index must be an integer.",
            steps,
            stack,
        )
    if input_index < 0 or input_index >= len(transaction.inputs):
        return _failure(
            "INVALID_INPUT_INDEX",
            "Input index is outside the transaction.",
            steps,
            stack,
        )
    if not isinstance(previous_script_pubkey, Script):
        return _failure(
            "INVALID_SCRIPT",
            "previous_script_pubkey must be a Script instance.",
            steps,
            stack,
        )
    if not is_p2pkh(previous_script_pubkey):
        return _failure(
            "UNSUPPORTED_SCRIPT",
            "Only standard legacy P2PKH locking scripts are supported.",
            steps,
            stack,
        )

    script_sig = transaction.inputs[input_index].script_sig.get_script()
    if len(script_sig) != 2 or not all(
        isinstance(item, str) for item in script_sig
    ):
        return _failure(
            "UNSUPPORTED_SCRIPTSIG",
            "A P2PKH scriptSig must contain exactly a signature and public-key push.",
            steps,
            stack,
        )

    for position, token in enumerate(script_sig):
        before = _stack_hex(stack)
        try:
            value = bytes.fromhex(token)
        except ValueError:
            return _failure(
                "INVALID_PUSH_DATA",
                "scriptSig contains invalid hexadecimal data.",
                steps,
                stack,
            )
        stack.append(value)
        steps.append(
            {
                "phase": "scriptSig",
                "instruction": (
                    "PUSH_SIGNATURE" if position == 0 else "PUSH_PUBLIC_KEY"
                ),
                "value": token,
                "stack_before": before,
                "stack_after": _stack_hex(stack),
                "error": None,
            }
        )

    for token in previous_script_pubkey.get_script():
        before = _stack_hex(stack)
        step: dict[str, Any] = {
            "phase": "scriptPubKey",
            "instruction": token,
            "stack_before": before,
            "error": None,
        }

        if isinstance(token, str) and not token.startswith("OP_"):
            try:
                stack.append(bytes.fromhex(token))
            except ValueError:
                step["stack_after"] = _stack_hex(stack)
                step["error"] = "Locking script contains invalid hexadecimal data."
                steps.append(step)
                return _failure("INVALID_PUSH_DATA", step["error"], steps, stack)
        elif token == "OP_DUP":
            if not stack:
                return _failure(
                    "STACK_UNDERFLOW",
                    "OP_DUP requires one stack item.",
                    steps,
                    stack,
                )
            stack.append(stack[-1])
        elif token == "OP_HASH160":
            if not stack:
                return _failure(
                    "STACK_UNDERFLOW",
                    "OP_HASH160 requires one stack item.",
                    steps,
                    stack,
                )
            stack.append(ripemd160(hashlib.sha256(stack.pop()).digest()))
        elif token == "OP_EQUALVERIFY":
            if len(stack) < 2:
                return _failure(
                    "STACK_UNDERFLOW",
                    "OP_EQUALVERIFY requires two stack items.",
                    steps,
                    stack,
                )
            right, left = stack.pop(), stack.pop()
            if left != right:
                step["stack_after"] = _stack_hex(stack)
                step["error"] = "The public-key hash does not match the locking script."
                steps.append(step)
                return _failure("EQUALVERIFY_FAILED", step["error"], steps, stack)
        elif token == "OP_CHECKSIG":
            if len(stack) < 2:
                return _failure(
                    "STACK_UNDERFLOW",
                    "OP_CHECKSIG requires a signature and public key.",
                    steps,
                    stack,
                )
            public_key_bytes = stack.pop()
            signature = stack.pop()
            if not signature:
                step["stack_after"] = _stack_hex(stack)
                step["error"] = "The signature push is empty."
                steps.append(step)
                return _failure("INVALID_SIGNATURE", step["error"], steps, stack)
            sighash = signature[-1]
            if sighash != SIGHASH_ALL:
                step["stack_after"] = _stack_hex(stack)
                step["error"] = "Only SIGHASH_ALL is supported by this educational evaluator."
                steps.append(step)
                return _failure("UNSUPPORTED_SIGHASH", step["error"], steps, stack)
            digest = transaction.get_transaction_digest(
                input_index, previous_script_pubkey, SIGHASH_ALL
            )
            try:
                public_key = PublicKey(public_key_bytes.hex())
                valid = public_key.key.verify_digest(
                    signature[:-1], digest, sigdecode=sigdecode_der
                )
            except (
                BadSignatureError,
                IndexError,
                TypeError,
                ValueError,
                AssertionError,
            ):
                valid = False
            stack.append(b"\x01" if valid else b"")
            step["digest"] = digest.hex()
            step["signature_valid"] = valid
        else:
            step["stack_after"] = _stack_hex(stack)
            step["error"] = f"Unsupported instruction: {token!r}."
            steps.append(step)
            return _failure("UNSUPPORTED_INSTRUCTION", step["error"], steps, stack)

        step["stack_after"] = _stack_hex(stack)
        steps.append(step)

    success = bool(stack and stack[-1] not in (b"", b"\x80"))
    if not success:
        return _failure(
            "CHECKSIG_FAILED",
            "The signature does not authorize this P2PKH input.",
            steps,
            stack,
        )
    return _result(True, steps, stack)

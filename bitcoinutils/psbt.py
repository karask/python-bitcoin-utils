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

"""BIP-0174 Partially Signed Bitcoin Transaction (PSBT) support.

Implements PSBT version 0 per https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""

import struct
from io import BytesIO
from typing import Optional
import base64

from bitcoinutils.constants import SIGHASH_ALL
from bitcoinutils.script import Script
from bitcoinutils.transactions import (
    Transaction,
    TxInput,
    TxOutput,
    TxWitnessInput,
)
from bitcoinutils.utils import (
    encode_varint,
    parse_compact_size,
    h_to_b,
    b_to_h,
)

# PSBT magic bytes
PSBT_MAGIC = b"psbt\xff"

# Global types
PSBT_GLOBAL_UNSIGNED_TX = 0x00
PSBT_GLOBAL_XPUB = 0x01

# Per-input types
PSBT_IN_NON_WITNESS_UTXO = 0x00
PSBT_IN_WITNESS_UTXO = 0x01
PSBT_IN_PARTIAL_SIG = 0x02
PSBT_IN_SIGHASH_TYPE = 0x03
PSBT_IN_REDEEM_SCRIPT = 0x04
PSBT_IN_WITNESS_SCRIPT = 0x05
PSBT_IN_BIP32_DERIVATION = 0x06
PSBT_IN_FINAL_SCRIPTSIG = 0x07
PSBT_IN_FINAL_SCRIPTWITNESS = 0x08

# Per-output types
PSBT_OUT_REDEEM_SCRIPT = 0x00
PSBT_OUT_WITNESS_SCRIPT = 0x01
PSBT_OUT_BIP32_DERIVATION = 0x02


# Sets of known key types for validation
_KNOWN_INPUT_SINGLE_BYTE_KEYS = {
    PSBT_IN_NON_WITNESS_UTXO,
    PSBT_IN_WITNESS_UTXO,
    PSBT_IN_SIGHASH_TYPE,
    PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_WITNESS_SCRIPT,
    PSBT_IN_FINAL_SCRIPTSIG,
    PSBT_IN_FINAL_SCRIPTWITNESS,
}

_KNOWN_INPUT_PUBKEY_KEYS = {
    PSBT_IN_PARTIAL_SIG,
    PSBT_IN_BIP32_DERIVATION,
}

_KNOWN_OUTPUT_SINGLE_BYTE_KEYS = {
    PSBT_OUT_REDEEM_SCRIPT,
    PSBT_OUT_WITNESS_SCRIPT,
}

_KNOWN_OUTPUT_PUBKEY_KEYS = {
    PSBT_OUT_BIP32_DERIVATION,
}


def _validate_pubkey_length(pubkey: bytes, context: str) -> None:
    """Validate that a pubkey is 33 (compressed) or 65 (uncompressed) bytes."""
    if len(pubkey) not in (33, 65):
        raise ValueError(
            f"Invalid public key length {len(pubkey)} in {context}: "
            "expected 33 (compressed) or 65 (uncompressed)"
        )


# ---------------------------------------------------------------------------
# Script type detection helpers
# ---------------------------------------------------------------------------

def _is_p2pkh(script: Script) -> bool:
    """OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG"""
    s = script.script
    return (
        len(s) == 5
        and s[0] == "OP_DUP"
        and s[1] == "OP_HASH160"
        and isinstance(s[2], str) and len(s[2]) == 40
        and s[3] == "OP_EQUALVERIFY"
        and s[4] == "OP_CHECKSIG"
    )


def _is_p2sh(script: Script) -> bool:
    """OP_HASH160 <20-byte-hash> OP_EQUAL"""
    s = script.script
    return (
        len(s) == 3
        and s[0] == "OP_HASH160"
        and isinstance(s[1], str) and len(s[1]) == 40
        and s[2] == "OP_EQUAL"
    )


def _is_p2wpkh(script: Script) -> bool:
    """OP_0 <20-byte-hash>"""
    s = script.script
    return (
        len(s) == 2
        and s[0] == "OP_0"
        and isinstance(s[1], str) and len(s[1]) == 40
    )


def _is_p2wsh(script: Script) -> bool:
    """OP_0 <32-byte-hash>"""
    s = script.script
    return (
        len(s) == 2
        and s[0] == "OP_0"
        and isinstance(s[1], str) and len(s[1]) == 64
    )


def _is_p2tr(script: Script) -> bool:
    """OP_1 <32-byte-key>"""
    s = script.script
    return (
        len(s) == 2
        and s[0] == "OP_1"
        and isinstance(s[1], str) and len(s[1]) == 64
    )


# Map OP_n strings to integer n
_OP_N_MAP = {f"OP_{i}": i for i in range(1, 17)}


def _parse_multisig(script: Script):
    """Parse a bare multisig script.

    Returns (m, n, [pubkey_hex_strings]) or None if not multisig.
    """
    s = script.script
    if len(s) < 4:
        return None
    if s[-1] != "OP_CHECKMULTISIG":
        return None
    m_op = s[0]
    n_op = s[-2]
    m = _OP_N_MAP.get(m_op)
    n = _OP_N_MAP.get(n_op)
    if m is None or n is None:
        return None
    pubkeys = s[1:-2]
    if len(pubkeys) != n:
        return None
    return (m, n, pubkeys)


def _read_compact_size_from_stream(stream: BytesIO) -> int:
    """Read a compact size integer from a BytesIO stream."""
    first = stream.read(1)
    if len(first) == 0:
        raise ValueError("Unexpected end of stream reading compact size")
    fb = first[0]
    if fb < 0xFD:
        return fb
    elif fb == 0xFD:
        return struct.unpack("<H", stream.read(2))[0]
    elif fb == 0xFE:
        return struct.unpack("<I", stream.read(4))[0]
    else:
        return struct.unpack("<Q", stream.read(8))[0]


def _read_kv_pair(stream: BytesIO):
    """Read a key-value pair from PSBT stream.

    Returns (key_bytes, value_bytes) or None if separator (0x00) encountered.
    """
    key_len = _read_compact_size_from_stream(stream)
    if key_len == 0:
        return None
    key_data = stream.read(key_len)
    if len(key_data) != key_len:
        raise ValueError("Truncated PSBT key data")
    value_len = _read_compact_size_from_stream(stream)
    value_data = stream.read(value_len)
    if len(value_data) != value_len:
        raise ValueError("Truncated PSBT value data")
    return (key_data, value_data)


def _write_kv(key_type: int, key_data: bytes, value: bytes) -> bytes:
    """Serialize a single PSBT key-value pair."""
    key = bytes([key_type]) + key_data
    return encode_varint(len(key)) + key + encode_varint(len(value)) + value


def _write_kv_simple(key_type: int, value: bytes) -> bytes:
    """Serialize a key-value pair where the key is just the type byte."""
    key = bytes([key_type])
    return encode_varint(len(key)) + key + encode_varint(len(value)) + value


# ---------------------------------------------------------------------------
# PSBTInput / PSBTOutput data containers
# ---------------------------------------------------------------------------

class PSBTInput:
    """Data associated with a single PSBT input."""

    def __init__(self):
        self.non_witness_utxo: Optional[Transaction] = None
        self.witness_utxo: Optional[TxOutput] = None
        self.partial_sigs: dict[bytes, bytes] = {}  # pubkey -> sig
        self.sighash_type: Optional[int] = None
        self.redeem_script: Optional[Script] = None
        self.witness_script: Optional[Script] = None
        self.bip32_derivs: dict[bytes, tuple[bytes, list[int]]] = {}
        self.final_scriptsig: Optional[Script] = None
        self.final_scriptwitness: Optional[list[bytes]] = None
        self.unknown: dict[bytes, bytes] = {}


class PSBTOutput:
    """Data associated with a single PSBT output."""

    def __init__(self):
        self.redeem_script: Optional[Script] = None
        self.witness_script: Optional[Script] = None
        self.bip32_derivs: dict[bytes, tuple[bytes, list[int]]] = {}
        self.unknown: dict[bytes, bytes] = {}


# ---------------------------------------------------------------------------
# Main PSBT class
# ---------------------------------------------------------------------------

class PSBT:
    """BIP-174 Partially Signed Bitcoin Transaction (version 0).

    Attributes
    ----------
    tx : Transaction
        The unsigned transaction (no scriptSigs, no segwit flag).
    inputs : list[PSBTInput]
        Per-input metadata, partial signatures, etc.
    outputs : list[PSBTOutput]
        Per-output metadata.
    unknown_global : dict[bytes, bytes]
        Unknown global key-value pairs.
    """

    def __init__(self, tx: Transaction):
        # Deep copy and strip scriptSigs / segwit data
        self.tx = Transaction.copy(tx)
        for inp in self.tx.inputs:
            inp.script_sig = Script([])
        self.tx.has_segwit = False
        self.tx.witnesses = []

        self.inputs: list[PSBTInput] = [PSBTInput() for _ in self.tx.inputs]
        self.outputs: list[PSBTOutput] = [PSBTOutput() for _ in self.tx.outputs]
        self.unknown_global: dict[bytes, bytes] = {}

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Serialize this PSBT to binary format."""
        result = PSBT_MAGIC

        # --- Global map ---
        # Unsigned transaction (non-segwit serialization)
        tx_bytes = self.tx.to_bytes(False)
        result += _write_kv_simple(PSBT_GLOBAL_UNSIGNED_TX, tx_bytes)
        for k, v in self.unknown_global.items():
            result += encode_varint(len(k)) + k + encode_varint(len(v)) + v
        result += b"\x00"  # separator

        # --- Input maps ---
        for psi in self.inputs:
            result += self._serialize_input(psi)
            result += b"\x00"  # separator

        # --- Output maps ---
        for pso in self.outputs:
            result += self._serialize_output(pso)
            result += b"\x00"  # separator

        return result

    @staticmethod
    def _serialize_input(psi: PSBTInput) -> bytes:
        data = b""
        if psi.non_witness_utxo is not None:
            tx_bytes = psi.non_witness_utxo.to_bytes(psi.non_witness_utxo.has_segwit)
            data += _write_kv_simple(PSBT_IN_NON_WITNESS_UTXO, tx_bytes)
        if psi.witness_utxo is not None:
            data += _write_kv_simple(PSBT_IN_WITNESS_UTXO, psi.witness_utxo.to_bytes())
        for pubkey, sig in psi.partial_sigs.items():
            data += _write_kv(PSBT_IN_PARTIAL_SIG, pubkey, sig)
        if psi.sighash_type is not None:
            data += _write_kv_simple(
                PSBT_IN_SIGHASH_TYPE, struct.pack("<I", psi.sighash_type)
            )
        if psi.redeem_script is not None:
            data += _write_kv_simple(PSBT_IN_REDEEM_SCRIPT, psi.redeem_script.to_bytes())
        if psi.witness_script is not None:
            data += _write_kv_simple(
                PSBT_IN_WITNESS_SCRIPT, psi.witness_script.to_bytes()
            )
        for pubkey, (fp, path) in psi.bip32_derivs.items():
            value = fp
            for idx in path:
                value += struct.pack("<I", idx)
            data += _write_kv(PSBT_IN_BIP32_DERIVATION, pubkey, value)
        if psi.final_scriptsig is not None:
            data += _write_kv_simple(
                PSBT_IN_FINAL_SCRIPTSIG, psi.final_scriptsig.to_bytes()
            )
        if psi.final_scriptwitness is not None:
            wit_data = encode_varint(len(psi.final_scriptwitness))
            for item in psi.final_scriptwitness:
                wit_data += encode_varint(len(item)) + item
            data += _write_kv_simple(PSBT_IN_FINAL_SCRIPTWITNESS, wit_data)
        for k, v in psi.unknown.items():
            data += encode_varint(len(k)) + k + encode_varint(len(v)) + v
        return data

    @staticmethod
    def _serialize_output(pso: PSBTOutput) -> bytes:
        data = b""
        if pso.redeem_script is not None:
            data += _write_kv_simple(PSBT_OUT_REDEEM_SCRIPT, pso.redeem_script.to_bytes())
        if pso.witness_script is not None:
            data += _write_kv_simple(
                PSBT_OUT_WITNESS_SCRIPT, pso.witness_script.to_bytes()
            )
        for pubkey, (fp, path) in pso.bip32_derivs.items():
            value = fp
            for idx in path:
                value += struct.pack("<I", idx)
            data += _write_kv(PSBT_OUT_BIP32_DERIVATION, pubkey, value)
        for k, v in pso.unknown.items():
            data += encode_varint(len(k)) + k + encode_varint(len(v)) + v
        return data

    def to_base64(self) -> str:
        """Serialize to base64 string."""
        return base64.b64encode(self.to_bytes()).decode("ascii")

    def to_hex(self) -> str:
        """Serialize to hex string."""
        return b_to_h(self.to_bytes())

    # ------------------------------------------------------------------
    # Deserialization
    # ------------------------------------------------------------------

    @classmethod
    def from_bytes(cls, data: bytes) -> "PSBT":
        """Deserialize a PSBT from raw bytes."""
        if data[:5] != PSBT_MAGIC:
            raise ValueError("Invalid PSBT magic bytes")
        stream = BytesIO(data[5:])

        # --- Global map ---
        unsigned_tx = None
        unknown_global: dict[bytes, bytes] = {}
        seen_global_keys: set[bytes] = set()

        while True:
            kv = _read_kv_pair(stream)
            if kv is None:
                break
            key_data, value_data = kv
            if key_data in seen_global_keys:
                raise ValueError("Duplicate key in global map")
            seen_global_keys.add(key_data)

            key_type = key_data[0]
            if key_type == PSBT_GLOBAL_UNSIGNED_TX:
                if len(key_data) != 1:
                    raise ValueError(
                        "Invalid global unsigned tx key: must be single byte"
                    )
                # Detect witness serialization: version(4) + marker(0x00) + flag(0x01)
                if len(value_data) >= 6 and value_data[4:6] == b"\x00\x01":
                    raise ValueError(
                        "PSBT unsigned tx must not use witness serialization"
                    )
                unsigned_tx = Transaction.from_raw(value_data)
                unsigned_tx.has_segwit = False
                unsigned_tx.witnesses = []
            else:
                unknown_global[key_data] = value_data

        if unsigned_tx is None:
            raise ValueError("PSBT missing global unsigned transaction")

        # Verify the unsigned tx has no scriptSigs
        for inp in unsigned_tx.inputs:
            if inp.script_sig.script:
                raise ValueError(
                    "PSBT global unsigned tx must have empty scriptSigs"
                )

        # Build PSBT object (bypassing __init__ to avoid re-copying)
        psbt = object.__new__(cls)
        psbt.tx = unsigned_tx
        psbt.unknown_global = unknown_global
        psbt.inputs = []
        psbt.outputs = []

        # --- Input maps ---
        for inp_idx in range(len(unsigned_tx.inputs)):
            psi = PSBTInput()
            seen_keys: set[bytes] = set()
            while True:
                kv = _read_kv_pair(stream)
                if kv is None:
                    break
                key_data, value_data = kv
                if key_data in seen_keys:
                    raise ValueError(
                        f"Duplicate key in input {inp_idx}"
                    )
                seen_keys.add(key_data)
                key_type = key_data[0]
                cls._parse_input_kv(psi, key_type, key_data, value_data)
            psbt.inputs.append(psi)

        # --- Output maps ---
        for out_idx in range(len(unsigned_tx.outputs)):
            pso = PSBTOutput()
            seen_keys = set()
            while True:
                kv = _read_kv_pair(stream)
                if kv is None:
                    break
                key_data, value_data = kv
                if key_data in seen_keys:
                    raise ValueError(
                        f"Duplicate key in output {out_idx}"
                    )
                seen_keys.add(key_data)
                key_type = key_data[0]
                cls._parse_output_kv(pso, key_type, key_data, value_data)
            psbt.outputs.append(pso)

        return psbt

    @staticmethod
    def _parse_input_kv(
        psi: PSBTInput, key_type: int, key_data: bytes, value_data: bytes
    ):
        # Validate key format for known types
        if key_type in _KNOWN_INPUT_SINGLE_BYTE_KEYS:
            if len(key_data) != 1:
                raise ValueError(
                    f"Input key type 0x{key_type:02x} must be a single byte, "
                    f"got {len(key_data)} bytes"
                )
        if key_type in _KNOWN_INPUT_PUBKEY_KEYS:
            _validate_pubkey_length(
                key_data[1:], f"input key type 0x{key_type:02x}"
            )

        if key_type == PSBT_IN_NON_WITNESS_UTXO and len(key_data) == 1:
            psi.non_witness_utxo = Transaction.from_raw(value_data)
        elif key_type == PSBT_IN_WITNESS_UTXO and len(key_data) == 1:
            psi.witness_utxo = TxOutput.from_raw(value_data, 0)[0]
        elif key_type == PSBT_IN_PARTIAL_SIG:
            pubkey = key_data[1:]  # strip key type byte
            psi.partial_sigs[pubkey] = value_data
        elif key_type == PSBT_IN_SIGHASH_TYPE and len(key_data) == 1:
            psi.sighash_type = struct.unpack("<I", value_data)[0]
        elif key_type == PSBT_IN_REDEEM_SCRIPT and len(key_data) == 1:
            psi.redeem_script = Script.from_raw(value_data)
        elif key_type == PSBT_IN_WITNESS_SCRIPT and len(key_data) == 1:
            psi.witness_script = Script.from_raw(value_data)
        elif key_type == PSBT_IN_BIP32_DERIVATION:
            pubkey = key_data[1:]
            fingerprint = value_data[:4]
            path = []
            for i in range(4, len(value_data), 4):
                path.append(struct.unpack("<I", value_data[i : i + 4])[0])
            psi.bip32_derivs[pubkey] = (fingerprint, path)
        elif key_type == PSBT_IN_FINAL_SCRIPTSIG and len(key_data) == 1:
            psi.final_scriptsig = Script.from_raw(value_data)
        elif key_type == PSBT_IN_FINAL_SCRIPTWITNESS and len(key_data) == 1:
            wit_stream = BytesIO(value_data)
            num_items = _read_compact_size_from_stream(wit_stream)
            items = []
            for _ in range(num_items):
                item_len = _read_compact_size_from_stream(wit_stream)
                items.append(wit_stream.read(item_len))
            psi.final_scriptwitness = items
        else:
            psi.unknown[key_data] = value_data

    @staticmethod
    def _parse_output_kv(
        pso: PSBTOutput, key_type: int, key_data: bytes, value_data: bytes
    ):
        # Validate key format for known types
        if key_type in _KNOWN_OUTPUT_SINGLE_BYTE_KEYS:
            if len(key_data) != 1:
                raise ValueError(
                    f"Output key type 0x{key_type:02x} must be a single byte, "
                    f"got {len(key_data)} bytes"
                )
        if key_type in _KNOWN_OUTPUT_PUBKEY_KEYS:
            _validate_pubkey_length(
                key_data[1:], f"output key type 0x{key_type:02x}"
            )

        if key_type == PSBT_OUT_REDEEM_SCRIPT and len(key_data) == 1:
            pso.redeem_script = Script.from_raw(value_data)
        elif key_type == PSBT_OUT_WITNESS_SCRIPT and len(key_data) == 1:
            pso.witness_script = Script.from_raw(value_data)
        elif key_type == PSBT_OUT_BIP32_DERIVATION:
            pubkey = key_data[1:]
            fingerprint = value_data[:4]
            path = []
            for i in range(4, len(value_data), 4):
                path.append(struct.unpack("<I", value_data[i : i + 4])[0])
            pso.bip32_derivs[pubkey] = (fingerprint, path)
        else:
            pso.unknown[key_data] = value_data

    @classmethod
    def from_base64(cls, b64_str: str) -> "PSBT":
        """Deserialize a PSBT from a base64 string."""
        return cls.from_bytes(base64.b64decode(b64_str))

    @classmethod
    def from_hex(cls, hex_str: str) -> "PSBT":
        """Deserialize a PSBT from a hex string."""
        return cls.from_bytes(h_to_b(hex_str))

    # ------------------------------------------------------------------
    # Updater
    # ------------------------------------------------------------------

    def update_input(
        self,
        index: int,
        non_witness_utxo: Optional[Transaction] = None,
        witness_utxo: Optional[TxOutput] = None,
        redeem_script: Optional[Script] = None,
        witness_script: Optional[Script] = None,
        sighash_type: Optional[int] = None,
        bip32_derivs: Optional[dict[bytes, tuple[bytes, list[int]]]] = None,
    ):
        """Add UTXO and script metadata for an input."""
        psi = self.inputs[index]
        if non_witness_utxo is not None:
            psi.non_witness_utxo = non_witness_utxo
        if witness_utxo is not None:
            psi.witness_utxo = witness_utxo
        if redeem_script is not None:
            psi.redeem_script = redeem_script
        if witness_script is not None:
            psi.witness_script = witness_script
        if sighash_type is not None:
            psi.sighash_type = sighash_type
        if bip32_derivs is not None:
            psi.bip32_derivs.update(bip32_derivs)

    def update_output(
        self,
        index: int,
        redeem_script: Optional[Script] = None,
        witness_script: Optional[Script] = None,
        bip32_derivs: Optional[dict[bytes, tuple[bytes, list[int]]]] = None,
    ):
        """Add script metadata for an output."""
        pso = self.outputs[index]
        if redeem_script is not None:
            pso.redeem_script = redeem_script
        if witness_script is not None:
            pso.witness_script = witness_script
        if bip32_derivs is not None:
            pso.bip32_derivs.update(bip32_derivs)

    # ------------------------------------------------------------------
    # Signer
    # ------------------------------------------------------------------

    def sign_input(self, input_index: int, private_key, sighash: int = SIGHASH_ALL) -> bool:
        """Sign a PSBT input using the library's signing methods.

        Parameters
        ----------
        input_index : int
            Index of the input to sign.
        private_key : PrivateKey
            The private key to sign with.
        sighash : int
            Sighash type (default SIGHASH_ALL).

        Returns
        -------
        bool
            True if a signature was produced.
        """
        psi = self.inputs[input_index]
        pubkey_hex = private_key.get_public_key().to_hex(compressed=True)
        pubkey_bytes = h_to_b(pubkey_hex)

        # Determine the script type and sign accordingly
        script_pubkey = self._get_script_pubkey(input_index)
        if script_pubkey is None:
            raise ValueError(
                f"Cannot determine scriptPubKey for input {input_index}. "
                "Provide non_witness_utxo or witness_utxo."
            )

        sig_hex = None

        if _is_p2pkh(script_pubkey):
            sig_hex = private_key.sign_input(self.tx, input_index, script_pubkey, sighash)

        elif _is_p2wpkh(script_pubkey):
            amount = self._get_witness_amount(input_index)
            p2pkh_script = self._p2wpkh_to_p2pkh_script(script_pubkey)
            sig_hex = private_key.sign_segwit_input(
                self.tx, input_index, p2pkh_script, amount, sighash
            )

        elif _is_p2sh(script_pubkey):
            # Could be P2SH-P2WPKH, P2SH-P2WSH, or P2SH legacy
            redeem = psi.redeem_script
            if redeem is None:
                raise ValueError(
                    f"P2SH input {input_index} requires redeem_script"
                )
            if _is_p2wpkh(redeem):
                # P2SH-P2WPKH
                amount = self._get_witness_amount(input_index)
                p2pkh_script = self._p2wpkh_to_p2pkh_script(redeem)
                sig_hex = private_key.sign_segwit_input(
                    self.tx, input_index, p2pkh_script, amount, sighash
                )
            elif _is_p2wsh(redeem):
                # P2SH-P2WSH
                ws = psi.witness_script
                if ws is None:
                    raise ValueError(
                        f"P2SH-P2WSH input {input_index} requires witness_script"
                    )
                amount = self._get_witness_amount(input_index)
                sig_hex = private_key.sign_segwit_input(
                    self.tx, input_index, ws, amount, sighash
                )
            else:
                # Legacy P2SH
                sig_hex = private_key.sign_input(
                    self.tx, input_index, redeem, sighash
                )

        elif _is_p2wsh(script_pubkey):
            ws = psi.witness_script
            if ws is None:
                raise ValueError(
                    f"P2WSH input {input_index} requires witness_script"
                )
            amount = self._get_witness_amount(input_index)
            sig_hex = private_key.sign_segwit_input(
                self.tx, input_index, ws, amount, sighash
            )

        else:
            raise ValueError(
                f"Unsupported script type for input {input_index}"
            )

        if sig_hex is not None:
            psi.partial_sigs[pubkey_bytes] = h_to_b(sig_hex)
            return True
        return False

    def _get_script_pubkey(self, input_index: int) -> Optional[Script]:
        """Get the scriptPubKey for the given input from UTXO data."""
        psi = self.inputs[input_index]
        if psi.witness_utxo is not None:
            return psi.witness_utxo.script_pubkey
        if psi.non_witness_utxo is not None:
            txin = self.tx.inputs[input_index]
            prev_tx = psi.non_witness_utxo
            return prev_tx.outputs[txin.txout_index].script_pubkey
        return None

    def _get_witness_amount(self, input_index: int) -> int:
        """Get the amount for segwit signing."""
        psi = self.inputs[input_index]
        if psi.witness_utxo is not None:
            return psi.witness_utxo.amount
        if psi.non_witness_utxo is not None:
            txin = self.tx.inputs[input_index]
            return psi.non_witness_utxo.outputs[txin.txout_index].amount
        raise ValueError(f"No UTXO data for input {input_index}")

    @staticmethod
    def _p2wpkh_to_p2pkh_script(wpkh_script: Script) -> Script:
        """Convert a P2WPKH scriptPubKey to P2PKH-equivalent for segwit signing."""
        keyhash = wpkh_script.script[1]
        return Script(["OP_DUP", "OP_HASH160", keyhash, "OP_EQUALVERIFY", "OP_CHECKSIG"])

    # ------------------------------------------------------------------
    # Combiner
    # ------------------------------------------------------------------

    def combine(self, other: "PSBT") -> "PSBT":
        """Combine this PSBT with another, returning a new merged PSBT.

        Both PSBTs must have the same unsigned transaction.
        """
        if self.tx.to_bytes(False) != other.tx.to_bytes(False):
            raise ValueError("Cannot combine PSBTs with different unsigned transactions")

        combined = PSBT(self.tx)
        combined.unknown_global = {**self.unknown_global, **other.unknown_global}

        for i in range(len(self.inputs)):
            dst = combined.inputs[i]
            for src in (self.inputs[i], other.inputs[i]):
                if src.non_witness_utxo is not None:
                    dst.non_witness_utxo = src.non_witness_utxo
                if src.witness_utxo is not None:
                    dst.witness_utxo = src.witness_utxo
                dst.partial_sigs.update(src.partial_sigs)
                if src.sighash_type is not None:
                    dst.sighash_type = src.sighash_type
                if src.redeem_script is not None:
                    dst.redeem_script = src.redeem_script
                if src.witness_script is not None:
                    dst.witness_script = src.witness_script
                dst.bip32_derivs.update(src.bip32_derivs)
                if src.final_scriptsig is not None:
                    dst.final_scriptsig = src.final_scriptsig
                if src.final_scriptwitness is not None:
                    dst.final_scriptwitness = src.final_scriptwitness
                dst.unknown.update(src.unknown)

        for i in range(len(self.outputs)):
            dst = combined.outputs[i]
            for src in (self.outputs[i], other.outputs[i]):
                if src.redeem_script is not None:
                    dst.redeem_script = src.redeem_script
                if src.witness_script is not None:
                    dst.witness_script = src.witness_script
                dst.bip32_derivs.update(src.bip32_derivs)
                dst.unknown.update(src.unknown)

        return combined

    # ------------------------------------------------------------------
    # Finalizer
    # ------------------------------------------------------------------

    def finalize_input(self, input_index: int):
        """Finalize a single input, constructing final scriptSig / witness."""
        psi = self.inputs[input_index]

        # Already finalized?
        if psi.final_scriptsig is not None or psi.final_scriptwitness is not None:
            return

        script_pubkey = self._get_script_pubkey(input_index)
        if script_pubkey is None:
            raise ValueError(f"Cannot determine script type for input {input_index}")

        if _is_p2pkh(script_pubkey):
            self._finalize_p2pkh(psi)
        elif _is_p2wpkh(script_pubkey):
            self._finalize_p2wpkh(psi)
        elif _is_p2sh(script_pubkey):
            redeem = psi.redeem_script
            if redeem is None:
                raise ValueError("P2SH input requires redeem_script for finalization")
            if _is_p2wpkh(redeem):
                self._finalize_p2sh_p2wpkh(psi)
            elif _is_p2wsh(redeem):
                self._finalize_p2sh_p2wsh(psi)
            else:
                self._finalize_p2sh_legacy(psi)
        elif _is_p2wsh(script_pubkey):
            self._finalize_p2wsh(psi)
        else:
            raise ValueError("Unsupported script type for finalization")

        # Clear non-final fields after finalization
        psi.partial_sigs = {}
        psi.sighash_type = None
        psi.redeem_script = None
        psi.witness_script = None
        psi.bip32_derivs = {}

    def finalize(self):
        """Finalize all inputs."""
        for i in range(len(self.inputs)):
            self.finalize_input(i)

    @staticmethod
    def _finalize_p2pkh(psi: PSBTInput):
        if len(psi.partial_sigs) != 1:
            raise ValueError("P2PKH finalization requires exactly one signature")
        pubkey, sig = next(iter(psi.partial_sigs.items()))
        psi.final_scriptsig = Script([b_to_h(sig), b_to_h(pubkey)])

    @staticmethod
    def _finalize_p2wpkh(psi: PSBTInput):
        if len(psi.partial_sigs) != 1:
            raise ValueError("P2WPKH finalization requires exactly one signature")
        pubkey, sig = next(iter(psi.partial_sigs.items()))
        psi.final_scriptsig = Script([])
        psi.final_scriptwitness = [sig, pubkey]

    @staticmethod
    def _finalize_p2sh_p2wpkh(psi: PSBTInput):
        if len(psi.partial_sigs) != 1:
            raise ValueError("P2SH-P2WPKH finalization requires exactly one signature")
        pubkey, sig = next(iter(psi.partial_sigs.items()))
        psi.final_scriptsig = Script([psi.redeem_script.to_hex()])
        psi.final_scriptwitness = [sig, pubkey]

    @staticmethod
    def _finalize_p2wsh(psi: PSBTInput):
        ws = psi.witness_script
        if ws is None:
            raise ValueError("P2WSH finalization requires witness_script")
        ms = _parse_multisig(ws)
        if ms is None:
            raise ValueError("P2WSH finalization currently only supports multisig")
        m, n, script_pubkeys = ms
        ordered_sigs = _order_sigs_for_multisig(psi.partial_sigs, script_pubkeys, m)
        psi.final_scriptsig = Script([])
        psi.final_scriptwitness = [b""] + ordered_sigs + [ws.to_bytes()]

    @staticmethod
    def _finalize_p2sh_p2wsh(psi: PSBTInput):
        ws = psi.witness_script
        if ws is None:
            raise ValueError("P2SH-P2WSH finalization requires witness_script")
        ms = _parse_multisig(ws)
        if ms is None:
            raise ValueError("P2SH-P2WSH finalization currently only supports multisig")
        m, n, script_pubkeys = ms
        ordered_sigs = _order_sigs_for_multisig(psi.partial_sigs, script_pubkeys, m)
        psi.final_scriptsig = Script([psi.redeem_script.to_hex()])
        psi.final_scriptwitness = [b""] + ordered_sigs + [ws.to_bytes()]

    @staticmethod
    def _finalize_p2sh_legacy(psi: PSBTInput):
        rs = psi.redeem_script
        if rs is None:
            raise ValueError("P2SH finalization requires redeem_script")
        ms = _parse_multisig(rs)
        if ms is not None:
            m, n, script_pubkeys = ms
            ordered_sigs = _order_sigs_for_multisig(psi.partial_sigs, script_pubkeys, m)
            sig_hexes = [b_to_h(s) for s in ordered_sigs]
            psi.final_scriptsig = Script(["OP_0"] + sig_hexes + [rs.to_hex()])
        elif len(psi.partial_sigs) == 1:
            pubkey, sig = next(iter(psi.partial_sigs.items()))
            psi.final_scriptsig = Script([b_to_h(sig), b_to_h(pubkey), rs.to_hex()])
        else:
            raise ValueError("Cannot finalize P2SH input: unsupported script pattern")

    # ------------------------------------------------------------------
    # Extractor
    # ------------------------------------------------------------------

    def extract_transaction(self) -> Transaction:
        """Extract the fully signed transaction.

        Returns
        -------
        Transaction
            The complete, signed transaction ready for broadcast.
        """
        has_witness = False
        for psi in self.inputs:
            if psi.final_scriptsig is None and psi.final_scriptwitness is None:
                raise ValueError(
                    "Cannot extract: not all inputs are finalized"
                )
            if psi.final_scriptwitness is not None:
                has_witness = True

        inputs = []
        for i, txin in enumerate(self.tx.inputs):
            new_in = TxInput(txin.txid, txin.txout_index, sequence=txin.sequence)
            psi = self.inputs[i]
            if psi.final_scriptsig is not None:
                new_in.script_sig = psi.final_scriptsig
            inputs.append(new_in)

        outputs = [TxOutput(txout.amount, txout.script_pubkey) for txout in self.tx.outputs]

        witnesses = []
        if has_witness:
            for i in range(len(inputs)):
                psi = self.inputs[i]
                if psi.final_scriptwitness is not None:
                    stack = [b_to_h(item) for item in psi.final_scriptwitness]
                    witnesses.append(TxWitnessInput(stack))
                else:
                    witnesses.append(TxWitnessInput([]))

        return Transaction(
            inputs=inputs,
            outputs=outputs,
            locktime=self.tx.locktime,
            version=self.tx.version,
            has_segwit=has_witness,
            witnesses=witnesses,
        )


def _order_sigs_for_multisig(
    partial_sigs: dict[bytes, bytes],
    script_pubkeys: list[str],
    m: int,
) -> list[bytes]:
    """Order partial signatures to match the pubkey order in a multisig script.

    Returns m signatures ordered by their pubkey position in the script.
    """
    ordered = []
    for pk_hex in script_pubkeys:
        pk_bytes = h_to_b(pk_hex)
        if pk_bytes in partial_sigs:
            ordered.append(partial_sigs[pk_bytes])
    if len(ordered) < m:
        raise ValueError(
            f"Not enough signatures for multisig: have {len(ordered)}, need {m}"
        )
    return ordered[:m]

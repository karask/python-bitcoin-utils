"""
psbt.py
=======
This module defines classes for handling Partially Signed Bitcoin Transactions (PSBTs).

Classes:
  - PSBTMap: Base class for PSBT key-value maps.
  - PSBTInput: Represents an input map of a PSBT.
  - PSBTOutput: Represents an output map of a PSBT.
  - PSBT: The main class for parsing, serializing, finalizing, and extracting PSBTs.

This module relies on helper functions and validators from psbt_utils.py.
"""

import binascii
from io import BytesIO
from bitcoinutils.transactions import Transaction  
from bitcoinutils.script import Script 
from bitcoinutils.psbt_utils import (
    read_key_value_pair, write_key_value_pair, encode_varint,
    ALLOWED_INPUT_VALIDATORS, ALLOWED_OUTPUT_VALIDATORS, ALLOWED_GLOBAL_VALIDATORS,
    build_push_script, encode_witness_stack, decode_witness_stack,is_valid_pubkey 
)

class PSBTMap:
    """
    Base class for PSBT key-value maps.

    Provides functions for parsing, serializing, and validating key-value pairs.
    """
    def __init__(self):
        self.map = {}

    def parse(self, stream: BytesIO) -> None:
        """
        Parse PSBT key-value pairs from a stream.

        Args:
            stream: A BytesIO stream containing PSBT key-value pairs.

        Raises:
            ValueError: If duplicate keys are encountered.
        """
        while True:
            key, value = read_key_value_pair(stream)
            if key is None:
                break
            if key in self.map:
                raise ValueError(f"Duplicate key found in PSBT map: {key.hex()}")
            self.map[key] = value

    def serialize(self) -> bytes:
        """
        Serialize the PSBT map to bytes.

        Returns:
            The serialized key-value map as bytes.
        """
        data = b""
        for k, v in self.map.items():
            data += write_key_value_pair(k, v)
        data += b"\x00"  # Map delimiter
        return data

    def validate_keys(self, allowed_validators: dict, key_type_name: str = "map") -> bool:
        """
        Validate keys in the map using allowed validators.

        Args:
            allowed_validators: Dictionary mapping key prefixes to validator functions.
            key_type_name: Description of the map (e.g., 'input map').

        Returns:
            True if all keys are valid.

        Raises:
            ValueError: If any key fails validation.
        """
        for k, v in self.map.items():
            base = k[:1]
            if base in {b"\x02", b"\x06"} and len(k) <= 1:
                raise ValueError(f"Invalid {key_type_name} key: {k.hex()} (expected pubkey appended)")
            if base in allowed_validators:
                allowed_validators[base](k, v)
        return True

class PSBTInput(PSBTMap):
    """
    Represents a PSBT input map.

    Contains methods for setting UTXO data, redeem/witness scripts, partial signatures,
    and checking if the input is finalized.
    """
    def add_partial_signature(self, pubkey: bytes, signature: bytes) -> None:
        """
        Add a partial signature for the given public key.

        Args:
            pubkey: The public key (bytes).
            signature: The signature (bytes).

        Raises:
            ValueError: If a signature for this pubkey already exists or if the pubkey is invalid.
        """
        key = b"\x02" + pubkey
        if key in self.map:
            raise ValueError("Duplicate partial signature key found.")
        
        if not is_valid_pubkey(pubkey):
            raise ValueError(f"Invalid pubkey length for partial signature: {pubkey.hex()}")
        self.map[key] = signature

    def get_partial_signatures(self) -> dict:
        """
        Retrieve all partial signatures.

        Returns:
            A dictionary mapping pubkeys (without prefix) to signatures.
        """
        sigs = {}
        for k, v in self.map.items():
            if k.startswith(b"\x02"):
                sigs[k[1:]] = v
        return sigs

    def set_non_witness_utxo(self, tx_bytes: bytes) -> None:
        """Set the non-witness UTXO data."""
        self.map[b"\x00"] = tx_bytes

    def get_non_witness_utxo(self) -> bytes:
        """Get the non-witness UTXO data."""
        return self.map.get(b"\x00")

    def set_witness_utxo(self, tx_out_bytes: bytes) -> None:
        """Set the witness UTXO data."""
        self.map[b"\x01"] = tx_out_bytes

    def get_witness_utxo(self) -> bytes:
        """Get the witness UTXO data."""
        return self.map.get(b"\x01")

    def set_redeem_script(self, script_bytes: bytes) -> None:
        """Set the redeem script."""
        self.map[b"\x04"] = script_bytes

    def get_redeem_script(self) -> bytes:
        """Get the redeem script."""
        return self.map.get(b"\x04")

    def set_witness_script(self, script_bytes: bytes) -> None:
        """Set the witness script."""
        self.map[b"\x05"] = script_bytes

    def get_witness_script(self) -> bytes:
        """Get the witness script."""
        return self.map.get(b"\x05")

    def set_bip32_derivation(self, pubkey: bytes, derivation_path: bytes) -> None:
        """Set BIP32 derivation data for the given public key."""
        self.map[b"\x06" + pubkey] = derivation_path

    def get_bip32_derivation(self, pubkey: bytes) -> bytes:
        """Get BIP32 derivation data for the given public key."""
        return self.map.get(b"\x06" + pubkey)

    def get_input_type(self) -> str:
        """
        Determine the type of the input based on available data.

        Returns:
            A string indicating the input type, e.g., 'P2PKH', 'P2SH', 'SegWit', etc.
        """
        if self.get_witness_utxo() is not None:
            if self.get_witness_script() is not None:
                return "P2WSH"
            redeem = self.get_redeem_script()
            if redeem is not None and len(redeem) == 22 and redeem[0] == 0x00:
                return "P2SH-P2WPKH"
            return "SegWit"
        else:
            if self.get_redeem_script() is not None:
                return "P2SH"
            return "P2PKH"

    def is_finalized(self) -> bool:
        """
        Check whether the input is finalized (i.e., no partial signatures remain).

        Returns:
            True if finalized, otherwise False.
        """
        for k in self.map:
            if k.startswith(b"\x02"):
                return False
        return True

    def check_signatures_completeness(self) -> bool:
        """
        Check if the input has sufficient signatures based on its redeem script.

        The redeem script's first byte (an opcode) indicates the required number of signatures
        (e.g., OP_2 means two signatures). This method compares that requirement with the number
        of partial signatures currently present.

        Returns:
            True if the input has at least the required number of signatures; otherwise False.
        """
        redeem = self.get_redeem_script()
        if redeem is None:
            return False
        op_m = redeem[0]
        if 0x51 <= op_m <= 0x60:
            m = op_m - 0x50
        else:
            return False
        sigs = self.get_partial_signatures()
        return len(sigs) >= m

    def validate_keys(self) -> bool:
        """
        Validate all keys in the input map using allowed input validators.

        Returns:
            True if validation succeeds.
        """
        return super().validate_keys(ALLOWED_INPUT_VALIDATORS, key_type_name="input map")

class PSBTOutput(PSBTMap):
    """
    Represents a PSBT output map.

    Contains methods for handling output-specific fields such as redeem scripts,
    witness scripts, and BIP32 derivation data.
    """
    def set_redeem_script(self, script_bytes: bytes) -> None:
        """Set the redeem script for this output."""
        self.map[b"\x00"] = script_bytes

    def get_redeem_script(self) -> bytes:
        """Get the redeem script for this output."""
        return self.map.get(b"\x00")

    def set_witness_script(self, script_bytes: bytes) -> None:
        """Set the witness script for this output."""
        self.map[b"\x01"] = script_bytes

    def get_witness_script(self) -> bytes:
        """Get the witness script for this output."""
        return self.map.get(b"\x01")

    def set_bip32_derivation(self, pubkey: bytes, derivation_path: bytes) -> None:
        """Set the BIP32 derivation information for this output."""
        self.map[b"\x02" + pubkey] = derivation_path

    def get_bip32_derivation(self, pubkey: bytes) -> bytes:
        """Get the BIP32 derivation information for this output."""
        return self.map.get(b"\x02" + pubkey)

    def validate_keys(self) -> bool:
        """
        Validate all keys in the output map using allowed output validators.

        Returns:
            True if validation succeeds.
        """
        return super().validate_keys(ALLOWED_OUTPUT_VALIDATORS, key_type_name="output map")

class PSBT:
    """
    Represents a Partially Signed Bitcoin Transaction (PSBT).

    Provides functionality to parse from/serialize to bytes (or hex),
    finalize inputs (constructing finalized unlocking data), extract the complete
    network-serialized transaction, and validate the PSBT structure.
    """
    MAGIC_BYTES = b"psbt\xff"

    def __init__(self):
        self.global_map = {}
        self.inputs = []
        self.outputs = []
        self.tx = None  # Underlying Transaction object

    @classmethod
    def from_hex(cls, hex_string: str) -> "PSBT":
        """
        Create a PSBT instance from a hex-encoded string.

        Args:
            hex_string: PSBT as a hex string.
        
        Returns:
            A PSBT instance.
        """
        return cls.from_bytes(binascii.unhexlify(hex_string))

    def to_hex(self) -> str:
        """
        Serialize the PSBT to a hex-encoded string.

        Returns:
            PSBT as a hex string.
        """
        return self.to_bytes().hex()

    @classmethod
    def from_bytes(cls, raw_bytes: bytes) -> "PSBT":
        """
        Parse a PSBT from its raw bytes.

        Args:
            raw_bytes: The PSBT data as bytes.
        
        Returns:
            A PSBT instance.
        
        Raises:
            ValueError: If the PSBT format is invalid.
        """
        stream = BytesIO(raw_bytes)
        magic = stream.read(5)
        if magic != cls.MAGIC_BYTES:
            raise ValueError("Invalid PSBT magic bytes (Not a PSBT format network transaction)")
        psbt = cls()
        while True:
            key, value = read_key_value_pair(stream)
            if key is None:
                break
            if key in psbt.global_map:
                raise ValueError(f"Duplicate global key: {key.hex()}")
            psbt.global_map[key] = value

        if b"\x00" not in psbt.global_map:
            raise ValueError("PSBT missing unsigned transaction (global type 0x00)")

        try:
            tx = Transaction.from_raw(psbt.global_map[b"\x00"].hex())
            if tx is None:
                raise ValueError("Invalid unsigned transaction in global map.")
            if not hasattr(tx, "inputs") or len(tx.inputs) == 0:
                raise ValueError("Unsigned transaction must have at least one input.")
            if not hasattr(tx, "outputs") or len(tx.outputs) == 0:
                raise ValueError("Unsigned transaction must have at least one output.")
        except Exception as e:
            raise ValueError("Global unsigned transaction validation error: " + str(e))

        psbt.tx = Transaction.from_raw(psbt.global_map[b"\x00"].hex())
        if psbt.tx is None:
            raise ValueError("Transaction.from_raw() returned None")

        # Ensure that inputs in the unsigned transaction do not already have unlocking data.
        for idx, txin in enumerate(psbt.tx.inputs):
            if hasattr(txin, "script_sig") and txin.script_sig and txin.script_sig.to_bytes() != b"":
                raise ValueError(f"Input #{idx} in unsigned tx already contains a scriptSig")

        # Parse each PSBT input map.
        for _ in range(len(psbt.tx.inputs)):
            psbt_input = PSBTInput()
            psbt_input.parse(stream)
            psbt_input.validate_keys()
            psbt.inputs.append(psbt_input)

        if len(psbt.tx.outputs) == 0:
            raise ValueError("PSBT missing outputs")

        # Parse each PSBT output map.
        for _ in range(len(psbt.tx.outputs)):
            psbt_output = PSBTOutput()
            psbt_output.parse(stream)
            psbt_output.validate_keys()
            psbt.outputs.append(psbt_output)

        return psbt

    def to_bytes(self) -> bytes:
        """
        Serialize the PSBT into raw bytes.

        Returns:
            The PSBT as bytes.
        """
        if b"\x00" not in self.global_map:
            raise ValueError("PSBT missing unsigned transaction (global key 0x00)")
        buffer = BytesIO()
        buffer.write(self.MAGIC_BYTES)
        for key, value in self.global_map.items():
            buffer.write(write_key_value_pair(key, value))
        buffer.write(b"\x00")
        for psbt_input in self.inputs:
            buffer.write(psbt_input.serialize())
        for psbt_output in self.outputs:
            buffer.write(psbt_output.serialize())
        return buffer.getvalue()

    def finalize(self) -> None:
        """
        Finalize each PSBT input by constructing finalized unlocking data.

        For each input with enough partial signatures, this method builds either the
        finalized scriptSig (key 0x07) or script witness (key 0x08) based on whether
        the input is SegWit. It then removes all intermediate signing fields (partial
        signatures, redeem/witness scripts, BIP32 derivations) while keeping UTXO and unknown fields.

        Raises:
            ValueError: If an input lacks required partial signatures.
        """
        for idx, psbt_input in enumerate(self.inputs):
            partials = psbt_input.get_partial_signatures()
            if not partials:
                raise ValueError(f"Input {idx} has no partial signatures to finalize.")

            redeem_script = psbt_input.get_redeem_script()
            is_multisig = redeem_script is not None
            is_segwit = (psbt_input.get_witness_utxo() is not None) or (hasattr(self.tx, "has_segwit") and self.tx.has_segwit)

            finalized_scriptsig = b""
            finalized_scriptwitness = b""

            if is_multisig:
                if not redeem_script:
                    raise ValueError(f"Input {idx} multisig missing redeem script.")
                if len(partials) == 0:
                    raise ValueError(f"Input {idx} multisig has no partial signatures.")
                if is_segwit:
                    # Build witness stack: dummy element, each signature, then redeem script.
                    witness_stack = [b""]
                    for pub, sig in partials.items():
                        witness_stack.append(sig)
                    witness_stack.append(redeem_script)
                    finalized_scriptwitness = encode_witness_stack(witness_stack)
                else:
                    # For non-segwit multisig, build scriptSig: OP_0 followed by signatures and redeem script.
                    script_parts = [b"\x00"] + list(partials.values()) + [redeem_script]
                    finalized_scriptsig = build_push_script(script_parts)
            else:
                # Single signature: expect exactly one partial signature.
                if len(partials) != 1:
                    raise ValueError(f"Input {idx} expected 1 partial signature for single-sig, got {len(partials)}")
                pubkey, signature = list(partials.items())[0]
                if is_segwit:
                    finalized_scriptwitness = encode_witness_stack([signature, pubkey])
                else:
                    finalized_scriptsig = build_push_script([signature, pubkey])

            # Add finalized fields if non-empty.
            if finalized_scriptsig:
                psbt_input.map[b"\x07"] = finalized_scriptsig
            if finalized_scriptwitness:
                psbt_input.map[b"\x08"] = finalized_scriptwitness

            # Remove intermediate keys (partial sigs, sighash, redeem/witness scripts, BIP32) while retaining UTXO/unknown fields.
            keys_to_remove = []
            for k in list(psbt_input.map.keys()):
                base = k[:1]
                if base in {b"\x02", b"\x03", b"\x04", b"\x05", b"\x06"}:
                    keys_to_remove.append(k)
            for k in keys_to_remove:
                del psbt_input.map[k]

    def extract_transaction(self) -> bytes:
        """
        Extract and return the finalized, network-serialized transaction.

        This method verifies that each input has the required finalized unlocking data:
          - Non-SegWit inputs must have key 0x07.
          - SegWit inputs must have key 0x08.

        Returns:
            The network-serialized transaction as bytes.

        Raises:
            ValueError: If any input is missing the required finalized data.
        """
        for idx, psbt_input in enumerate(self.inputs):
            input_type = psbt_input.get_input_type()
            if input_type in ["P2PKH", "P2SH"]:
                if b"\x07" not in psbt_input.map:
                    raise ValueError(f"Input {idx} is not finalized: missing 0x07 finalized scriptSig.")
            else:
                if b"\x08" not in psbt_input.map:
                    raise ValueError(f"Input {idx} is not finalized: missing 0x08 finalized scriptWitness.")

        for idx, psbt_input in enumerate(self.inputs):
            input_type = psbt_input.get_input_type()
            if input_type in ["P2PKH", "P2SH"]:
                finalized_scriptsig = psbt_input.map.get(b"\x07", b"")
                self.tx.inputs[idx].script_sig = Script.from_raw(finalized_scriptsig.hex())
            else:
                if b"\x07" in psbt_input.map:
                    finalized_scriptsig = psbt_input.map[b"\x07"]
                    self.tx.inputs[idx].script_sig = Script.from_raw(finalized_scriptsig.hex())
                witness_bytes = psbt_input.map.get(b"\x08", b"")
                self.tx.inputs[idx].witness = decode_witness_stack(witness_bytes)

        segwit = hasattr(self.tx, "has_segwit") and self.tx.has_segwit
        return self.tx.to_bytes(segwit)

    def is_finalized(self) -> bool:
        """
        Determine if the PSBT is fully finalized.

        Returns:
            True if all inputs have finalized unlocking data; otherwise False.
        """
        for idx, psbt_input in enumerate(self.inputs):
            if not psbt_input.is_finalized():
                return False
            tx_in = self.tx.inputs[idx]
            if not ((hasattr(tx_in, "script_sig") and tx_in.script_sig) or (hasattr(tx_in, "witness") and tx_in.witness)):
                return False
        return True

    def validate_structure(self) -> list:
        """
        Validate the overall structure of the PSBT.

        Returns:
            A list of error messages for any structural issues found.
        """
        errors = []
        if b"\x00" not in self.global_map:
            errors.append("Global map missing unsigned transaction (0x00)")
        for idx, psbt_input in enumerate(self.inputs):
            try:
                psbt_input.validate_keys()
            except Exception as e:
                errors.append(f"Input {idx} key error: {str(e)}")
            input_type = psbt_input.get_input_type()
            if not psbt_input.is_finalized():
                if input_type in ["P2PKH", "P2SH"]:
                    if psbt_input.get_non_witness_utxo() is None:
                        errors.append(f"Input {idx} ({input_type}): missing non-witness UTXO.")
                if input_type in ["SegWit", "P2SH-P2WPKH", "P2WSH"]:
                    if psbt_input.get_witness_utxo() is None:
                        errors.append(f"Input {idx} ({input_type}): missing witness UTXO.")
            if input_type in ["P2SH", "P2SH-P2WPKH", "P2WSH"]:
                if psbt_input.get_partial_signatures() == {}:
                    errors.append(f"Input {idx} ({input_type}): no partial signatures found.")
        if len(self.outputs) == 0:
            errors.append("PSBT missing outputs.")
        for idx, psbt_output in enumerate(self.outputs):
            try:
                psbt_output.validate_keys()
            except Exception as e:
                errors.append(f"Output {idx} key error: {str(e)}")
        return errors

    def summary(self) -> str:
        """
        Generate a summary of the PSBT structure.

        Returns:
            A multiline string summarizing the number of inputs, outputs, finalized inputs,
            and the distribution of input types.
        """
        total_inputs = len(self.inputs)
        total_outputs = len(self.outputs)
        finalized = sum(1 for inp in self.inputs if inp.is_finalized())
        input_types = {}
        for inp in self.inputs:
            typ = inp.get_input_type()
            input_types[typ] = input_types.get(typ, 0) + 1
        summary_lines = [
            "PSBT Summary:",
            f"  Total Inputs: {total_inputs}",
            f"  Total Outputs: {total_outputs}",
            f"  Finalized Inputs: {finalized} / {total_inputs}",
            "  Input Types:"
        ]
        for typ, count in input_types.items():
            summary_lines.append(f"    {typ}: {count}")
        return "\n".join(summary_lines)

    def get_input(self, index: int) -> PSBTInput:
        """
        Retrieve a specific PSBT input.

        Args:
            index: The index of the input.
        
        Returns:
            The PSBTInput at the given index.
        
        Raises:
            IndexError if the index is out of range.
        """
        if index < 0 or index >= len(self.inputs):
            raise IndexError("Input index out of range.")
        return self.inputs[index]

    def get_output(self, index: int) -> PSBTOutput:
        """
        Retrieve a specific PSBT output.

        Args:
            index: The index of the output.
        
        Returns:
            The PSBTOutput at the given index.
        
        Raises:
            IndexError if the index is out of range.
        """
        if index < 0 or index >= len(self.outputs):
            raise IndexError("Output index out of range.")
        return self.outputs[index]
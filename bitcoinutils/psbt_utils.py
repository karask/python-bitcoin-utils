"""
psbt_utils.py
=============
This module contains helper functions and validators for Partially Signed Bitcoin Transactions (PSBTs).

Functions provided:
  - is_valid_pubkey: Validates public key length.
  - is_push_only: Checks that a script consists only of data-push opcodes.
  - encode_witness_stack / decode_witness_stack: Serialize and parse witness stacks.
  - build_push_script: Builds a Bitcoin push script for arbitrary-length data.
  - Various validators for PSBT input and output key fields.
  
Additionally, allowed validator dictionaries are provided for input, output, and global PSBT maps.
"""

import binascii
from io import BytesIO
from bitcoinutils.script import Script  
from bitcoinutils.transactions import Transaction  

def is_valid_pubkey(pubkey: bytes) -> bool:
    """
    Check whether the given public key is valid by length.
    
    Compressed keys are 33 bytes and uncompressed keys are 65 bytes.
    
    Args:
        pubkey: Public key as bytes.
    
    Returns:
        True if valid; otherwise False.
    """
    return len(pubkey) in (33, 65)

def is_push_only(script_bytes: bytes) -> bool:
    """
    Check that a Bitcoin script is push-only.
    
    A push-only script consists solely of data push opcodes and small numeric pushes.
    
    Args:
        script_bytes: The script in bytes.
        
    Returns:
        True if the script is push-only, otherwise False.
    """
    i = 0
    while i < len(script_bytes):
        opcode = script_bytes[i]
        if opcode <= 0x4b:  # Direct data push: opcode indicates data length.
            if i + 1 + opcode > len(script_bytes):
                return False
            i += 1 + opcode
        elif opcode == 0x4c:  # OP_PUSHDATA1
            if i + 1 >= len(script_bytes):
                return False
            data_length = script_bytes[i+1]
            if i + 2 + data_length > len(script_bytes):
                return False
            i += 2 + data_length
        elif opcode == 0x4d:  # OP_PUSHDATA2
            if i + 2 >= len(script_bytes):
                return False
            data_length = script_bytes[i+1] + (script_bytes[i+2] << 8)
            if i + 3 + data_length > len(script_bytes):
                return False
            i += 3 + data_length
        elif opcode == 0x4e:  # OP_PUSHDATA4
            if i + 4 >= len(script_bytes):
                return False
            data_length = (script_bytes[i+1] +
                           (script_bytes[i+2] << 8) +
                           (script_bytes[i+3] << 16) +
                           (script_bytes[i+4] << 24))
            if i + 5 + data_length > len(script_bytes):
                return False
            i += 5 + data_length
        elif opcode == 0x00 or (0x51 <= opcode <= 0x60):
            i += 1
        else:
            # If any opcode is encountered that is not a recognized push, return False.
            return False
    return True

def encode_witness_stack(witness_stack: list) -> bytes:
    """
    Encode a witness stack for a segwit transaction.
    
    The encoding is:
        <varint count> followed by a sequence of [<varint length> <data>] items.
    
    Args:
        witness_stack: List of witness items as bytes.
    
    Returns:
        The encoded witness stack as bytes.
    """
    result = encode_varint(len(witness_stack))
    for item in witness_stack:
        result += encode_varint(len(item)) + item
    return result

def decode_witness_stack(data: bytes) -> list:
    """
    Decode an encoded witness stack into its component items.
    
    Args:
        data: The serialized witness stack.
    
    Returns:
        A list of witness items (each as bytes).
    """
    stream = BytesIO(data)
    count = read_varint(stream)
    items = []
    for _ in range(count):
        length = read_varint(stream)
        items.append(stream.read(length))
    return items

def build_push_script(items: list) -> bytes:
    """
    Build a Bitcoin script that pushes each item onto the stack.
    
    The function handles arbitrary data lengths by selecting the proper push opcode:
      - 1 to 75 bytes: The opcode is the length itself.
      - 76 to 255 bytes: Use OP_PUSHDATA1 (0x4c).
      - 256 to 65535 bytes: Use OP_PUSHDATA2 (0x4d).
      - Larger: Use OP_PUSHDATA4 (0x4e).
    
    Args:
        items: A list of byte strings to push.
    
    Returns:
        A complete push script as bytes.
    """
    script = b""
    for item in items:
        length = len(item)
        if length == 0:
            # An empty push is represented as OP_0.
            script += b"\x00"
        elif length < 76:
            script += length.to_bytes(1, "little") + item
        elif length <= 255:
            script += b"\x4c" + length.to_bytes(1, "little") + item
        elif length <= 65535:
            script += b"\x4d" + length.to_bytes(2, "little") + item
        else:
            script += b"\x4e" + length.to_bytes(4, "little") + item
    return script

# -----------------------------
# Validators for PSBT Key Fields
# -----------------------------

def validate_in_non_witness_utxo(key: bytes, value: bytes):
    """
    Validate the non-witness UTXO field for a PSBT input.
    
    Args:
        key: The PSBT key.
        value: The serialized transaction.
    
    Raises:
        ValueError if the UTXO is empty, cannot be parsed, or lacks outputs.
    """
    if not value:
        raise ValueError("Non-witness UTXO is empty.")
    tx = Transaction.from_raw(value.hex())
    if tx is None:
        raise ValueError("Non-witness UTXO does not parse as a valid transaction.")
    if not hasattr(tx, "outputs") or len(tx.outputs) == 0:
        raise ValueError("Non-witness UTXO does not contain any outputs.")

def validate_in_witness_utxo(key: bytes, value: bytes):
    """
    Validate the witness UTXO field for a PSBT input.
    
    Args:
        key: The PSBT key.
        value: The serialized transaction output.
    
    Raises:
        ValueError if the witness UTXO is empty or too short.
    """
    if not value or len(value) < 9:
        raise ValueError("Witness UTXO is empty or too short.")

def validate_in_partial_sig(key: bytes, value: bytes):
    """
    Validate a partial signature field in a PSBT input.
    
    Args:
        key: The key (prefix + pubkey).
        value: The signature.
    
    Raises:
        ValueError if the pubkey length is invalid or if the signature is empty.
    """
    pubkey = key[1:]
    if not is_valid_pubkey(pubkey):
        raise ValueError("Invalid pubkey length in partial signature key.")
    if not value or len(value) == 0:
        raise ValueError("Partial signature value is empty.")

def validate_in_sighash(key: bytes, value: bytes):
    """
    Validate the sighash type field for a PSBT input.
    
    Args:
        key: The key for the sighash type.
        value: The 4-byte sighash type.
    
    Raises:
        ValueError if the sighash type is not 4 bytes.
    """
    if len(value) != 4:
        raise ValueError("Sighash type value must be exactly 4 bytes.")

def validate_in_redeem_script(key: bytes, value: bytes):
    """
    Validate the redeem script field for a PSBT input.
    
    Args:
        key: The key for the redeem script.
        value: The redeem script.
    
    Raises:
        ValueError if the redeem script is empty, parses to empty, or is not push-only.
    """
    if not value:
        raise ValueError("Redeem script is empty.")
    try:
        script = Script.from_raw(value.hex())
        s_bytes = script.to_bytes()
        if not s_bytes:
            raise ValueError("Redeem script parsed as empty.")
        if not is_push_only(s_bytes):
            raise ValueError("Redeem script is not push-only.")
    except Exception as e:
        raise ValueError("Invalid redeem script: " + str(e))

def validate_in_witness_script(key: bytes, value: bytes):
    """
    Validate the witness script field for a PSBT input.
    
    Args:
        key: The key for the witness script.
        value: The witness script.
    
    Raises:
        ValueError if the witness script is empty or parses as empty.
    """
    if not value:
        raise ValueError("Witness script is empty.")
    try:
        script = Script.from_raw(value.hex())
        s_bytes = script.to_bytes()
        if not s_bytes:
            raise ValueError("Witness script parsed as empty.")
    except Exception as e:
        raise ValueError("Invalid witness script: " + str(e))

def validate_in_bip32(key: bytes, value: bytes):
    """
    Validate the BIP32 derivation field for a PSBT input.
    
    Args:
        key: The key (prefix + pubkey).
        value: The derivation path data.
    
    Raises:
        ValueError if the pubkey is invalid or if the derivation path is empty.
    """
    pubkey = key[1:]
    if not is_valid_pubkey(pubkey):
        raise ValueError("Invalid pubkey length in BIP32 derivation key (input).")
    if not value or len(value) == 0:
        raise ValueError("Empty derivation path in input.")

def validate_in_final_scriptsig(key: bytes, value: bytes):
    """
    Validate the finalized scriptSig field for a PSBT input.
    
    Args:
        key: The key for the finalized scriptSig.
        value: The finalized scriptSig.
    
    Raises:
        ValueError if the scriptSig is empty, parsed as empty, or not push-only.
    """
    if not value:
        raise ValueError("Final scriptSig is empty.")
    try:
        script = Script.from_raw(value.hex())
        s_bytes = script.to_bytes()
        if not s_bytes or len(s_bytes) < 1:
            raise ValueError("Final scriptSig parsed as empty.")
        if not is_push_only(s_bytes):
            raise ValueError("Final scriptSig is not push-only.")
    except Exception as e:
        raise ValueError("Invalid final scriptSig: " + str(e))

def validate_in_final_scriptwitness(key: bytes, value: bytes):
    """
    Validate the finalized script witness field for a PSBT input.
    
    Args:
        key: The key for the finalized script witness.
        value: The finalized script witness.
    
    Raises:
        ValueError if the script witness is empty.
    """
    if not value:
        raise ValueError("Final script witness is empty.")

# Validators for PSBT Output Keys

def validate_out_redeem_script(key: bytes, value: bytes):
    """
    Validate the redeem script field for a PSBT output.
    
    Args:
        key: The key for the redeem script.
        value: The redeem script.
    
    Raises:
        ValueError if the redeem script is empty, parses as empty, or is not push-only.
    """
    if not value:
        raise ValueError("Output redeem script is empty.")
    try:
        script = Script.from_raw(value.hex())
        s_bytes = script.to_bytes()
        if not s_bytes:
            raise ValueError("Output redeem script parsed as empty.")
        if not is_push_only(s_bytes):
            raise ValueError("Output redeem script is not push-only.")
    except Exception as e:
        raise ValueError("Invalid output redeem script: " + str(e))

def validate_out_witness_script(key: bytes, value: bytes):
    """
    Validate the witness script field for a PSBT output.
    
    Args:
        key: The key for the witness script.
        value: The witness script.
    
    Raises:
        ValueError if the witness script is empty or parses as empty.
    """
    if not value:
        raise ValueError("Output witness script is empty.")
    try:
        script = Script.from_raw(value.hex())
        s_bytes = script.to_bytes()
        if not s_bytes:
            raise ValueError("Output witness script parsed as empty or too short.")
    except Exception as e:
        raise ValueError("Invalid output witness script: " + str(e))

def validate_out_bip32(key: bytes, value: bytes):
    """
    Validate the BIP32 derivation field for a PSBT output.
    
    Args:
        key: The key (prefix + pubkey).
        value: The derivation path data.
    
    Raises:
        ValueError if the pubkey is invalid or if the derivation path is empty.
    """
    pubkey = key[1:]
    if not is_valid_pubkey(pubkey):
        raise ValueError("Invalid pubkey length in output BIP32 derivation key.")
    if not value or len(value) == 0:
        raise ValueError("Empty derivation path in output.")

# Allowed Validators Dictionaries

ALLOWED_INPUT_VALIDATORS = {
    b"\x00": validate_in_non_witness_utxo,   # non-witness UTXO
    b"\x01": validate_in_witness_utxo,         # witness UTXO
    b"\x02": validate_in_partial_sig,          # partial signature
    b"\x03": validate_in_sighash,              # sighash type
    b"\x04": validate_in_redeem_script,        # redeem script
    b"\x05": validate_in_witness_script,       # witness script
    b"\x06": validate_in_bip32,                # BIP32 derivation
    b"\x07": validate_in_final_scriptsig,      # final scriptSig
    b"\x08": validate_in_final_scriptwitness   # final script witness
}

ALLOWED_OUTPUT_VALIDATORS = {
    b"\x00": validate_out_redeem_script,       # redeem script
    b"\x01": validate_out_witness_script,       # witness script
    b"\x02": validate_out_bip32                  # BIP32 derivation
}

def validate_global_unsigned_tx(key: bytes, value: bytes):
    """
    Validate the global unsigned transaction field for a PSBT.
    
    Args:
        key: The key for the unsigned transaction.
        value: The serialized unsigned transaction.
    
    Raises:
        ValueError if the transaction is empty, too short, invalid, or missing inputs/outputs.
    """
    if not value or len(value) < 50:
        raise ValueError("Unsigned transaction is empty or too short.")
    tx = Transaction.from_raw(value.hex())
    if tx is None:
        raise ValueError("Invalid unsigned transaction in global map.")
    if not hasattr(tx, "inputs") or len(tx.inputs) == 0:
        raise ValueError("Unsigned transaction must have at least one input.")
    if not hasattr(tx, "outputs") or len(tx.outputs) == 0:
        raise ValueError("Unsigned transaction must have at least one output.")

ALLOWED_GLOBAL_VALIDATORS = {
    b"\x00": validate_global_unsigned_tx
}

def read_varint(stream):
    pos = stream.tell()
    first = stream.read(1)
    if not first:
        raise EOFError(f"Unexpected end of stream at position {pos} when reading varint")
    prefix = first[0]
    if prefix < 0xfd:
        # print(f"[read_varint] pos={pos}, prefix={prefix} (1 byte)")
        return prefix
    elif prefix == 0xfd:
        data = stream.read(2)
        val = int.from_bytes(data, 'little')
        # print(f"[read_varint] pos={pos}, prefix=0xfd, value={val} (2 bytes)")
        return val
    elif prefix == 0xfe:
        data = stream.read(4)
        val = int.from_bytes(data, 'little')
        # print(f"[read_varint] pos={pos}, prefix=0xfe, value={val} (4 bytes)")
        return val
    elif prefix == 0xff:
        data = stream.read(8)
        val = int.from_bytes(data, 'little')
        # print(f"[read_varint] pos={pos}, prefix=0xff, value={val} (8 bytes)")
        return val
    else:
        raise ValueError(f"Invalid varint prefix: {prefix}")

def encode_varint(i):
    if i < 0xfd:
        return i.to_bytes(1, 'little')
    elif i <= 0xffff:
        return b'\xfd' + i.to_bytes(2, 'little')
    elif i <= 0xffffffff:
        return b'\xfe' + i.to_bytes(4, 'little')
    else:
        return b'\xff' + i.to_bytes(8, 'little')

def read_key_value_pair(stream):
    # print(f"[read_key_value_pair] stream: {stream}")
    start_pos = stream.tell()
    key_len = read_varint(stream)
    if key_len == 0:
        # print(f"[read_key_value_pair] Separator encountered at pos {start_pos}")
        return None, None
    key = stream.read(key_len)
    value_len = read_varint(stream)
    value = stream.read(value_len)
    # print(f"[read_key_value_pair] pos={start_pos}, key_len={key_len}, value_len={value_len}, key={key.hex()}")
    return key, value

def write_key_value_pair(key: bytes, value: bytes):
    return encode_varint(len(key)) + key + encode_varint(len(value)) + value
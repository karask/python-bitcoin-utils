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


import copy
import hashlib
import struct
from typing import Any, Union


from bitcoinutils.ripemd160 import ripemd160
from bitcoinutils.utils import b_to_h, h_to_b, vi_to_int


# import bitcoinutils.keys




# Bitcoin's op codes. Complete list at: https://en.bitcoin.it/wiki/Script
OP_CODES = {
   # constants
   "OP_0": b"\x00",
   "OP_FALSE": b"\x00",
   "OP_PUSHDATA1": b"\x4c",
   "OP_PUSHDATA2": b"\x4d",
   "OP_PUSHDATA4": b"\x4e",
   "OP_1NEGATE": b"\x4f",
   "OP_1": b"\x51",
   "OP_TRUE": b"\x51",
   "OP_2": b"\x52",
   "OP_3": b"\x53",
   "OP_4": b"\x54",
   "OP_5": b"\x55",
   "OP_6": b"\x56",
   "OP_7": b"\x57",
   "OP_8": b"\x58",
   "OP_9": b"\x59",
   "OP_10": b"\x5a",
   "OP_11": b"\x5b",
   "OP_12": b"\x5c",
   "OP_13": b"\x5d",
   "OP_14": b"\x5e",
   "OP_15": b"\x5f",
   "OP_16": b"\x60",
   # flow control
   "OP_NOP": b"\x61",
   "OP_IF": b"\x63",
   "OP_NOTIF": b"\x64",
   "OP_ELSE": b"\x67",
   "OP_ENDIF": b"\x68",
   "OP_VERIFY": b"\x69",
   "OP_RETURN": b"\x6a",
   # stack
   "OP_TOALTSTACK": b"\x6b",
   "OP_FROMALTSTACK": b"\x6c",
   "OP_IFDUP": b"\x73",
   "OP_DEPTH": b"\x74",
   "OP_DROP": b"\x75",
   "OP_DUP": b"\x76",
   "OP_NIP": b"\x77",
   "OP_OVER": b"\x78",
   "OP_PICK": b"\x79",
   "OP_ROLL": b"\x7a",
   "OP_ROT": b"\x7b",
   "OP_SWAP": b"\x7c",
   "OP_TUCK": b"\x7d",
   "OP_2DROP": b"\x6d",
   "OP_2DUP": b"\x6e",
   "OP_3DUP": b"\x6f",
   "OP_2OVER": b"\x70",
   "OP_2ROT": b"\x71",
   "OP_2SWAP": b"\x72",
   # splice
   #'OP_CAT'                : b'\x7e',
   #'OP_SUBSTR'             : b'\x7f',
   #'OP_LEFT'               : b'\x80',
   #'OP_RIGHT'              : b'\x81',
   "OP_SIZE": b"\x82",
   # bitwise logic
   #'OP_INVERT'             : b'\x83',
   #'OP_AND'                : b'\x84',
   #'OP_OR'                 : b'\x85',
   #'OP_XOR'                : b'\x86',
   "OP_EQUAL": b"\x87",
   "OP_EQUALVERIFY": b"\x88",
   # arithmetic
   "OP_1ADD": b"\x8b",
   "OP_1SUB": b"\x8c",
   #'OP_2MUL'               : b'\x8d',
   #'OP_2DIV'               : b'\x8e',
   "OP_NEGATE": b"\x8f",
   "OP_ABS": b"\x90",
   "OP_NOT": b"\x91",
   "OP_0NOTEQUAL": b"\x92",
   "OP_ADD": b"\x93",
   "OP_SUB": b"\x94",
   #'OP_MUL'                : b'\x95',
   #'OP_DIV'                : b'\x96',
   #'OP_MOD'                : b'\x97',
   #'OP_LSHIFT'             : b'\x98',
   #'OP_RSHIFT'             : b'\x99',
   "OP_BOOLAND": b"\x9a",
   "OP_BOOLOR": b"\x9b",
   "OP_NUMEQUAL": b"\x9c",
   "OP_NUMEQUALVERIFY": b"\x9d",
   "OP_NUMNOTEQUAL": b"\x9e",
   "OP_LESSTHAN": b"\x9f",
   "OP_GREATERTHAN": b"\xa0",
   "OP_LESSTHANOREQUAL": b"\xa1",
   "OP_GREATERTHANOREQUAL": b"\xa2",
   "OP_MIN": b"\xa3",
   "OP_MAX": b"\xa4",
   "OP_WITHIN": b"\xa5",
   # crypto
   "OP_RIPEMD160": b"\xa6",
   "OP_SHA1": b"\xa7",
   "OP_SHA256": b"\xa8",
   "OP_HASH160": b"\xa9",
   "OP_HASH256": b"\xaa",
   "OP_CODESEPARATOR": b"\xab",
   "OP_CHECKSIG": b"\xac",
   "OP_CHECKSIGVERIFY": b"\xad",
   "OP_CHECKMULTISIG": b"\xae",
   "OP_CHECKMULTISIGVERIFY": b"\xaf",
   "OP_CHECKSIGADD": b"\xba",             # added this new OPCODE
   # locktime
   "OP_NOP2": b"\xb1",
   "OP_CHECKLOCKTIMEVERIFY": b"\xb1",
   "OP_NOP3": b"\xb2",
   "OP_CHECKSEQUENCEVERIFY": b"\xb2",
  
}


CODE_OPS = {
   # constants
   b"\x00": "OP_0",
   b"\x4c": "OP_PUSHDATA1",
   b"\x4d": "OP_PUSHDATA2",
   b"\x4e": "OP_PUSHDATA4",
   b"\x4f": "OP_1NEGATE",
   b"\x51": "OP_1",
   b"\x52": "OP_2",
   b"\x53": "OP_3",
   b"\x54": "OP_4",
   b"\x55": "OP_5",
   b"\x56": "OP_6",
   b"\x57": "OP_7",
   b"\x58": "OP_8",
   b"\x59": "OP_9",
   b"\x5a": "OP_10",
   b"\x5b": "OP_11",
   b"\x5c": "OP_12",
   b"\x5d": "OP_13",
   b"\x5e": "OP_14",
   b"\x5f": "OP_15",
   b"\x60": "OP_16",
   # flow control
   b"\x61": "OP_NOP",
   b"\x63": "OP_IF",
   b"\x64": "OP_NOTIF",
   b"\x67": "OP_ELSE",
   b"\x68": "OP_ENDIF",
   b"\x69": "OP_VERIFY",
   b"\x6a": "OP_RETURN",
   # stack
   b"\x6b": "OP_TOALTSTACK",
   b"\x6c": "OP_FROMALTSTACK",
   b"\x73": "OP_IFDUP",
   b"\x74": "OP_DEPTH",
   b"\x75": "OP_DROP",
   b"\x76": "OP_DUP",
   b"\x77": "OP_NIP",
   b"\x78": "OP_OVER",
   b"\x79": "OP_PICK",
   b"\x7a": "OP_ROLL",
   b"\x7b": "OP_ROT",
   b"\x7c": "OP_SWAP",
   b"\x7d": "OP_TUCK",
   b"\x6d": "OP_2DROP",
   b"\x6e": "OP_2DUP",
   b"\x6f": "OP_3DUP",
   b"\x70": "OP_2OVER",
   b"\x71": "OP_2ROT",
   b"\x72": "OP_2SWAP",
   # splice
   b"\x82": "OP_SIZE",
   # bitwise logic
   b"\x87": "OP_EQUAL",
   b"\x88": "OP_EQUALVERIFY",
   # arithmetic
   b"\x8b": "OP_1ADD",
   b"\x8c": "OP_1SUB",
   b"\x8f": "OP_NEGATE",
   b"\x90": "OP_ABS",
   b"\x91": "OP_NOT",
   b"\x92": "OP_0NOTEQUAL",
   b"\x93": "OP_ADD",
   b"\x94": "OP_SUB",
   b"\x9a": "OP_BOOLAND",
   b"\x9b": "OP_BOOLOR",
   b"\x9c": "OP_NUMEQUAL",
   b"\x9d": "OP_NUMEQUALVERIFY",
   b"\x9e": "OP_NUMNOTEQUAL",
   b"\x9f": "OP_LESSTHAN",
   b"\xa0": "OP_GREATERTHAN",
   b"\xa1": "OP_LESSTHANOREQUAL",
   b"\xa2": "OP_GREATERTHANOREQUAL",
   b"\xa3": "OP_MIN",
   b"\xa4": "OP_MAX",
   b"\xa5": "OP_WITHIN",
   # crypto
   b"\xa6": "OP_RIPEMD160",
   b"\xa7": "OP_SHA1",
   b"\xa8": "OP_SHA256",
   b"\xa9": "OP_HASH160",
   b"\xaa": "OP_HASH256",
   b"\xab": "OP_CODESEPARATOR",
   b"\xac": "OP_CHECKSIG",
   b"\xad": "OP_CHECKSIGVERIFY",
   b"\xae": "OP_CHECKMULTISIG",
   b"\xaf": "OP_CHECKMULTISIGVERIFY",
   b"\xba": "OP_CHECKSIGADD", # added this new OPCODE
   # locktime
   # This used to be OP_NOP2
   b"\xb1": "OP_CHECKLOCKTIMEVERIFY", 
   # This used to be OP_NOP3
   b"\xb2": "OP_CHECKSEQUENCEVERIFY", 
}




class Script:
   """Represents any script in Bitcoin


   A Script contains just a list of OP_CODES and also knows how to serialize
   into bytes


   Attributes
   ----------
   script : list
       the list with all the script OP_CODES and data


   Methods
   -------
   to_bytes()
       returns a serialized byte version of the script


   to_hex()
       returns a serialized version of the script in hex


   get_script()
       returns the list of strings that makes up this script


   copy()
       creates a copy of the object (classmethod)


   from_raw()


   to_p2sh_script_pub_key()
       converts script to p2sh scriptPubKey (locking script)


   to_p2wsh_script_pub_key()
       converts script to p2wsh scriptPubKey (locking script)


   is_p2wpkh()
       checks if script is P2WPKH (Pay-to-Witness-Public-Key-Hash)


   is_p2tr()
       checks if script is P2TR (Pay-to-Taproot)


   is_p2wsh()
       checks if script is P2WSH (Pay-to-Witness-Script-Hash)


   is_p2sh()
       checks if script is P2SH (Pay-to-Script-Hash)


   is_p2pkh()
       checks if script is P2PKH (Pay-to-Public-Key-Hash)


   is_multisig()
       checks if script is a multisig script


   get_script_type()
       determines the type of script


   Raises
   ------
   ValueError
       If string data is too large or integer is negative
   """


   def __init__(self, script: list[Any]):
       """See Script description"""
       self.script: list[Any] = script


   @classmethod
   def copy(cls, script: "Script") -> "Script":
       """Deep copy of Script"""
       scripts = copy.deepcopy(script.script)
       return cls(scripts)


   def _op_push_data(self, data: str) -> bytes:
       """Converts data to appropriate OP_PUSHDATA OP code including length"""
       data_bytes = h_to_b(data)  # Assuming string is hexadecimal


       if len(data_bytes) < 0x4C:
           return bytes([len(data_bytes)]) + data_bytes
       elif len(data_bytes) < 0xFF:
           return b"\x4c" + bytes([len(data_bytes)]) + data_bytes
       elif len(data_bytes) < 0xFFFF:
           return b"\x4d" + struct.pack("<H", len(data_bytes)) + data_bytes
       elif len(data_bytes) < 0xFFFFFFFF:
           return b"\x4e" + struct.pack("<I", len(data_bytes)) + data_bytes
       else:
           raise ValueError("Data too large. Cannot push into script")


   def _push_integer(self, integer: int) -> bytes:
       """Converts integer to bytes; as signed little-endian integer"""
       if integer < 0:
           raise ValueError("Integer is currently required to be positive.")


       number_of_bytes = (integer.bit_length() + 7) // 8
       integer_bytes = integer.to_bytes(number_of_bytes, byteorder="little")


       if integer & (1 << number_of_bytes * 8 - 1):
           integer_bytes += b"\x00"


       return self._op_push_data(b_to_h(integer_bytes))


   def to_bytes(self) -> bytes:
       """Converts the script to bytes"""
       script_bytes = b""
       for token in self.script:
           if token in OP_CODES:
               script_bytes += OP_CODES[token]
           elif isinstance(token, int) and token >= 0 and token <= 16:
               script_bytes += OP_CODES["OP_" + str(token)]
           else:
               if isinstance(token, int):
                   script_bytes += self._push_integer(token)
               else:
                   script_bytes += self._op_push_data(token)
       return script_bytes


   def to_hex(self) -> str:
       """Converts the script to hexadecimal"""
       return b_to_h(self.to_bytes())


   @staticmethod
   def from_raw(scriptrawhex: Union[str, bytes], has_segwit: bool = False):
       """
       Imports a Script commands list from raw hexadecimal data
       """
       if isinstance(scriptrawhex, str):
           scriptraw = h_to_b(scriptrawhex)
       elif isinstance(scriptrawhex, bytes):
           scriptraw = scriptrawhex
       else:
           raise TypeError("Input must be a hexadecimal string or bytes")
      
       commands = []
       index = 0


       while index < len(scriptraw):
           byte = scriptraw[index]
           if bytes([byte]) in CODE_OPS:
               if (
                   bytes([byte]) != b"\x4c"
                   and bytes([byte]) != b"\x4d"
                   and bytes([byte]) != b"\x4e"
               ):
                   commands.append(CODE_OPS[bytes([byte])])
               index = index + 1
               if has_segwit is False and bytes([byte]) == b"\x4c":
                   bytes_to_read = int.from_bytes(
                       scriptraw[index : index + 1], "little"
                   )
                   index = index + 1
                   commands.append(scriptraw[index : index + bytes_to_read].hex())
                   index = index + bytes_to_read
               elif has_segwit is False and bytes([byte]) == b"\x4d":
                   bytes_to_read = int.from_bytes(
                       scriptraw[index : index + 2], "little"
                   )
                   index = index + 2
                   commands.append(scriptraw[index : index + bytes_to_read].hex())
                   index = index + bytes_to_read
               elif has_segwit is False and bytes([byte]) == b"\x4e":
                   bytes_to_read = int.from_bytes(
                       scriptraw[index : index + 4], "little"
                   )
                   index = index + 4
                   commands.append(scriptraw[index : index + bytes_to_read].hex())
                   index = index + bytes_to_read
           else:
               data_size, size = vi_to_int(scriptraw[index : index + 8])
               commands.append(
                   scriptraw[index + size : index + size + data_size].hex()
               )
               index = index + data_size + size


       return Script(script=commands)


   def get_script(self) -> list[Any]:
       """Returns script as array of strings"""
       return self.script


   def to_p2sh_script_pub_key(self) -> "Script":
       """Converts script to p2sh scriptPubKey (locking script)"""
       script_hash160 = ripemd160(hashlib.sha256(self.to_bytes()).digest())
       hex_hash160 = b_to_h(script_hash160)
       return Script(["OP_HASH160", hex_hash160, "OP_EQUAL"])


   def to_p2wsh_script_pub_key(self) -> "Script":
       """Converts script to p2wsh scriptPubKey (locking script)"""
       sha256 = hashlib.sha256(self.to_bytes()).digest()
       return Script(["OP_0", b_to_h(sha256)])


   def is_p2wpkh(self) -> bool:
       """
       Check if script is P2WPKH (Pay-to-Witness-Public-Key-Hash).
      
       P2WPKH format: OP_0 <20-byte-key-hash>
      
       Returns:
           bool: True if script is P2WPKH
       """
       ops = self.script
       return (len(ops) == 2 and
               (ops[0] == 0 or ops[0] == "OP_0") and
               isinstance(ops[1], str) and
               len(h_to_b(ops[1])) == 20)


   def is_p2tr(self) -> bool:
       """
       Check if script is P2TR (Pay-to-Taproot).
      
       P2TR format: OP_1 <32-byte-key>
      
       Returns:
           bool: True if script is P2TR
       """
       ops = self.script
       return (len(ops) == 2 and
               (ops[0] == 1 or ops[0] == "OP_1") and
               isinstance(ops[1], str) and
               len(h_to_b(ops[1])) == 32)


   def is_p2wsh(self) -> bool:
       """
       Check if script is P2WSH (Pay-to-Witness-Script-Hash).
      
       P2WSH format: OP_0 <32-byte-script-hash>
      
       Returns:
           bool: True if script is P2WSH
       """
       ops = self.script
       return (len(ops) == 2 and
               (ops[0] == 0 or ops[0] == "OP_0") and
               isinstance(ops[1], str) and
               len(h_to_b(ops[1])) == 32)


   def is_p2sh(self) -> bool:
       """
       Check if script is P2SH (Pay-to-Script-Hash).
      
       P2SH format: OP_HASH160 <20-byte-script-hash> OP_EQUAL
      
       Returns:
           bool: True if script is P2SH
       """
       ops = self.script
       return (len(ops) == 3 and
               ops[0] == 'OP_HASH160' and
               isinstance(ops[1], str) and
               len(h_to_b(ops[1])) == 20 and
               ops[2] == 'OP_EQUAL')


   def is_p2pkh(self) -> bool:
       """
       Check if script is P2PKH (Pay-to-Public-Key-Hash).
      
       P2PKH format: OP_DUP OP_HASH160 <20-byte-key-hash> OP_EQUALVERIFY OP_CHECKSIG
      
       Returns:
           bool: True if script is P2PKH
       """
       ops = self.script
       return (len(ops) == 5 and
               ops[0] == 'OP_DUP' and
               ops[1] == 'OP_HASH160' and
               isinstance(ops[2], str) and
               len(h_to_b(ops[2])) == 20 and
               ops[3] == 'OP_EQUALVERIFY' and
               ops[4] == 'OP_CHECKSIG')


   def is_multisig(self) -> tuple[bool, Union[tuple[int, int], None]]:
       """
       Check if script is a multisig script.
      
       Multisig format: OP_M <pubkey1> ... <pubkeyN> OP_N OP_CHECKMULTISIG
      
       Returns:
           tuple: (bool, (M, N) if multisig, None otherwise)
       """
       ops = self.script
      
       if (len(ops) >= 4 and
           isinstance(ops[0], int) and
           ops[-1] == 'OP_CHECKMULTISIG' and
           isinstance(ops[-2], int)):
          
           m = ops[0]  # Required signatures
           n = ops[-2]  # Total public keys
          
           # Validate the structure
           if len(ops) == n + 3:  # M + N pubkeys + N + OP_CHECKMULTISIG
               return True, (m, n)
      
       return False, None


   def get_script_type(self) -> str:
       """
       Determine the type of script.
      
       Returns:
           str: Script type ('p2pkh', 'p2sh', 'p2wpkh', 'p2wsh', 'p2tr', 'multisig', 'unknown')
       """
       if self.is_p2pkh():
           return 'p2pkh'
       elif self.is_p2sh():
           return 'p2sh'
       elif self.is_p2wpkh():
           return 'p2wpkh'
       elif self.is_p2wsh():
           return 'p2wsh'
       elif self.is_p2tr():
           return 'p2tr'
       elif self.is_multisig()[0]:
           return 'multisig'
       else:
           return 'unknown'


   def __str__(self) -> str:
       return str(self.script)


   def __repr__(self) -> str:
       return self.__str__()


   def __eq__(self, _other: object) -> bool:
       if not isinstance(_other, Script):
           return False
       return self.script == _other.script

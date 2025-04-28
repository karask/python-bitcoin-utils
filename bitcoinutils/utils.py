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

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bitcoinutils.keys import PublicKey
    from bitcoinutils.script import Script
    from decimal import Decimal
    from typing import Tuple

import hashlib
from ecdsa import ellipticcurve  # type: ignore
from bitcoinutils.constants import SATOSHIS_PER_BITCOIN, LEAF_VERSION_TAPSCRIPT
from bitcoinutils.schnorr import full_pubkey_gen, point_add, point_mul, G
import struct


class Secp256k1Params:
    # ECDSA curve using secp256k1 is defined by: y**2 = x**3 + 7
    # This is done modulo p which (secp256k1) is:
    # p is the finite field prime number and is equal to:
    # 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    # Note that we could also get that from ecdsa lib from the curve, e.g.:
    # SECP256k1.__dict__['curve'].__dict__['_CurveFp__p']
    _p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    # Curve's a and b are (y**2 = x**3 + a*x + b)
    _a = 0x0000000000000000000000000000000000000000000000000000000000000000
    _b = 0x0000000000000000000000000000000000000000000000000000000000000007
    # Curve's generator point is:
    _Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    _Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    # prime number of points in the group (the order)
    _order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    # field
    _field = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

    # The ECDSA curve (secp256k1) is:
    # Note that we could get that from ecdsa lib, e.g.:
    # SECP256k1.__dict__['curve']
    _curve = ellipticcurve.CurveFp(_p, _a, _b)

    # The generator base point is:
    # Note that we could get that from ecdsa lib, e.g.:
    # SECP256k1.__dict__['generator']
    _G = ellipticcurve.Point(_curve, _Gx, _Gy, _order)


class ControlBlock:
    """Represents a control block for spending a taproot script path

    Attributes
    ----------
    pubkey : PublicKey
        the internal public key object
    scripts : list[ list[Script] ]
        a list of list of Scripts describing the merkle tree of scripts to commit
    merkle_path : bytes
        the pre-calculated merkle path

    Methods
    -------
    to_bytes()
        returns the control block as bytes
    to_hex()
        returns the control block as a hexadecimal string
    """

    def __init__(
        self,
        pubkey: PublicKey,
        scripts: None | list[list[Script]],
        index: int,
        is_odd=False,
    ):
        """
        Parameters
        ----------
        pubkey : PublicKey
            the internal public key object
        scripts : list[list[Script]]
            a list of list of Scripts describing the merkle tree of scripts to commit
        index : int
            the index of the leaf taproot using which to execute the transaction
        """
        self.pubkey = pubkey
        self.scripts = scripts
        self.merkle_path = _generate_merkle_path(scripts, index)
        self.is_odd = is_odd

    def to_bytes(self) -> bytes:
        leaf_version = bytes([(1 if self.is_odd else 0) + LEAF_VERSION_TAPSCRIPT])
        # x-only public key is required
        pub_key = bytes.fromhex(self.pubkey.to_x_only_hex())
        return leaf_version + pub_key + self.merkle_path

    def to_hex(self):
        """Converts object to hexadecimal string"""
        return b_to_h(self.to_bytes())


def _generate_merkle_path(all_leafs, target_leaf_index):
    """Generate the merkle path for spending a taproot path.

    Parameters
    ----------
    all_leafs : list
        List of all taproot leaf scripts. Can be nested.
    target_leaf_index : int
        Index of the target leaf script for which to generate the merkle path.

    Returns
    ----------
    merkle_path : bytes
        Tagged hash representing the merkle path.
    """
    traversed = 0

    def traverse_level(level):
        nonlocal traversed
        if isinstance(level, list):
            if len(level) == 1:
                return traverse_level(level[0])
            if len(level) == 2:
                a, a1 = traverse_level(level[0])
                b, b1 = traverse_level(level[1])
                if a1:
                    return (a + b), True
                if b1:
                    return (b + a), True
                return tapbranch_tagged_hash(a, b), False
            raise ValueError(
                "Invalid Merkle branch: List cannot have more than 2 branches."
            )
        else:
            if traversed == target_leaf_index:
                traversed += 1
                return b"", True
            traversed += 1
            return tapleaf_tagged_hash(level), False

    merkle_path = traverse_level(all_leafs)

    return merkle_path[0]


def get_tag_hashed_merkle_root(
    scripts: None | Script | list[Script] | list[list[Script]],
) -> bytes:
    """Tag hashed merkle root of all scripts - tag hashes tapleafs and branches
    as needed.

    Scripts is a list of list of Scripts describing the merkle tree of scripts to commit
    Example of scripts' list:  [ [A, B], C ]
    """
    # empty scripts or empty list
    if not scripts:
        return b""
    # print('1')
    # if not list return tapleaf_hash of Script
    if not isinstance(scripts, list):
        # print('2')
        return tapleaf_tagged_hash(scripts)
    # list
    else:
        if len(scripts) == 0:
            # print('3')
            return b""
        elif len(scripts) == 1:
            # print('4')
            return get_tag_hashed_merkle_root(scripts[0])
        elif len(scripts) == 2:
            # print('5')
            left = get_tag_hashed_merkle_root(scripts[0])
            right = get_tag_hashed_merkle_root(scripts[1])
            return tapbranch_tagged_hash(left, right)
        else:
            # Raise an error if a branch node contains more than two elements
            raise ValueError(
                "Invalid Merkle branch: List cannot have more than 2 branches."
            )


def to_satoshis(num: int | float | Decimal):
    """
    Converts from any number type (int/float/Decimal) to satoshis (int)
    """
    # we need to round because of how floats are stored internally:
    # e.g. 0.29 * 100000000 = 28999999.999999996
    return int(round(num * SATOSHIS_PER_BITCOIN))


def prepend_compact_size(data: bytes) -> bytes:
    """
    Counts bytes and returns them with their varint (or compact size) prepended.
    """
    varint_bytes = encode_varint(len(data))
    return varint_bytes + data


def encode_varint(i: int) -> bytes:
    """
    Encode a potentially very large integer into varint bytes. The length should be
    specified in little-endian.

    https://bitcoin.org/en/developer-reference#compactsize-unsigned-integers
    """
    if i < 253:
        return bytes([i])
    elif i < 0x10000:
        return b"\xfd" + i.to_bytes(2, "little")
    elif i < 0x100000000:
        return b"\xfe" + i.to_bytes(4, "little")
    elif i < 0x10000000000000000:
        return b"\xff" + i.to_bytes(8, "little")
    else:
        raise ValueError("Integer is too large: %d" % i)


def parse_compact_size(data: bytes) -> tuple:
    """
    Parse variable integer. Returns (count, size)
    """
    first_byte = data[0]
    if first_byte < 0xFD:
        return (first_byte, 1)
    elif first_byte == 0xFD:
        return (struct.unpack("<H", data[1:3])[0], 3)
    elif first_byte == 0xFE:
        return (struct.unpack("<I", data[1:5])[0], 5)
    elif first_byte == 0xFF:
        return (struct.unpack("<Q", data[1:9])[0], 9)


def get_transaction_length(data: bytes) -> int:
    """
    Return length of a transaction, including handling for SegWit transactions.
    """
    offset = 0

    # Version (4 bytes)
    offset += 4

    # Check for SegWit marker and flag
    marker, flag = data[offset], data[offset + 1]
    is_segwit = marker == 0 and flag != 0
    if is_segwit:
        offset += 2  # Skip marker and flag

    # Number of Inputs (CompactSize)
    num_inputs, size = parse_compact_size(data[offset:])
    offset += size

    # Inputs
    for _ in range(num_inputs):
        # Previous output (32 bytes + 4 bytes)
        offset += 36
        # Script length
        script_length, size = parse_compact_size(data[offset:])
        offset += size
        # Script + sequence number
        offset += script_length + 4

    # Number of Outputs (CompactSize)
    num_outputs, size = parse_compact_size(data[offset:])
    offset += size

    # Outputs
    for _ in range(num_outputs):
        # Value (8 bytes)
        offset += 8
        # Script length
        script_length, size = parse_compact_size(data[offset:])
        offset += size
        # Script
        offset += script_length

    # Witness Data
    if is_segwit:
        for _ in range(num_inputs):
            num_witness_items, size = parse_compact_size(data[offset:])
            offset += size
            for __ in range(num_witness_items):
                witness_length, size = parse_compact_size(data[offset:])
                offset += size + witness_length

    # Lock time (4 bytes)
    offset += 4

    return offset


def is_address_bech32(address: str) -> bool:
    """
    Returns if an address (string) is bech32 or not
    """
    if not address:
        return False

    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    # Check if the string has valid characters
    for char in address:
        if char.lower() not in CHARSET:
            return False
    try:
        hrp, data = address.lower().split("1")
    except ValueError:
        return False
    # Check if the human-readable part (hrp) and data part are of appropriate lengths
    if len(hrp) < 1 or len(data) < 6:
        return False
    return True


def vi_to_int(byteint: bytes) -> Tuple[int, int]:
    """
    Converts varint bytes to int
    """
    if not isinstance(byteint, (bytes)):
        raise Exception("Byteint must be a list or defined as bytes")

    ni = byteint[0]
    if ni < 253:
        return ni, 1
    if ni == 253:  # integer of 2 bytes
        size = 2
    elif ni == 254:  # integer of 4 bytes
        size = 4
    else:  # integer of 8 bytes
        size = 8
    return int.from_bytes(byteint[1 : 1 + size][::-1], "big"), size + 1


def add_magic_prefix(message: str) -> bytes:
    """
    Required prefix when signing a message
    """
    magic_prefix = b"\x18Bitcoin Signed Message:\n"
    # need to use varint for big messages
    # note that previously big-endian was used but varint uses little-endian
    # successfully tested with signatures from bitcoin core but keep this in mind
    message_size = encode_varint(len(message))
    message_encoded = message.encode("utf-8")
    message_magic = magic_prefix + message_size + message_encoded
    return message_magic


def tagged_hash(data: bytes, tag: str) -> bytes:
    """
    Tagged hashes ensure that hashes used in one context can not be used in another.
    It is used extensively in Taproot

    A tagged hash is: SHA256( SHA256("TapTweak") ||
                              SHA256("TapTweak") ||
                              data
                            )
    """

    tag_digest = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_digest + tag_digest + data).digest()


def calculate_tweak(
    pubkey: PublicKey, scripts: None | Script | list[Script] | list[list[Script]] | bytes
) -> int:
    """
    Calculates the tweak to apply to the public and private key when required.
    """

    # only the x coordinate is tagged_hash'ed
    key_x = pubkey.to_bytes()[:32]

    if not scripts:
        tweak = tagged_hash(key_x, "TapTweak")
    elif isinstance(scripts, bytes):
        tweak = tagged_hash(key_x + scripts, "TapTweak")
    else:
        # if also script spending this should include the tapleaf of the
        # versioned script!
        merkle_root = get_tag_hashed_merkle_root(scripts)
        tweak = tagged_hash(key_x + merkle_root, "TapTweak")

    # we convert to int for later elliptic curve  arithmetics
    tweak_int = b_to_i(tweak)

    return tweak_int


def tapleaf_tagged_hash(script: Script) -> bytes:
    """Calculates the tagged hash for a tapleaf"""
    script_part = bytes([LEAF_VERSION_TAPSCRIPT]) + prepend_compact_size(
        script.to_bytes()
    )
    return tagged_hash(script_part, "TapLeaf")


def tapbranch_tagged_hash(thashed_a: bytes, thashed_b: bytes) -> bytes:
    """Calculates the tagged hash for a tapbranch"""
    # order - smaller left side
    if thashed_a < thashed_b:
        return tagged_hash(thashed_a + thashed_b, "TapBranch")
    else:
        return tagged_hash(thashed_b + thashed_a, "TapBranch")


def negate_privkey(key: bytes) -> str:
    """Negate private key, if necessary"""

    # get the public key from BIP-340 schnorr ref impl.
    internal_pubkey_bytes = full_pubkey_gen(key)
    pubkey_hex = internal_pubkey_bytes.hex()

    # negate private key if necessary
    if int(pubkey_hex[64:], 16) % 2 == 0:
        negated_key = h_to_i(key.hex())
    else:
        key_secret_exponent = h_to_i(key.hex())
        # negate private key
        negated_key = Secp256k1Params._order - key_secret_exponent

    return f"{negated_key:064x}"

def tweak_taproot_pubkey(internal_pubkey: bytes, tweak: int) -> Tuple[bytes, bool]:
    """
    Tweaks the public key with the specified tweak. Required to create the
    taproot public key from the internal key.
    """

    # calculate tweak
    # tweak_int = calculate_tweak( internal_pubkey, script )

    # convert public key bytes to tuple Point
    x = h_to_i(internal_pubkey[:32].hex())
    y = h_to_i(internal_pubkey[32:].hex())

    # if y is odd then negate y (effectively P) to make it even and equivalent
    # to a 02 compressed pk
    if y % 2 != 0:
        y = Secp256k1Params._field - y
    P = (x, y)

    # apply tweak to public key (Q = P + th*G)
    Q = point_add(P, (point_mul(G, tweak)))

    # stores if it's odd to correct the control block bit
    is_odd = False

    # negate Q as well before returning ?!?
    if Q[1] % 2 != 0:  # type: ignore
        is_odd = True
        Q = (Q[0], Secp256k1Params._field - Q[1])  # type: ignore

    # print(f'Tweaked Public Key: {Q[0]:064x}{Q[1]:064x}')
    return bytes.fromhex(f"{Q[0]:064x}{Q[1]:064x}"), is_odd  # type: ignore


def tweak_taproot_privkey(privkey: bytes, tweak: int) -> bytes:
    """
    Tweaks the private key before signing with it. Check if public key's y
    is even and negate the private key before tweaking if it is not.
    """

    # get the public key from BIP-340 schnorr ref impl.
    internal_pubkey_bytes = full_pubkey_gen(privkey)

    # tweak_int = calculate_tweak( internal_pubkey_bytes, script )

    internal_pubkey_hex = internal_pubkey_bytes.hex()

    # negate private key if necessary
    if int(internal_pubkey_hex[64:], 16) % 2 == 0:
        negated_key = privkey.hex()
    else:
        negated_key = negate_privkey(privkey)

    # The tweaked private key can be computed by d + hash(P || S)
    # where d is the normal private key, P is the normal public key
    # and S is the alt script, if any (empty script, if none?? TODO)
    tweaked_privkey_int = (h_to_i(negated_key) + tweak) % Secp256k1Params._order

    # print(f'Tweaked Private Key:', hex(tweaked_privkey_int)[2:])
    return bytes.fromhex(f"{tweaked_privkey_int:064x}")


#
# Basic conversions between bytes (b), hexadecimal (h) and integer (i)
# Some were trivial but included for consistency.
#
def b_to_h(b: bytes) -> str:
    """Converts bytes to hexadecimal string"""
    return b.hex()


def h_to_b(h: str) -> bytes:
    """Converts hexadecimal string to bytes"""
    return bytes.fromhex(h)


def h_to_i(hex_str: str) -> int:
    """Converts a string hexadecimal to a number"""
    return int(hex_str, base=16)


def i_to_h64(i: int) -> str:
    """Converts an int to a string hexadecimal (padded to 64 hex chars)"""
    return f"{i:064x}"


# to convert hashes to ints we need byteorder BIG...
def b_to_i(b: bytes) -> int:
    """Converts a bytes to a number"""
    return int.from_bytes(b, byteorder="big")


def i_to_b32(i: int) -> bytes:
    """Converts a integer to bytes"""
    return i.to_bytes(32, byteorder="big")


def i_to_b(i: int) -> bytes:
    """Converts a integer to bytes"""
    # determine the number of bytes required to represent the integer
    byte_length = (i.bit_length() + 7) // 8
    return i.to_bytes(byte_length, "big")


# TODO are these required - maybe bytestoint and inttobytes are only required?!?

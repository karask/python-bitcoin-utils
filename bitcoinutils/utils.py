# Copyright (C) 2018-2022 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from hashlib import sha256
from binascii import hexlify, unhexlify
from ecdsa import ellipticcurve
from bitcoinutils.constants import SATOSHIS_PER_BITCOIN
from bitcoinutils.schnorr import full_pubkey_gen, point_add, point_mul, G


# TODO rename to Secp256k1Params and clean whatever is not used!
class EcdsaParams:
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
    _Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    # prime number of points in the group (the order)
    _order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    # field
    _field = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

    # The ECDSA curve (secp256k1) is:
    # Note that we could get that from ecdsa lib, e.g.:
    # SECP256k1.__dict__['curve']
    _curve = ellipticcurve.CurveFp( _p, _a, _b )

    # The generator base point is:
    # Note that we could get that from ecdsa lib, e.g.:
    # SECP256k1.__dict__['generator']
    _G = ellipticcurve.Point( _curve, _Gx, _Gy, _order )



def to_satoshis(num):
    '''
    Converts from any number type (int/float/Decimal) to satoshis (int)
    '''
    # we need to round because of how floats are stored insternally:
    # e.g. 0.29 * 100000000 = 28999999.999999996
    return int( round(num * SATOSHIS_PER_BITCOIN) )


def prepend_varint(data):
    '''
    Counts bytes and returns them with their varint (or compact size) prepended.
    Accepts bytes and returns bytes.
    '''
    varint_bytes = encode_varint( len(data) )
    return varint_bytes + data


def encode_varint(i):
    '''
    Encode a potentially very large integer into varint bytes. The length should be
    specified in little-endian.

    https://bitcoin.org/en/developer-reference#compactsize-unsigned-integers
    '''
    if i < 253:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' +  i.to_bytes(2, 'little')
    elif i < 0x100000000:
        return b'\xfe' +  i.to_bytes(4, 'little')
    elif i < 0x10000000000000000:
        return b'\xff' +  i.to_bytes(8, 'little')
    else:
        raise ValueError("Integer is too large: %d" % i)


def is_address_bech32(address):
    '''
    Returns if an address (string) is bech32 or not
    TODO improve by checking if valid, etc.
    '''
    if (address.startswith('bc') or
        address.startswith('tb')):
        return True

    return False


def vi_to_int(byteint):
    '''
    Converts varint bytes to int
    '''
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

    return int.from_bytes(byteint[1:1+size][::-1], 'big'), size + 1


# TODO name hex_to_bytes ??
def to_bytes(string, unhexlify=True):
    '''
	Converts a hex string to bytes
    '''
    if not string:
        return b''
    if unhexlify:
        try:
            if isinstance(string, bytes):
                string = string.decode()
            s = bytes.fromhex(string)
            return s
        except (TypeError, ValueError):
            pass
    if isinstance(string, bytes):
        return string
    else:
        return bytes(string, 'utf8')


def bytes32_from_int(x: int) -> bytes:
    '''
    Converts int to 32 big-endian bytes 
    '''
    return x.to_bytes(32, byteorder="big")


# TODO REMOVE --- NOT USED
#def int_from_bytes(b: bytes) -> int:
#    '''
#    Converts int to bytes
#    '''
#    return int.from_bytes(b, byteorder="big")


def add_magic_prefix(message):
    '''
    Required prefix when signing a message
    '''
    magic_prefix = b'\x18Bitcoin Signed Message:\n'
    # need to use varint for big messages
    # note that previously big-endian was used but varint uses little-endian
    # successfully tested with signatures from bitcoin core but keep this in mind
    message_size = encode_varint(len(message))
    message_encoded = message.encode('utf-8')
    message_magic = magic_prefix + message_size + message_encoded
    return message_magic


def tagged_hash(data: bytes, tag: str) -> bytes:
    '''
    Tagged hashes ensure that hashes used in one context can not be used in another.
    It is used extensively in Taproot

    A tagged hash is: SHA256( SHA256("TapTweak") || 
                              SHA256("TapTweak") ||
                              data
                            )
    Returns hashlib object (can then use .digest() or hexdigest())
    '''

    tag_digest = sha256(tag.encode()).digest()
    return sha256( tag_digest + tag_digest + data )


# TODO script also needs to be passed when spending with script
# since it is part of the calculation
def tweak_taproot_pubkey(pubkey: bytes, tweak: str) -> str:
    '''
    Tweaks the public key with the specified tweak. Required to create the
    taproot public key from the internal key.
    '''

    # only the x coordinate is tagged_hash'ed
    # TODO if also script spending this should include the script!)
    th = tagged_hash(pubkey[:32], tweak)
    # we convert to int for later elliptic curve  arithmetics
    th_as_int = hex_str_to_int( th.hexdigest() )

    # convert public key bytes to tuple Point
    x = hex_str_to_int( pubkey[:32].hex() )
    y = hex_str_to_int( pubkey[32:].hex() )
    P = (x, y)

    # if y is odd then negate y (effectively P) to make it even and equiv
    # to a 02 compressed pk
    if y % 2 != 0:
        y = EcdsaParams._field - y 

    P = (x, y)

    # calculated tweaked public key Q = P + th*G
    Q = point_add(P, (point_mul(G, th_as_int)))
    
    return f'{Q[0]:064x}{Q[1]:064x}'


def tweak_taproot_privkey(privkey: bytes, tweak: str) -> str:
    '''
    Tweaks the private key before signing with it. Check if public key's y
    is even and negate the private key before tweaking if it is not.
    '''
    key_secret_exponent = int(hexlify(privkey).decode('utf-8'), 16)

    # get the private key from BIP-340 schnorr ref impl.
    pubkey_bytes = full_pubkey_gen(privkey)
    pubkey_x_bytes = pubkey_bytes[:32]
    pubkey_y_int = int.from_bytes(pubkey_bytes[32:], byteorder="big")

    # if y coordinate is not even, negate private key
    if pubkey_y_int % 2 != 0:
        # negate private key
        key_secret_exponent = EcdsaParams._order - key_secret_exponent

    # tag hash the public key (bytes)
    th = tagged_hash(pubkey_x_bytes, tweak)
    th_as_int = hex_str_to_int( th.hexdigest() )

    # The tweaked private key can be computed by d + hash(P || S)
    # where d is the normal private key, P is the normal public key
    # and S is the alt script, if any (empty script, if none?? TODO)
    tweaked_privkey_int = (key_secret_exponent + th_as_int) % EcdsaParams._order

    return hex(tweaked_privkey_int)[2:]



# TODO are these required - maybe bytestoint and inttobytes are only required?!?
def hex_str_to_int(hex_str):
    '''
    Converts a string hexadecimal to a number
    '''
    return int(hex_str, base=16) 


def int_to_hex_str(i):
    '''
    Converts an int to a string hexadecimal to a number (starting with 0x)
    '''
    return f'{i:064x}'



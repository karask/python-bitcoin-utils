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

import hashlib
from binascii import hexlify, unhexlify
from ecdsa import ellipticcurve
from bitcoinutils.constants import SATOSHIS_PER_BITCOIN, LEAF_VERSION_TAPSCRIPT
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



class ControlBlock:
    '''Represents a control block for spending a taproot script path

    Attributes
    ----------
    pubkey : PublicKey
        the public key object
    scripts : list (Script)
        a list of Scripts lexicographically ordered to construct the merkle root

    Methods
    -------
    to_bytes()
        returns the control block as bytes
    to_hex()
        returns the control block as a hexadecimal string
    '''


    def __init__(self, pubkey, scripts):
        '''
        Parameters
        ----------
        pubkey : PublicKey
            the internal public key object
        scripts : list (Script)
            a list of Scripts lexicographically ordered to construct the merkle root
        '''
        self.pubkey = pubkey
        self.scripts = scripts


    def to_bytes(self):
        # leaf version is fixed but we check if the public key required negation
        # if negated (y is odd) add one to the leaf_version
        #if int(self.pubkey.to_hex()[-2:], 16) % 2 == 0:
        #    leaf_version = bytes([LEAF_VERSION_TAPSCRIPT])
        #else:
        #    leaf_version = bytes([LEAF_VERSION_TAPSCRIPT + 1])
        leaf_version = bytes([LEAF_VERSION_TAPSCRIPT])

        # x-only public key is required
        pub_key = bytes.fromhex( self.pubkey.to_x_only_hex() )

        # if a single alt script no merkle path is required
        if len(self.scripts) == 1:
            return leaf_version + pub_key 
        
        
        # TODO only single alternative script path for now
#        script_bytes = self.scripts[0].to_bytes()

        # tag hash the script
#        th = tagged_hash(bytes([LEAF_VERSION_TAPSCRIPT]) + prepend_varint(script_bytes), 
#                         "TapLeaf").digest()

        return leaf_version + pub_key 
        #return leaf_version + pub_key + th


    def to_hex(self):
        """Converts object to hexadecimal string"""

        return hexlify(self.to_bytes()).decode('utf-8')


def to_satoshis(num):
    '''
    Converts from any number type (int/float/Decimal) to satoshis (int)
    '''
    # we need to round because of how floats are stored internally:
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

    tag_digest = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256( tag_digest + tag_digest + data )


def calculate_tweak(pubkey: object, script: object) -> int:
    '''
    Calculates the tweak to apply to the public and private key when required.
    '''

    # only the x coordinate is tagged_hash'ed
    key_x = pubkey.to_bytes()[:32]
    if not script:
        th_final = tagged_hash(key_x, 'TapTweak')
    else:
        # if also script spending this should include the tapleaf of the versioned script!
        script_th_part = bytes([LEAF_VERSION_TAPSCRIPT]) + prepend_varint(script.to_bytes())
        th_script = tagged_hash(script_th_part, 'TapLeaf').digest()
        th_final = tagged_hash(key_x + th_script, 'TapTweak')

    # we convert to int for later elliptic curve  arithmetics
    th_as_int = hex_str_to_int( th_final.hexdigest() )

    return th_as_int


def has_even_y(key: object) -> bool:
    '''
    TODO
    '''

    if isinstance(key, bitcoinutils.keys.PrivateKey):
        return 'PrivateKey'


########################################################
# Split in several methods as part of PublicKey object #
########################################################
def tweak_taproot_pubkey(internal_pubkey: bytes, script: bytes) -> bytes:
    '''
    Tweaks the public key with the specified tweak. Required to create the
    taproot public key from the internal key.
    '''

    internal_pubkey_obj = bitcoinutils.keys.PublicKey( '04' + internal_pubkey.hex() )

    # calculate tweak
    tweak_int = calculate_tweak( internal_pubkey_obj, script )

    # convert public key bytes to tuple Point
    x = hex_str_to_int( internal_pubkey[:32].hex() )
    y = hex_str_to_int( internal_pubkey[32:].hex() )

    # if y is odd then negate y (effectively P) to make it even and equivalent
    # to a 02 compressed pk
    if y % 2 != 0:
        y = EcdsaParams._field - y 
    P = (x, y)

    # calculated tweaked public key Q = P + th*G
    Q = point_add(P, (point_mul(G, tweak_int)))
    
    # negate Q as well before returning ?!?
    if Q[1] % 2 != 0:
        Q = ( Q[0], EcdsaParams._field - Q[1] )

    #print(f'Tweaked Public Key: {Q[0]:064x}{Q[1]:064x}')
    return bytes.fromhex( f'{Q[0]:064x}{Q[1]:064x}' )


#########################################################
# Split in several methods as part of PrivateKey object #
#########################################################
def tweak_taproot_privkey(privkey: bytes, script: bytes) -> bytes:
    '''
    Tweaks the private key before signing with it. Check if public key's y
    is even and negate the private key before tweaking if it is not.
    '''

    # get the public key from BIP-340 schnorr ref impl.
    internal_privkey = bitcoinutils.keys.PrivateKey.from_bytes(privkey)
    internal_pubkey = internal_privkey.get_public_key()

    tweak_int = calculate_tweak( internal_pubkey, script )

    # negate private key if necessary
    if internal_pubkey.is_y_even():
        negated_key = internal_privkey.to_bytes().hex()
    else:
        negated_key = internal_privkey.get_negated_key()

    # The tweaked private key can be computed by d + hash(P || S)
    # where d is the normal private key, P is the normal public key
    # and S is the alt script, if any (empty script, if none?? TODO)
    tweaked_privkey_int = (hex_str_to_int(negated_key) + tweak_int) % EcdsaParams._order

    #print(f'Tweaked Private Key:', hex(tweaked_privkey_int)[2:])
    return bytes.fromhex( hex(tweaked_privkey_int)[2:] )



# TODO are these required - maybe bytestoint and inttobytes are only required?!?
def hex_str_to_int(hex_str):
    '''
    Converts a string hexadecimal to a number
    '''
    return int(hex_str, base=16) 


#def int_to_hex_str(i):
#    '''
#    Converts an int to a string hexadecimal to a number (starting with 0x)
#    '''
#    return f'{i:064x}'



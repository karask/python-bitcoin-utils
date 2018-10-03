# Copyright (C) 2018 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

# Classes related to Bitcoin private/public keys and addresses
#
# The rational of the classes and their method is that inputs are typically hex
# strings as displayed by blockexplorers and other such software. Internally data
# will be represented and operated upon in bytes. Finally, methods that return
# data intended for display will be converted to hex string again.

from hashlib import sha256
from binascii import unhexlify, hexlify
from base58check import b58encode, b58decode
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from sympy.ntheory import sqrt_mod

# if any of these is update WE NEED to uninstall/install lib again
from bitcoinutils.constants import NETWORK_BASE58_WIF_PREFIXES
from bitcoinutils.setup import setup, get_network

'''
PrivateKey
'''
class PrivateKey:

    def __init__(self, wif=None, secret_exponent=None):

        if not secret_exponent and not wif:
            self.is_compressed = True
            self.key = SigningKey.generate()
        else:
            if wif:
                self.from_wif(wif)
            elif secret_exponent:
                self.is_compressed = True
                self.key = SigningKey.from_secret_exponent(secret_exponent,
                                                           curve=SECP256k1)

    def to_bytes(self):
        return self.key.to_string()

    # expects wif in hex string
    def from_wif(self, wif):
        wif_utf = wif.encode('utf-8')

        # decode base58check get key bytes plus checksum
        data_bytes = b58decode( wif_utf )
        key_bytes = data_bytes[:-4]
        checksum = data_bytes[-4:]

        # verify key with checksum
        data_hash = sha256(sha256(key_bytes).digest()).digest()
        if not checksum == data_hash[0:4]:
            raise ValueError('Checksum is wrong. Possible mistype?')

        # get network prefix and check with current setup
        network_prefix = key_bytes[:1]
        if NETWORK_BASE58_WIF_PREFIXES[get_network()] != network_prefix:
            raise ValueError('Using the wrong network!')

        # remove network prefix
        key_bytes = key_bytes[1:]

        # check length of bytes and if > 32 then compressed
        # use this to instantite an ecdsa key
        if len(key_bytes) > 32:
            self.is_compressed = True
            self.key = SigningKey.from_string(key_bytes[:-1], curve=SECP256k1)
        else:
            self.is_compressed = False
            self.key = SigningKey.from_string(key_bytes, curve=SECP256k1)


    def to_wif(self, compressed=None):
        # add network prefix to the key
        key_bytes = NETWORK_BASE58_WIF_PREFIXES[get_network()] + self.to_bytes()

        # add suffix if compressed -- if parameter was passed explicitly it
        # supercedes creation compression state
        if compressed == True:
            key_bytes += b'\x01'
        elif compressed == False:
            pass
        else:
            if self.is_compressed:
                key_bytes += b'\x01'

        # double hash and get the first 4 bytes for checksum
        data_hash = sha256(sha256(key_bytes).digest()).digest()
        checksum = data_hash[0:4]

        # suffix the key bytes with the checksum and encode to base58check
        wif = b58encode( key_bytes + checksum )

        return wif.decode('utf-8')

    def get_public_key(self):
        verifying_key = hexlify(self.key.get_verifying_key().to_string())
        return PublicKey( '04' + verifying_key.decode('utf-8') )


'''
PublicKey
'''
class PublicKey:
    def __init__(self, hex_ascii):
        # expects key as hex string - SEC format
        first_byte_in_hex = hex_ascii[:2] # 2 since a byte is represented by 2 hex characters
        hex_bytes = unhexlify(hex_ascii)

        # check if compressed or not
        if len(hex_bytes) > 33:
            # uncompressed - SEC format: 0x04 + x + y coordinates (x,y are 32 byte numbers)
            # remove first byte and instantiate ecdsa key
            self.key = VerifyingKey.from_string(hex_bytes[1:], curve=SECP256k1)
        else:
            # compressed - SEC FORMAT: 0x02|0x03 + x coordinate (if 02 then y
            # is even else y is old. Calculate y and then instantiate the ecdsa key
            x_coord = int( hex_ascii[2:], 16 )

            # ECDSA curve using secp256k1 is defined by: y**2 = x**3 + 7
            # This is done modulo p which (secp256k1) is:
            p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

            # y = modulo_square_root( (x**3 + 7) mod p ) -- there will be 2 y values
            y_values = sqrt_mod( (x_coord**3 + 7) % p, p, True )

            # check SEC format's first byte to determine which of the 2 values to use
            if first_byte_in_hex == '02':
                # y is the even value
                if y_values[0] % 2 == 0:
                    y_coord = y_values[0]
                else:
                    y_coord = y_values[1]
            elif first_byte_in_hex == '03':
                # y is the odd value
                if y_values[0] % 2 == 0:
                    y_coord = y_values[1]
                else:
                    y_coord = y_values[0]
            else:
                raise TypeError("Invalid SEC compressed format")

            uncompressed_hex = "%0.64X%0.64X" % (x_coord, y_coord)
            uncompressed_hex_bytes = unhexlify(uncompressed_hex)
            self.key = VerifyingKey.from_string(uncompressed_hex_bytes, curve=SECP256k1)


    def to_bytes(self):
        return self.key.to_string()

    def to_hex(self, compressed=True):
        key_hex = hexlify(self.key.to_string())

        if compressed:
            # check if y is even or odd
            if int(key_hex[-2:], 16) % 2 == 0:
                key_str = b'02' + key_hex[:64]
            else:
                key_str = b'03' + key_hex[:64]
        else:
            key_str = b'04' + key_hex

        return key_str.decode('utf-8')


def main():
    setup('mainnet')
    priv = PrivateKey('KzVpbhbE6vF8HhybZLypQw8qgGsj53KrT7njHQNcrCiboFrVT9jY')
    print(priv.to_wif())
    print(priv.to_wif(compressed=False))
    pub = priv.get_public_key()
    print(pub.to_hex())
    #print("-----------")
    #p1 = PublicKey('040F031CA83F3FB372BD6C2430119E0B947CF059D19CDEA98F4CEFFEF620C584F9F064F1FDE4BC07D4F48C5114680AD1ADAF5F6EAA2166F7E4B4887703A681B548')
    #print(p1.to_bytes())
    #print(p1.to_hex())
    #p2 = PublicKey('020F031CA83F3FB372BD6C2430119E0B947CF059D19CDEA98F4CEFFEF620C584F9')
    #print(p2.to_bytes())
    #print(p2.to_hex())

if __name__ == "__main__":
    main()

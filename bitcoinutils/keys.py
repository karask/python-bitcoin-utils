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

import re
import hashlib
from binascii import unhexlify, hexlify
from base58check import b58encode, b58decode
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from sympy.ntheory import sqrt_mod

# TODELETE if any of these is updated WE NEED to uninstall/install lib again
from bitcoinutils.constants import NETWORK_WIF_PREFIXES, NETWORK_P2PKH_PREFIXES
from bitcoinutils.setup import setup, get_network

class PrivateKey:
    """Represents an ECDSA private key.

    Attributes
    ----------
    key : bytes
        the raw key of 32 bytes

    Methods
    -------
    from_wif(wif)
        creates an object from a WIF of WIFC format (string)
    to_wif(compressed=True)
        returns as WIFC (compressed) or WIF format (string)
    to_bytes()
        returns the key's raw bytes
    get_public_key()
        returns the corresponding PublicKey object
    """

    def __init__(self, wif=None, secret_exponent=None):
        """With no parameters a random key is created

        Parameters
        ----------
        wif : str, optional
            the key in WIF of WIFC format (default None)
        secret_exponent : int, optional
            used to create a specific key deterministically (default None)
        """

        if not secret_exponent and not wif:
            self.key = SigningKey.generate()
        else:
            if wif:
                self._from_wif(wif)
            elif secret_exponent:
                self.key = SigningKey.from_secret_exponent(secret_exponent,
                                                           curve=SECP256k1)

    def to_bytes(self):
        """Returns key's bytes"""

        return self.key.to_string()


    @classmethod
    def from_wif(cls, wif):
        """Creates key from WIFC or WIF format key"""

        return cls(wif=wif)


    # expects wif in hex string
    def _from_wif(self, wif):
        """Creates key from WIFC or WIF format key

        Check to_wif for the detailed process. From WIF is the reverse.

        Raises
        ------
        ValueError
            if the checksum is wrong or if the WIF/WIFC is not from the
            configured network.
        """

        wif_utf = wif.encode('utf-8')

        # decode base58check get key bytes plus checksum
        data_bytes = b58decode( wif_utf )
        key_bytes = data_bytes[:-4]
        checksum = data_bytes[-4:]

        # verify key with checksum
        data_hash = hashlib.sha256(hashlib.sha256(key_bytes).digest()).digest()
        if not checksum == data_hash[0:4]:
            raise ValueError('Checksum is wrong. Possible mistype?')

        # get network prefix and check with current setup
        network_prefix = key_bytes[:1]
        if NETWORK_WIF_PREFIXES[get_network()] != network_prefix:
            raise ValueError('Using the wrong network!')

        # remove network prefix
        key_bytes = key_bytes[1:]

        # check length of bytes and if > 32 then compressed
        # use this to instantite an ecdsa key
        if len(key_bytes) > 32:
            self.key = SigningKey.from_string(key_bytes[:-1], curve=SECP256k1)
        else:
            self.key = SigningKey.from_string(key_bytes, curve=SECP256k1)


    def to_wif(self, compressed=True):
        """Returns key in WIFC or WIF string

        key_bytes = (32 bytes number) [ + 0x01 if compressed ]
        network_prefix = (1 byte version number)
        data_hash = SHA-256( SHA-256( key_bytes ) )
        checksum = (first 4 bytes of data_hash)
        wif = Base58CheckEncode( key_bytes + checksum )
        """

        # add network prefix to the key
        key_bytes = NETWORK_WIF_PREFIXES[get_network()] + self.to_bytes()

        if compressed == True:
            key_bytes += b'\x01'

        # double hash and get the first 4 bytes for checksum
        data_hash = hashlib.sha256(hashlib.sha256(key_bytes).digest()).digest()
        checksum = data_hash[0:4]

        # suffix the key bytes with the checksum and encode to base58check
        wif = b58encode( key_bytes + checksum )

        return wif.decode('utf-8')


    def get_public_key(self):
        """Returns the corresponding PublicKey"""

        verifying_key = hexlify(self.key.get_verifying_key().to_string())
        return PublicKey( '04' + verifying_key.decode('utf-8') )


class PublicKey:
    """Represents an ECDSA public key.

    Attributes
    ----------
    key : bytes
        the raw public key of 64 bytes (x, y coordinates of the ECDSA curve

    Methods
    -------
    from_hex(hex_str)
        creates an object from a hex string
    to_hex(compressed=True)
        returns the key as hex string (compressed format by default)
    to_bytes()
        returns the key's raw bytes
    get_address(compressed=True))
        returns the corresponding Address object
    """


    def __init__(self, hex_str):
        """
        Parameters
        ----------
        hex_str : str
            the public key in hex string

        Raises
        ------
            TypeError
                If first byte of public key (corresponding to SEC format) is
                invalid.
        """

        # expects key as hex string - SEC format
        first_byte_in_hex = hex_str[:2] # 2 since a byte is represented by 2 hex characters
        hex_bytes = unhexlify(hex_str)

        # check if compressed or not
        if len(hex_bytes) > 33:
            # uncompressed - SEC format: 0x04 + x + y coordinates (x,y are 32 byte numbers)
            # remove first byte and instantiate ecdsa key
            self.key = VerifyingKey.from_string(hex_bytes[1:], curve=SECP256k1)
        else:
            # compressed - SEC FORMAT: 0x02|0x03 + x coordinate (if 02 then y
            # is even else y is old. Calculate y and then instantiate the ecdsa key
            x_coord = int( hex_str[2:], 16 )

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

    @classmethod
    def from_hex(cls, hex_str):
        """Creates a public key from a hex string"""

        return cls(hex_str)

    def to_bytes(self):
        """Returns key's bytes"""

        return self.key.to_string()

    def to_hex(self, compressed=True):
        """Creates a public key from a hex string"""

        key_hex = hexlify(self.key.to_string())

        if compressed:
            # check if y is even or odd (02 even, 03 odd)
            if int(key_hex[-2:], 16) % 2 == 0:
                key_str = b'02' + key_hex[:64]
            else:
                key_str = b'03' + key_hex[:64]
        else:
            # uncompressed starts with 04
            key_str = b'04' + key_hex

        return key_str.decode('utf-8')

    def get_address(self, compressed=True):
        """Returns the corresponding Address (default compressed)"""

        pubkey = unhexlify( self.to_hex(compressed) )
        hashsha256 = hashlib.sha256(pubkey).digest()
        hashripemd160 = hashlib.new('ripemd160')
        hashripemd160.update(hashsha256)
        hash160 = hashripemd160.digest()
        addr_string_hex = hexlify(hash160).decode('utf-8')
        return P2pkhAddress(hash160=addr_string_hex)


class P2pkhAddress:
    """Represents a Bitcoin address derived from a public key

    Attributes
    ----------
    hash160 : str
        the hash160 representation of the address

    Methods
    -------
    from_address(address)
        instantiates an object from address string encoding
    from_hash160(hash160_str)
        instantiates an object from a hash160 hex string
    to_address()
        returns the address's string encoding
    to_hash160()
        returns the address's hash160 hex string representation

    Raises
    ------
    TypeError
        If an invalid address or hash160 is provided.
    """

    def __init__(self, address=None, hash160=None):
        """
        Parameters
        ----------
        address : str
            the address as a string
        hash160 : str
            the hash160 hex string representation
        """

        if hash160:
            if self._is_hash160_valid(hash160):
                self.hash160 = hash160
            else:
                raise ValueError("Invalid value for parameter hash160.")
        elif address:
            if self._is_address_valid(address):
                self.hash160 = self._address_to_hash160(address)
            else:
                raise ValueError("Invalid value for parameter address.")
        else:
            raise TypeError("A valid address or hash160 is required.")

    @classmethod
    def from_address(cls, address):
        """blah"""

        return cls(address=address)


    @classmethod
    def from_hash160(cls, hash160):
        """blah"""

        return cls(hash160=hash160)


    def _address_to_hash160(self, address):
        addr_encoded = address.encode('utf-8')
        data_checksum = b58decode( addr_encoded )
        network_prefix = data_checksum[:1]
        data = data_checksum[1:-4]
        #checksum = data_checksum[-4:]
        return hexlify(data).decode('utf-8')


    def _is_hash160_valid(self, hash160):
        # check the size -- should be 20 bytes, 40 characters in hexadecimal string
        if len(hash160) != 40:
            return False

        # check all (string) digits are hex
        try:
            int(hash160, 16)
            return True
        except ValueError:
            return False


    def _is_address_valid(self, address):

        digits_58_pattern = r'[^123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]'

        # check for invalid characters
        if re.search(digits_58_pattern, address):
            return False

        # check for length (26-35 characters)
        # TODO: need to confirm the possible length!
        if len(address) < 26 or len(address) > 35:
            return False

        # check address' checksum
        data_checksum = b58decode( address.encode('utf-8') )
        data = data_checksum[:-4]
        checksum = data_checksum[-4:]

        data_hash = hashlib.sha256(hashlib.sha256(data).digest()).digest()

        if data_hash[0:4] != checksum:
            return False

        return True

    def to_hash160(self):
        return self.hash160

    def to_address(self):
        hash160_encoded = self.hash160.encode('utf-8')
        hash160_bytes = unhexlify(hash160_encoded)

        data = NETWORK_P2PKH_PREFIXES[get_network()] + hash160_bytes
        data_hash = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        checksum = data_hash[0:4]
        address_bytes = b58encode( data + checksum )
        return address_bytes.decode('utf-8')


def main():
    setup('mainnet')
    #priv = PrivateKey(secret_exponent = 1)
    priv = PrivateKey.from_wif('KzVpbhbE6vF8HhybZLypQw8qgGsj53KrT7njHQNcrCiboFrVT9jY')
    print(priv.to_bytes())
    print(priv.to_wif())
    print(priv.to_wif(compressed=False))
    pub = priv.get_public_key()
    print(pub.to_hex())
    print("-----------")
    print(pub.to_bytes())
    print(pub.to_hex())
    print(pub.to_hex(compressed = False))
    a = pub.get_address(compressed=False)
    print("+++++++++")
    #a = P2pkhAddress('1andreas3batLhQa2FawWjeyjCqyBzypd')
    print(a.to_hash160())
    a2 = P2pkhAddress(hash160='0663d2403f560f8d053a25fbea618eb470716176')
    print(a.to_address())
    #p1 = PublicKey.from_hex('040F031CA83F3FB372BD6C2430119E0B947CF059D19CDEA98F4CEFFEF620C584F9F064F1FDE4BC07D4F48C5114680AD1ADAF5F6EAA2166F7E4B4887703A681B548')
    #print(p1.to_bytes())
    #print(p1.to_hex())
    #p2 = PublicKey('020F031CA83F3FB372BD6C2430119E0B947CF059D19CDEA98F4CEFFEF620C584F9')
    #print(p2.to_bytes())
    #print(p2.to_hex())

if __name__ == "__main__":
    main()

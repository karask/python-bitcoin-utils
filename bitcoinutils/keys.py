'''
Classes related to private/public keys and addresses
'''
import hashlib
import binascii
import base58check
from ecdsa import SigningKey, SECP256k1

from bitcoinutils.constants import NETWORK_BASE58_WIF_PREFIXES
from bitcoinutils.setup import get_network

'''
PrivateKey
'''
class PrivateKey:

    def __init__(self, wif=None, secret_exponent=None):

        if not secret_exponent and not wif:
            self.key = SigningKey.generate()
        else:
            if wif:
                self.from_wif(wif)
            elif secret_exponent:
                self.key = SigningKey.from_secret_exponent(secret_exponent,
                                                           curve=SECP256k1)

    def to_bytes(self):
       return self.key.to_string()

    # expects wif in hex string
    def from_wif(self, wif):
        wif_bytes = wif.encode('utf-8')

        # decode base58check get key bytes plus checksum
        data_bytes = base58check.b58decode( wif_bytes )
        key_bytes = data_bytes[:-4]
        checksum = data_bytes[-4:]

        # verify key with checksum
        # ...

        # get network prefix and check with current setup
        network_prefix = key_bytes[:1]
        if NETWORK_BASE58_WIF_PREFIXES[get_network()] != network_prefix:
            raise TypeError('Using the wrong network!')

        # remove network prefix
        key_bytes = key_bytes[1:]

        # check length of bytes and if > 32 then compressed
        # use this to instantite an ecdsa key
        if len(key_bytes) > 32:
            self.key = SigningKey.from_string(key_bytes[:-1], curve=SECP256k1)
        else:
            self.key = SigningKey.from_string(key_bytes, curve=SECP256k1)


    def to_wif(self, compressed=True):
        # add network prefix to the key
        key_bytes = NETWORK_BASE58_WIF_PREFIXES[get_network()] + self.to_bytes()

        # add suffix if compressed
        if compressed:
            key_bytes += b'\x01'

        # double hash and get the first 4 bytes for checksum
        data_hash = hashlib.sha256(hashlib.sha256(key_bytes).digest()).digest()
        checksum = data_hash[0:4]

        # suffix the key bytes with the checksum and encode to base58check
        wif = base58check.b58encode( key_bytes + checksum )

        return wif

    #def get_public_key(self):
    #    self.key.get_verifying_key()


'''
PublicKey
'''
class PublicKey:
    def __init__(self, hex):
        # expects key as hex string - SEC format
        hex_bytes = hex.encode('utf-8')

        # check if compressed or not
        if len(hex_bytes) > 33:
            # uncompressed - remove first byte (\x04 for uncompressed in SEC
            # format) and instantiate ecdsa key
            self.key = VerifyingKey.from_string(hex_bytes[1:], curve=SECP256k1)
        else:
            # compressed - need to check if x or y is given and calculate the other
            # and then instantiate the ecdsa key
            #...
        pass




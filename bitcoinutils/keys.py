# Copyright (C) 2018-2020 The python-bitcoin-utils developers
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
import struct
import hashlib
from abc import ABC, abstractmethod
from base64 import b64encode, b64decode
from binascii import unhexlify, hexlify
from base58check import b58encode, b58decode
from ecdsa import SigningKey, VerifyingKey, SECP256k1, ellipticcurve, numbertheory
from ecdsa.util import sigencode_string, sigdecode_string, sigencode_der
from sympy.ntheory import sqrt_mod

from bitcoinutils.constants import NETWORK_WIF_PREFIXES, \
        NETWORK_P2PKH_PREFIXES, NETWORK_P2SH_PREFIXES, SIGHASH_ALL, \
        P2PKH_ADDRESS, P2SH_ADDRESS, P2WPKH_ADDRESS_V0, P2WSH_ADDRESS_V0, \
        NETWORK_SEGWIT_PREFIXES
from bitcoinutils.setup import get_network
import bitcoinutils.bech32
import bitcoinutils.script


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

# The ECDSA curve (secp256k1) is:
# Note that we could get that from ecdsa lib, e.g.:
# SECP256k1.__dict__['curve']
_curve = ellipticcurve.CurveFp( _p, _a, _b )

# The generator base point is:
# Note that we could get that from ecdsa lib, e.g.:
# SECP256k1.__dict__['generator']
_G = ellipticcurve.Point( _curve, _Gx, _Gy, _order )




# method used by both PrivateKey and PublicKey - TODO clean - add in another module?
def add_magic_prefix(message):
    magic_prefix = b'\x18Bitcoin Signed Message:\n'
    message_size = len(message).to_bytes(1, byteorder='big')
    message_encoded = message.encode('utf-8')
    message_magic = magic_prefix + message_size + message_encoded
    return message_magic



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
    sign_message(message, compressed=True)
        signs the message's digest and returns the signature
    sign_input(tx, txin_index, script, sighash=SIGHASH_ALL)
        signs the transaction's digest for a particular index and returns the
        signature.
    sign_segwit_input(tx, txin_index, script, amount, sighash=SIGHASH_ALL)
        signs the transaction's digest for a particular index and amount and 
        returns the signature.
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
            self.key = SigningKey.generate(curve=SECP256k1)
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

        |  Pseudocode:
        |      network_prefix = (1 byte version number)
        |      data = network_prefix + (32 bytes number/key) [ + 0x01 if compressed ]
        |      data_hash = SHA-256( SHA-256( data ) )
        |      checksum = (first 4 bytes of data_hash)
        |      wif = Base58CheckEncode( data + checksum )
        """

        # add network prefix to the key
        data = NETWORK_WIF_PREFIXES[get_network()] + self.to_bytes()

        if compressed == True:
            data += b'\x01'

        # double hash and get the first 4 bytes for checksum
        data_hash = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        checksum = data_hash[0:4]

        # suffix the key bytes with the checksum and encode to base58check
        wif = b58encode( data + checksum )

        return wif.decode('utf-8')


    def sign_message(self, message, compressed=True):
        """Signs the message with the private key (deterministically)

        Bitcoin uses a compact format for message signatures (for tx sigs it
        uses normal DER format). The format has the normal r and s parameters
        that ECDSA signatures have but also includes a prefix which encodes
        extra information. Using the prefix the public key can be
        reconstructed when verifying the signature.

        |  Prefix values:
        |      27 - 0x1B = first key with even y
        |      28 - 0x1C = first key with odd y
        |      29 - 0x1D = second key with even y
        |      30 - 0x1E = second key with odd y

        If key is compressed add 4 (31 - 0x1F, 32 - 0x20, 33 - 0x21, 34 - 0x22 respectively)

        Returns a Bitcoin compact signature in Base64
        """

        # All bitcoin signatures include the magic prefix. It is just a string
        # added to the message to distinguish Bitcoin-specific messages.
        message_magic = add_magic_prefix(message)

        # create message digest -- note double hashing
        message_digest = hashlib.sha256( hashlib.sha256(message_magic).digest() ).digest()

        #
        # sign non-deterministically - no reason
        #signature = self.key.sign_digest(message_digest,
        #                                 sigencode=sigencode_string)

        # deterministic signing
        signature = self.key.sign_digest_deterministic(message_digest,
                                                       sigencode=sigencode_string,
                                                       hashfunc=hashlib.sha256)
        prefix = 27
        if compressed:
            prefix += 4

        address = self.get_public_key().get_address(compressed=compressed).to_string()
        for i in range(prefix, prefix + 4):
            recid = chr(i).encode('utf-8')
            sig = b64encode( recid + signature ).decode('utf-8')
            try:
                if PublicKey.verify_message(address, sig, message):
                    return sig
            except:
                continue


    def sign_input(self, tx, txin_index, script, sighash=SIGHASH_ALL):
        # the tx knows how to calculate the digest for the corresponding
        # sighash)
        tx_digest = tx.get_transaction_digest(txin_index, script, sighash)
        return self._sign_input(tx_digest, sighash)


    def sign_segwit_input(self, tx, txin_index, script, amount, sighash=SIGHASH_ALL):
        # the tx knows how to calculate the digest for the corresponding
        # sighash)
        tx_digest = tx.get_transaction_segwit_digest(txin_index, script, amount, sighash)
        return self._sign_input(tx_digest, sighash)


    def _sign_input(self, tx_digest, sighash=SIGHASH_ALL):
        """Signs a transaction input with the private key

        Bitcoin uses the normal DER format for transactions. Each input is
        signed separately (thus txin_index is required). The script of the
        input we wish to spend is required and replaces the transaction's
        script sig in order to calculate the correct transaction hash (which
        is what is actually signed!)

        Returns a signature for that input
        """

        # note that deterministic signing is used
        signature = self.key.sign_digest_deterministic(tx_digest,
                                                       sigencode=sigencode_der,
                                                       hashfunc=hashlib.sha256)

        # make sure that signature complies with Low S standardness rule of
        # BIP62: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
        #
        # Both R ans S cannot start with 0x00 (be signed as negative) unless
        # they are higher than 2^128 or start with 0x80.
        #
        # The S part of the signature is equivalent to (order-S). This allows
        # for txid malleability attacks where S is modified with (order-S) and
        # thus a valid signature... but the txid hash would be different!
        #
        # For this reason Low S standardness rule specifies that all S's need
        # to be less than half of the curve order (SECP256k1). If it is not we
        # ensure it is by substrituting it with (order-S).

        # get DER values individually -- DER structure is:
        #   1-byte   -- 0x30 to specify a DER compound object (R,S)
        #   1-byte   -- length of the compound object
        #   1-byte   -- 0x02 to specify integer type for R
        #   1-byte   -- length of signature's R value
        #   variable -- R value
        #   1-byte   -- 0x02 to specify integer type for S
        #   1-byte   -- length of signature's S value
        #   variable -- S value

        der_prefix = signature[0]
        length_total = signature[1]
        der_type_int = signature[2]
        length_r = signature[3]
        R = signature[4:4+length_r]
        length_s = signature[5 + length_r]
        S = signature[5 + length_r + 1:]
        S_as_bigint = int( hexlify(S).decode('utf-8'), 16 )

        # update R, S if necessary -- in Bitcoin DER signatures' R should have a
        # prefix of 0x00 only if it starts with 0x80 or higher -- this was
        # implemented in Bitcoin Core of v0.17 to always be the case (however,
        # signatures are still valid even without a Low R value. Because R is
        # not mutable in the same way that S is, a low R value can only be
        # found by trying different nonves (RFC6979 - deterministic nonce
        # generation).
        # TODO to be 100% compliant with Bitcoin Core (still valid without it)

        # update S if necessary -- Low S standardness rule
        half_order = _order // 2
        # if S is larger than half the order then substructed from order and
        # use that as S since it is equivalent.
        if S_as_bigint > half_order:
            # make sure length is 33 bytes (it should be)
            assert length_s == 0x21

            new_S_as_bigint = _order - S_as_bigint
            # convert bigint to bytes
            new_S = unhexlify( format(new_S_as_bigint, 'x').zfill(64) )
            # new value should be 32 bytes
            assert len(new_S) == 0x20
            # reduce appropriate lengths
            length_s -= 1
            length_total -= 1
        else:
            new_S = S

        # reconstruct signature
        signature = struct.pack('BBBB', der_prefix, length_total, der_type_int, length_r) + R + \
                        struct.pack('BB', der_type_int, length_s) + new_S

        # add sighash in the signature -- as one byte!
        signature += struct.pack('B', sighash)

        # note that this is the final sig that needs to be added in the
        # script_sig (i.e. the DER signature plus the sighash)
        return hexlify(signature).decode('utf-8')


    def get_public_key(self):
        """Returns the corresponding PublicKey"""

        verifying_key = hexlify(self.key.get_verifying_key().to_string())
        return PublicKey( '04' + verifying_key.decode('utf-8') )


class PublicKey:
    """Represents an ECDSA public key.

    Attributes
    ----------
    key : bytes
        the raw public key of 64 bytes (x, y coordinates of the ECDSA curve)

    Methods
    -------
    from_hex(hex_str)
        creates an object from a hex string in SEC format
    from_message_signature(signature)
        NO-OP!
    verify_message(address, signature, message)
        Class method that constructs the public key, confirms the address and
        verifies the signature
    verify(signature, message)
        returns true if the message was signed with this public key's
        corresponding private key.
    to_hex(compressed=True)
        returns the key as hex string (in SEC format - compressed by default)
    to_bytes()
        returns the key's raw bytes
    to_hash160()
        returns the hash160 hex string of the public key
    get_address(compressed=True))
        returns the corresponding P2pkhAddress object
    get_segwit_address()
        returns the corresponding P2wpkhAddress object
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
            # is even else y is odd. Calculate y and then instantiate the ecdsa key
            x_coord = int( hex_str[2:], 16 )

            # y = modulo_square_root( (x**3 + 7) mod p ) -- there will be 2 y values
            y_values = sqrt_mod( (x_coord**3 + 7) % _p, _p, True )

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
        """Creates a public key from a hex string (SEC format)"""

        return cls(hex_str)


    def to_bytes(self):
        """Returns key's bytes"""

        return self.key.to_string()


    def to_hex(self, compressed=True):
        """Returns public key as a hex string (SEC format - compressed by
        default)"""

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


    @classmethod
    def from_message_signature(self, signature):
        # TODO implement (add signature=None in __init__, etc.)
        # TODO plus does this apply to DER signatures as well?
        #return cls(signature=signature)
        raise BaseException('NO-OP!')


    @classmethod
    def verify_message(self, address, signature, message):
        """Creates a public key from a message signature and verifies message

        Bitcoin uses a compact format for message signatures (for tx sigs it
        uses normal DER format). The format has the normal r and s parameters
        that ECDSA signatures have but also includes a prefix which encodes
        extra information. Using the prefix the public key can be
        reconstructed from the signature.

        |  Prefix values:
        |      27 - 0x1B = first key with even y
        |      28 - 0x1C = first key with odd y
        |      29 - 0x1D = second key with even y
        |      30 - 0x1E = second key with odd y

        If key is compressed add 4 (31 - 0x1F, 32 - 0x20, 33 - 0x21, 34 - 0x22 respectively)

        Raises
        ------
        ValueError
            If signature is invalid
        """

        sig = b64decode( signature.encode('utf-8') )
        if len(sig) != 65:
            raise ValueError('Invalid signature size')

        # get signature prefix, compressed and recid (which key is odd/even)
        prefix = sig[0]
        if prefix < 27 or prefix > 35:
            return False
        if prefix >= 31:
            compressed = True
            recid = prefix - 31
        else:
            compressed = False
            recid = prefix - 27

        # create message digest -- note double hashing
        message_magic = add_magic_prefix(message)
        message_digest = hashlib.sha256( hashlib.sha256(message_magic).digest() ).digest()

        #
        # use recid, r and s to get the point in the curve
        #

        # get signature's r and s
        r,s = sigdecode_string(sig[1:], _order)

        # ger R's x coordinate
        x = r + (recid // 2) * _order

        # get R's y coordinate (y**2 = x**3 + 7)
        y_values = sqrt_mod( (x**3 + 7) % _p, _p, True )
        if (y_values[0] - recid) % 2 == 0:
            y = y_values[0]
        else:
            y = y_values[1]

        # get R (recovered ephemeral key) from x,y
        R = ellipticcurve.Point(_curve, x, y, _order)

        # get e (hash of message encoded as big integer)
        e = int(hexlify(message_digest), 16)

        # compute public key Q = r^-1 (sR - eG)
        # because Point substraction is not defined we will instead use:
        # Q = r^-1 (sR + (-eG) )
        minus_e = -e % _order
        inv_r = numbertheory.inverse_mod(r, _order)
        Q = inv_r * ( s*R + minus_e*_G )

        # instantiate the public key and verify message
        public_key = VerifyingKey.from_public_point( Q, curve = SECP256k1 )
        key_hex = hexlify(public_key.to_string()).decode('utf-8')
        pubkey = PublicKey.from_hex('04' + key_hex)
        if not pubkey.verify(signature, message):
            return False

        # confirm that the address provided corresponds to that public key
        if pubkey.get_address(compressed=compressed).to_string() != address:
            return False

        return True


    def verify(self, signature, message):
        """Verifies that the message was signed with this public key's
        corresponding private key."""

        # All bitcoin signatures include the magic prefix. It is just a string
        # added to the message to distinguish Bitcoin-specific messages.
        message_magic = add_magic_prefix(message)

        # create message digest -- note double hashing
        message_digest = hashlib.sha256( hashlib.sha256(message_magic).digest()).digest()

        signature_bytes = b64decode( signature.encode('utf-8') )

        # verify -- ignore first byte of compact signature
        return self.key.verify_digest(signature_bytes[1:],
                                      message_digest,
                                      sigdecode=sigdecode_string)


    def _to_hash160(self, compressed=True):
        """Returns the RIPEMD( SHA256( ) ) of the public key in bytes"""

        pubkey = unhexlify( self.to_hex(compressed) )
        hashsha256 = hashlib.sha256(pubkey).digest()
        hashripemd160 = hashlib.new('ripemd160')
        hashripemd160.update(hashsha256)
        hash160 = hashripemd160.digest()
        return hash160

    def to_hash160(self, compressed=True):
        """Returns the RIPEMD( SHA256( ) ) of the public key in hex"""

        return hexlify(self._to_hash160(compressed)).decode('utf-8')


    def get_address(self, compressed=True):
        """Returns the corresponding P2PKH Address (default compressed)"""

        hash160 = self._to_hash160(compressed)
        addr_string_hex = hexlify(hash160).decode('utf-8')
        return P2pkhAddress(hash160=addr_string_hex)


    def get_segwit_address(self):
        """Returns the corresponding P2WPKH address

        Only compressed is allowed. It is otherwise identical to normal P2PKH
        address.
        """
        hash160 = self._to_hash160(True)
        addr_string_hex = hexlify(hash160).decode('utf-8')
        return P2wpkhAddress(witness_hash=addr_string_hex)



class Address(ABC):
    """Represents a Bitcoin address

    Attributes
    ----------
    hash160 : str
        the hash160 string representation of the address; hash160 represents
        two consequtive hashes of the public key or the redeam script, first
        a SHA-256 and then an RIPEMD-160

    Methods
    -------
    from_address(address)
        instantiates an object from address string encoding
    from_hash160(hash160_str)
        instantiates an object from a hash160 hex string
    from_script(redeem_script)
        instantiates an object from a redeem_script
    to_string()
        returns the address's string encoding
    to_hash160()
        returns the address's hash160 hex string representation

    Raises
    ------
    TypeError
        No parameters passed
    ValueError
        If an invalid address or hash160 is provided.
    """
    @abstractmethod
    def __init__(self, address=None, hash160=None, script=None):
        """
        Parameters
        ----------
        address : str
            the address as a string
        hash160 : str
            the hash160 hex string representation
        script : Script object
            instantiates an Address object from a redeem script

        Raises
        ------
        TypeError
            No parameters passed
        ValueError
            If an invalid address or hash160 is provided.
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
        elif script:
            # TODO for now just check that is an instance of Script
            if isinstance(script, bitcoinutils.script.Script):
                self.hash160 = self._script_to_hash160(script)
            else:
                raise TypeError("A Script class is required.")
        else:
            raise TypeError("A valid address or hash160 is required.")


    @classmethod
    def from_address(cls, address):
        """Creates an address object from an address string"""

        return cls(address=address)


    @classmethod
    def from_hash160(cls, hash160):
        """Creates an address object from a hash160 string"""

        return cls(hash160=hash160)


    @classmethod
    def from_script(cls, script):
        """Creates an address object from a Script object"""

        return cls(script=script)


    def _address_to_hash160(self, address):
        """Converts an address to it's hash160 equivalent

	Base58CheckDecode the address and remove network_prefix and checksum.
	"""

        addr_encoded = address.encode('utf-8')
        data_checksum = b58decode( addr_encoded )
        network_prefix = data_checksum[:1]
        data = data_checksum[1:-4]
        #checksum = data_checksum[-4:]
        return hexlify(data).decode('utf-8')


    def _script_to_hash160(self, script):
        """Converts a script to it's hash160 equivalent

        RIPEMD160( SHA256( script ) ) - required for P2SH addresses
	"""

        script_bytes = script.to_bytes()
        hashsha256 = hashlib.sha256(script_bytes).digest()
        hashripemd160 = hashlib.new('ripemd160')
        hashripemd160.update(hashsha256)
        hash160 = hashripemd160.digest()
        return hexlify(hash160).decode('utf-8')


    def _is_hash160_valid(self, hash160):
        """Checks is a hash160 hex string is valid"""

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
        """Checks is an address string is valid"""

        digits_58_pattern = r'[^123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]'

        # check for invalid characters
        if re.search(digits_58_pattern, address):
            return False

        # check for length (26-35 characters)
        # TODO: need to confirm the possible length!
        if len(address) < 26 or len(address) > 35:
            return False

        # get data, network_prefix and checksum
        data_checksum = b58decode( address.encode('utf-8') )
        data = data_checksum[:-4]
        network_prefix = data_checksum[:1]
        checksum = data_checksum[-4:]

        # check correct network (depending on address type)
        if self.get_type() == P2PKH_ADDRESS:
            if network_prefix != NETWORK_P2PKH_PREFIXES[get_network()]:
                return False
        elif self.get_type() == P2SH_ADDRESS:
            if network_prefix != NETWORK_P2SH_PREFIXES[get_network()]:
                return False

        # check address' checksum
        data_hash = hashlib.sha256(hashlib.sha256(data).digest()).digest()

        if data_hash[0:4] != checksum:
            return False

        return True


    def to_hash160(self):
        """Returns as hash160 hex string"""

        return self.hash160


    def to_string(self):
        """Returns as address string

        |  Pseudocode:
        |      network_prefix = (1 byte version number)
        |      data = network_prefix + hash160_bytes
        |      data_hash = SHA-256( SHA-256( hash160_bytes ) )
        |      checksum = (first 4 bytes of data_hash)
        |      address_bytes = Base58CheckEncode( data + checksum )
        """
        hash160_encoded = self.hash160.encode('utf-8')
        hash160_bytes = unhexlify(hash160_encoded)

        if self.get_type() == P2PKH_ADDRESS:
            data = NETWORK_P2PKH_PREFIXES[get_network()] + hash160_bytes
        elif self.get_type() == P2SH_ADDRESS:
            data = NETWORK_P2SH_PREFIXES[get_network()] + hash160_bytes

        data_hash = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        checksum = data_hash[0:4]
        address_bytes = b58encode( data + checksum )

        return address_bytes.decode('utf-8')


class P2pkhAddress(Address):
    """Encapsulates a P2PKH address.

    Check Address class for details

    Methods
    -------
    to_script_pub_key()
        returns the scriptPubKey (P2PKH) that corresponds to this address
    get_type()
        returns the type of address
    """

    def __init__(self, address=None, hash160=None):
        super().__init__(address=address, hash160=hash160)

    def to_script_pub_key(self):
        """Returns the scriptPubKey (P2PKH) that corresponds to this address"""
        return bitcoinutils.script.Script(['OP_DUP', 'OP_HASH160',
                                           self.to_hash160(), 'OP_EQUALVERIFY',
                                           'OP_CHECKSIG'])

    def get_type(self):
        """Returns the type of address"""
        return P2PKH_ADDRESS


class P2shAddress(Address):
    """Encapsulates a P2SH address.

    Check Address class for details

    Methods
    -------
    get_type()
        returns the type of address
    """

    def __init__(self, address=None, hash160=None, script=None):
        super().__init__(address=address, hash160=hash160, script=script)

    def get_type(self):
        """Returns the type of address"""
        return P2SH_ADDRESS





class SegwitAddress(ABC):
    """Represents a Bitcoin segwit address

    Note that currently the python bech32 reference implementation is used (by
    Pieter Wuille).

    Attributes
    ----------
    witness_hash : str
        the hash string representation of either the address; it can be either
        a public key hash (P2WPKH) or the hash of the script (P2WSH)

    Methods
    -------
    from_address(address)
        instantiates an object from address string encoding
    from_hash(hash_str)
        instantiates an object from a hash hex string
    from_script(witness_script)
        instantiates an object from a witness_script
    to_string()
        returns the address's string encoding (Bech32)
    to_hash()
        returns the address's hash hex string representation

    Raises
    ------
    TypeError
        No parameters passed
    ValueError
        If an invalid address or hash is provided.
    """
    @abstractmethod
    def __init__(self, address=None, witness_hash=None, script=None,
                 version=P2WPKH_ADDRESS_V0):
        """
        Parameters
        ----------
        address : str
            the address as a string
        witness_hash : str
            the hash hex string representation
        script : Script object
            instantiates an Address object from a witness script
        version : str
            specifies the default segwit version

        Raises
        ------
        TypeError
            No parameters passed
        ValueError
            If an invalid address or hash is provided.
        """

        self.version = version
        if self.version == P2WPKH_ADDRESS_V0 or self.version == P2WSH_ADDRESS_V0:
            self.segwit_num_version = 0

        if witness_hash:
            self.witness_hash = witness_hash
        elif address:
            self.witness_hash = self._address_to_hash(address)
        elif script:
            # TODO for now just check that is an instance of Script
            if isinstance(script, bitcoinutils.script.Script):
                self.witness_hash = self._script_to_hash(script)
            else:
                raise TypeError("A Script class is required.")
        else:
            raise TypeError("A valid address or hash is required.")


    @classmethod
    def from_address(cls, address):
        """Creates an address object from an address string"""

        return cls(address=address)


    @classmethod
    def from_hash(cls, witness_hash):
        """Creates an address object from a hash string"""

        return cls(witness_hash=witness_hash)


    @classmethod
    def from_script(cls, script):
        """Creates an address object from a Script object"""

        return cls(script=script)


    def _address_to_hash(self, address):
        """Converts an address to it's hash equivalent

	The size of the address determines between P2WPKH and P2WSH.
        Then Bech32 decodes the address removing network prefix, checksum,
        witness version.

        Uses a segwit's python reference implementation for now. (TODO)
	"""

        witness_version, witness_int_array = bitcoinutils.bech32.decode(NETWORK_SEGWIT_PREFIXES[get_network()], address)
        if witness_version == None:
            raise ValueError("Invalid value for parameter address.")
        if witness_version != self.segwit_num_version:
            raise TypeError("Invalid segwit version.")

        return hexlify( bytes(witness_int_array) ).decode('utf-8')


    def _script_to_hash(self, script):
        """Converts a script to it's hash equivalent"""

        script_bytes = script.to_bytes()
        hashsha256 = hashlib.sha256(script_bytes).digest()
        return hexlify(hashsha256).decode('utf-8')


    def to_hash(self):
        """Returns as hash hex string"""

        return self.witness_hash


    def to_string(self):
        """Returns as address string

        Uses a segwit's python reference implementation for now. (TODO)
        """

        # convert hex string hash to int array (required by bech32 lib)
        hash_bytes = unhexlify( self.witness_hash.encode('utf-8') )
        witness_int_array = memoryview(hash_bytes).tolist()

        return bitcoinutils.bech32.encode(NETWORK_SEGWIT_PREFIXES[get_network()],
                                          self.segwit_num_version, witness_int_array)



class P2wpkhAddress(SegwitAddress):
    """Encapsulates a P2WPKH address.

    Check Address class for details

    Methods
    -------
    to_script_pub_key()
        returns the scriptPubKey of a P2WPKH witness script
    get_type()
        returns the type of address
    """

    # TODO allow creation directly from Bech32 address !!!!!!
    def __init__(self, address=None, witness_hash=None,
                 version=P2WPKH_ADDRESS_V0):
        """Allow creation only from hash160 of public key"""

        super().__init__(address=address, witness_hash=witness_hash,
                         version=version)


    def to_script_pub_key(self):
        """Returns the scriptPubKey of a P2WPKH witness script"""
        return bitcoinutils.script.Script(['OP_0', self.to_hash()])


    def get_type(self):
        """Returns the type of address"""
        return self.version


class P2wshAddress(SegwitAddress):
    """Encapsulates a P2WSH address.

    Check Address class for details

    Methods
    -------
    from_script(witness_script)
        instantiates an object from a witness_script
    get_type()
        returns the type of address
    """

    def __init__(self, address=None, witness_hash=None, script=None,
                 version=P2WSH_ADDRESS_V0):
        """Allow creation only from hash160 of public key"""

        super().__init__(address=None, witness_hash=None, script=script,
                         version=version)


    def to_script_pub_key(self):
        """Returns the scriptPubKey of a P2WPKH witness script"""
        return bitcoinutils.script.Script(['OP_0', self.to_hash()])


    def get_type(self):
        """Returns the type of address"""
        return self.version



def main():
    pass

if __name__ == "__main__":
    main()

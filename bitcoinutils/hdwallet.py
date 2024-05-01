# Copyright (C) 2018-2024 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from typing import Optional

from bitcoinutils.setup import is_mainnet
from bitcoinutils.keys import PrivateKey
from bitcoinutils.constants import BIP32KEY_HARDEN

import hashlib
import hmac
from binascii import unhexlify, b2a_hex
import unicodedata
import ecdsa
import struct
from ecdsa.curves import SECP256k1
from ecdsa.util import string_to_number, number_to_string
import base58

class HDW:
    def __init__(self):
        """
        Initialize the HD Wallet with a seed if provided.

        Args:
            seed (Optional[str]): A hexadecimal string representing the seed from which the HD Wallet will derive its keys.
        """
        self.strength: Optional[int] = None
        self._depth: int = 0
        self._index: int = 0
        self._parent_fingerprint: bytes = b"\0\0\0\0"
        self.master_private_key : Optional[str] = None
        self.master_chain_code : Optional[str] = None
        self.seed : Optional[str] = None
        self._root_private_key: Optional[tuple] = None

    def from_seed(self, seed : str):
        """
        Generate the master keys from the seed bytes.

        Args:
            seed_bytes (bytes): Seed from which the master private key and chain code are derived.

        Returns:
            tuple: Tuple containing (master_private_key, master_chain_code).
        """
        self.seed = seed
        seed_bytes = unhexlify(seed)
        key = b"Bitcoin seed"
        h = hmac.new(key, seed_bytes, hashlib.sha512).digest()
        # Split the hash into two halves: private key and chain code.
        master_private_key = h[:32]
        master_chain_code = h[32:]
        self._root_private_key = (master_private_key, master_chain_code)
        self.master_private_key, self.master_chain_code = master_private_key, master_chain_code
        return master_private_key, master_chain_code
    
    @staticmethod
    def get_mnemonic_strength(mnemonic: str) -> int:
        """
        Get mnemonic strength.

        :param mnemonic: Mnemonic words.
        :type mnemonic: str

        :returns: int -- Mnemonic strength.
        """
        
        words = len(unicodedata.normalize("NFKD", mnemonic).split(" "))
        if words == 12:
            return 128
        elif words == 15:
            return 160
        elif words == 18:
            return 192
        elif words == 21:
            return 224
        elif words == 24:
            return 256
        else:
            raise ValueError("Unsupported number of words in mnemonic.")

    def from_mnemonic(self, mnemonic: str, passphrase: str = "") -> "HDW":
        """
        Create keys from a mnemonic phrase.

        Args:
            mnemonic (str): Mnemonic phrase used to generate the seed.
            passphrase (str): Additional passphrase used with the mnemonic for added security.

        Returns:
            HDW: Returns itself after initializing the master keys.
        """

        self._mnemonic = unicodedata.normalize("NFKD", mnemonic)
        self.strength = self.get_mnemonic_strength(mnemonic=self._mnemonic)
        seed = self.to_seed(self._mnemonic, passphrase).hex()
        self.master_private_key, self.master_chain_code = self.from_seed(seed)
        return self

    def to_seed(self, mnemonic: str, passphrase: str = "") -> bytes:
        """
        Generate a seed from a mnemonic and a passphrase.

        Args:
            mnemonic (str): Mnemonic phrase.
            passphrase (str): Optional passphrase for additional security.

        Returns:
            bytes: The seed generated from the mnemonic and passphrase.
        """

        passphrase = "mnemonic" + passphrase
        mnemonic_bytes = mnemonic.encode("utf-8")
        passphrase_bytes = passphrase.encode("utf-8")
        #PBKDF2 HMAC-SHA512 to derive the seed from the mnemonic and passphrase.
        stretched = hashlib.pbkdf2_hmac(
            "sha512", mnemonic_bytes, passphrase_bytes, 2048
        )
        return stretched[:64]
    
    @staticmethod
    def _deserialize_xprivate_key(xprivate_key: str, encoded: bool = True) -> tuple:
        """
        Deserialize an extended private key (xprivate key).

        Args:
            xprivate_key (str): The xprivate key as a string.
            encoded (bool): Flag indicating if the xprivate key is hex-encoded.

        Returns:
            tuple: A tuple containing different parts of the xprivate key.

        Raises:
            ValueError: If the xprivate key is invalid or improperly sized.
        """
        if encoded:
            # Decode from Base58Check to bytes
            try:
                xprivate_key_bytes = base58.b58decode_check(xprivate_key)
            except ValueError:
                raise ValueError("Invalid Base58Check in xprivate key.")
        else:
            # If the key is not encoded, directly convert it assuming it's in UTF-8 format
            xprivate_key_bytes = xprivate_key.encode()

        # Verify the length of the decoded xprivate key
        if len(xprivate_key_bytes) != 78:
            raise ValueError("Invalid xprivate key size.")
        
        return (
            xprivate_key_bytes[:4],    # Version bytes
            xprivate_key_bytes[4:5],   # Depth
            xprivate_key_bytes[5:9],   # Parent fingerprint
            xprivate_key_bytes[9:13],  # Child number (index)
            xprivate_key_bytes[13:45], # Private key data
            xprivate_key_bytes[46:]    # Chain code
        )

    def from_xprivate_key(self, xprivate_key: str, strict: bool = False) -> "HDW":
        """
        Initialize the HD wallet from an extended private key (xprivate key).

        Args:
            xprivate_key (str): The xprivate key as a string.
            strict (bool): If True, the xprivate key must be a root key.

        Returns:
            HDW: An instance of the HDWallet class initialized with the xprivate key.

        Raises:
            ValueError: If strict checking is enabled and the key is not a root key.
        """
        _parts = self._deserialize_xprivate_key(xprivate_key)
        if strict and _parts[0] != b'\x04\x88\xAD\xE4':  # version bytes for xprv
            raise ValueError("Invalid root xprivate key.")
        
        self._depth, self._parent_fingerprint, self._index = (
            int.from_bytes(_parts[1], "big"),
            _parts[2],
            struct.unpack(">L", _parts[3])[0]
        )
        self._root_private_key = (_parts[5], _parts[4])
        self._i = _parts[5] + _parts[4]
        self.master_private_key, self.master_chain_code = self._i[:32], self._i[32:]
        self._key = ecdsa.SigningKey.from_string(self.master_private_key, curve=ecdsa.SECP256k1)
        self._verified_key = self._key.get_verifying_key()
        return self
    
    def from_path(self, path: str) -> 'HDW':
        """
        Derive keys from a specified BIP32 path.

        Args:
            path (Union[str, Derivation]): BIP32 path.

        Returns:
            HDW: The HDWallet after deriving the specified path.
        """
        path = path.lstrip("m/").split("/") if isinstance(path, str) else path.to_path()
        for p in path:
            index = int(p[:-1]) + BIP32KEY_HARDEN if "'" in p else int(p)
            self = self._derive_key_by_index(index)
        return self

    def _derive_key_by_index(self, index: int) -> 'HDW':
        """
        Derive a child key by index.

        Args:
            index (int): Index for the child key derivation.

        Returns:
            HDW: New instance of HDWallet for the derived key.
        """
        if index & BIP32KEY_HARDEN:  # Hardened
            data = b'\x00' + self.master_private_key + struct.pack('>L', index)
        else:  # Non-hardened
            data = self._public_key_from_private(self.master_private_key) + struct.pack('>L', index)

        I = hmac.new(self.master_chain_code, data, hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]
        new_priv_key = (string_to_number(IL) + string_to_number(self.master_private_key)) % SECP256k1.order
        if new_priv_key == 0:
            raise Exception("Invalid child key derived")

       # Update the instance's keys and chain code
        self.master_private_key = new_priv_key.to_bytes(32, 'big')
        self.master_chain_code = IR

        # Update the public and private keys
        self._key = ecdsa.SigningKey.from_string(self.master_private_key, curve=SECP256k1)
        self._verified_key = self._key.get_verifying_key()

        return self  # Return the updated instance

    def _public_key_from_private(self, private_key):
        """
        Generate the public key corresponding to the given private key, in compressed format.

        Args:
            private_key (bytes): Private key.

        Returns:
            bytes: Compressed public key.
        """
        sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        # Get the compressed form of the public key
        if vk.pubkey.point.y() & 1:
            return b'\x03' + vk.to_string()[:32]
        else:
            return b'\x02' + vk.to_string()[:32]

    
    def wif(self, is_testnet=True) -> Optional[str]:
        """
        Get Wallet Import Format.

        Args:
            is_testnet (bool): Flag indicating whether to generate WIF for testnet.

        Returns:
            str: Wallet Import Format string if the key exists, None otherwise.
        """
        if self.master_private_key:
            # Set the prefix based on the network
            prefix = b'\xef' if is_testnet else b'\x80'
            # Prepare the payload with the private key and a suffix '01' which denotes that the corresponding public key is compressed
            payload = prefix + self.master_private_key + b'\x01'
            # Compute the checksum: first 4 bytes of SHA-256(SHA-256(payload))
            checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
            # Encode the result using Base58
            return base58.b58encode(payload + checksum).decode('utf-8')
        else:
            return None
        
    def clean_derivation(self) -> "HDW":
        """
        Clean derivation Path or Indexes.

        Returns:
            HDW: Hierarchical Deterministic Wallet instance reset to its root configuration.
        """
        if self._root_private_key:
            self._path, self._path_class, self._depth, self._parent_fingerprint, self._index = (
                "m", "m", 0, b"\0\0\0\0", 0
            )
            self.master_private_key, self.master_chain_code = self._root_private_key
            self._key = ecdsa.SigningKey.from_string(self.master_private_key, curve=SECP256k1)
            self._verified_key = self._key.get_verifying_key()


class HDWallet:
    """Wraps the python hdwallet library to provide basic HD wallet functionality

    Attributes
    ----------
    hdw : object
        a hdwallet object
    """

    def __init__(
        self,
        xprivate_key: Optional[str] = None,
        path: Optional[str] = None,
        mnemonic: Optional[str] = None,
        passphrase : Optional[str] = ""
    ):
        """Instantiate a hdwallet object using the corresponding library with BTC"""

        # symbol = None
        # if is_mainnet():
        #     symbol = BTC
        # else:
        #     symbol = BTCTEST

        self.hdw = HDW()
        if mnemonic:
            self.hdw.from_mnemonic(mnemonic=mnemonic,passphrase=passphrase)

        if xprivate_key and path:
            self.hdw.from_xprivate_key(xprivate_key=xprivate_key)
            self.hdw.from_path(path=path)

    @classmethod
    def from_mnemonic(cls, mnemonic: str , passphrase : str = ""):
        """Class method to instantiate from a mnemonic code for the HD Wallet"""
        return cls(mnemonic=mnemonic,passphrase=passphrase)

    @classmethod
    def from_xprivate_key(cls, xprivate_key: str, path: Optional[str] = None):
        """Class method to instantiate from an extended private key and optionally the path for the HD Wallet"""
        # Assert to ensure path is not None if xprivate_key is provided
        assert path is not None, "Path must be provided with xprivate key"
        # Create an instance directly using the xprivate key and path
        return cls(xprivate_key=xprivate_key, path=path)

    def from_path(self, path: str):
        """Set/update the path"""

        self.hdw.clean_derivation()  # type: ignore
        self.hdw.from_path(path=path)

    def get_private_key(self):
        """Return a PrivateKey object used throughout bitcoinutils library"""

        return PrivateKey(self.hdw.wif())  # type: ignore
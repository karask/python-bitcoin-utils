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

from hdwallet import HDWallet as ext_HDWallet  # type: ignore
from hdwallet.symbols import BTC, BTCTEST  # type: ignore

from bitcoinutils.setup import is_mainnet
from bitcoinutils.keys import PrivateKey

import hashlib
import hmac
from binascii import unhexlify
import unicodedata

class HDW:
    def __init__(self, seed):
        seed_bytes = unhexlify(seed)  # Convert hex string to bytes
        self.seed = seed_bytes
        self.master_private_key, self.master_chain_code = self.from_seed(seed_bytes)

    def from_seed(self, seed_bytes):
        """ Generate the master keys from the seed bytes """
        key = b"Bitcoin seed"
        h = hmac.new(key, seed_bytes, hashlib.sha512).digest()
        master_private_key = h[:32]
        master_chain_code = h[32:]
        return master_private_key, master_chain_code
    
    @staticmethod
    def get_mnemonic_strength(mnemonic: str, language: str = None) -> int:
        """
        Get mnemonic strength.

        :param mnemonic: Mnemonic words.
        :type mnemonic: str
        :param language: Mnemonic language, default to None.
        :type language: str

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
    ):
        """Instantiate a hdwallet object using the corresponding library with BTC"""

        symbol = None
        if is_mainnet():
            symbol = BTC
        else:
            symbol = BTCTEST

        self.hdw = ext_HDWallet(symbol)

        if mnemonic:
            self.hdw.from_mnemonic(mnemonic=mnemonic)

        if xprivate_key and path:
            self.hdw.from_xprivate_key(xprivate_key=xprivate_key)
            self.hdw.from_path(path=path)

    @classmethod
    def from_mnemonic(cls, mnemonic: str):
        """Class method to instantiate from a mnemonic code for the HD Wallet"""
        return cls(mnemonic=mnemonic)

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

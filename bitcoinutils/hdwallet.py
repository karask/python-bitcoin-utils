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


# class HDW:
#    """Implements mnemonic codes (BIP-39) and hierarchical deterministic
#    wallet (BIP-32)"""


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

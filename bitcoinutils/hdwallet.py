# Copyright (C) 2018-2023 The python-bitcoin-utils developers
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
            self.from_mnemonic(mnemonic)

        if xprivate_key:
            assert path is not None
            self.from_xprivate_key(xprivate_key, path)

    # TODO make this a class method, return cls(mnemonic=)
    def from_mnemonic(self, mnemonic: str):
        """Set a mnemonic code for the HD Wallet"""

        self.hdw.from_mnemonic(mnemonic=mnemonic)

    # TODO make this a class method, return cls(xprivate_key=, path=)
    def from_xprivate_key(self, xprivate_key: str, path: Optional[str] = None):
        """Set an extended private key and optionally the path for the HD Wallet"""

        self.hdw.from_xprivate_key(xprivate_key=xprivate_key)
        if path:
            self.hdw.from_path(path=path)

    def from_path(self, path: str):
        """Set/update the path"""

        self.hdw.clean_derivation()  # type: ignore
        self.hdw.from_path(path=path)

    def get_private_key(self):
        """Return a PrivateKey object used throughout bitcoinutils library"""

        return PrivateKey(self.hdw.wif())  # type: ignore

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

from typing import Optional
import ssl
from configparser import ConfigParser
from bitcoinrpc.authproxy import AuthServiceProxy  # type: ignore

from bitcoinutils.setup import get_network
from bitcoinutils.constants import NETWORK_DEFAULT_PORTS


class NodeProxy:
    """Simple Bitcoin node proxy that can call all of Bitcoin's JSON-RPC functionality.

    Attributes
    ----------
    proxy : object
        a bitcoinrpc AuthServiceProxy object
    """

    def __init__(
        self,
        rpcuser: str,
        rpcpassword: str,
        host: Optional[str] = None,
        port: Optional[int] = None,
    ) -> None:
        """Connects to node using credentials given

        Parameters
        ----------
        rpcuser : str
            as defined in bitcoin.conf
        rpcpassword : str
            as defined in bitcoin.conf
        host : str, optional
            host where the Bitcoin node resides; defaults to 127.0.0.1
        port : int, optional
            port to connect to; uses default ports according to network

        Raises
        ------
        ValueError
            if rpcuser and/or rpcpassword are not specified
        """

        if not rpcuser or not rpcpassword:
            raise ValueError("rpcuser or rpcpassword is missing")

        if not host:
            host = "127.0.0.1"

        if not port:
            port = NETWORK_DEFAULT_PORTS[get_network()]

        self.config = ConfigParser()
        self.config.read('config.ini')
        self.ignore_ssl_cert = self.config.getboolean('bitcoin', 'ignore_ssl_cert', fallback=False)
        self.proxy = AuthServiceProxy(
            "http://{}:{}@{}:{}".format(rpcuser, rpcpassword, host, port),
            ssl_context=self._get_ssl_context()
        )
    
    def _get_ssl_context(self) -> ssl.SSLContext:
        """Returns SSL context based on config"""
        if self.ignore_ssl_cert:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            return ssl_context

        return None
    
    def get_proxy(self) -> "NodeProxy":
        """Returns bitcoinrpc AuthServiceProxy object"""
        return self.proxy

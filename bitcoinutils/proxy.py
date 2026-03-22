# Copyright (C) 2018-2025 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import base64
import decimal
import http.client
import json
import logging
import time
from typing import Any, Dict, List, Optional, Sequence, Union

from bitcoinutils.setup import get_network
from bitcoinutils.constants import NETWORK_DEFAULT_PORTS

log = logging.getLogger("BitcoinRPC")

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT = 30  # seconds
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_BASE = 0.5  # seconds — first retry waits 0.5s, then 1s, 2s …
USER_AGENT = "python-bitcoin-utils"

# Errors that indicate a broken / refused connection worth retrying.
_RETRIABLE_EXCEPTIONS = (
    ConnectionError,
    ConnectionResetError,
    ConnectionRefusedError,
    BrokenPipeError,
    http.client.RemoteDisconnected,
    http.client.CannotSendRequest,
    http.client.BadStatusLine,
    OSError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _encode_decimal(obj: Any) -> Any:
    """JSON encoder for :class:`decimal.Decimal` values.

    Bitcoin Core returns monetary amounts as JSON numbers. We parse them as
    ``Decimal`` on the way in (see ``_decode_response``) and need to convert
    them back when serialising outbound parameters.
    """
    if isinstance(obj, decimal.Decimal):
        return float(round(obj, 8))
    raise TypeError(f"{obj!r} is not JSON serializable")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class RPCException(Exception):
    """Raised when the Bitcoin Core JSON-RPC interface returns an error.

    Attributes
    ----------
    code : int | None
        The JSON-RPC error code (e.g. ``-32600`` for invalid request).
    message : str | None
        Human-readable description returned by Bitcoin Core.
    error : dict
        The raw error dict from the JSON-RPC response.
    """

    def __init__(self, rpc_error: Dict[str, Any]) -> None:
        self.error = rpc_error
        self.code: Optional[int] = rpc_error.get("code")
        self.message: Optional[str] = rpc_error.get("message")
        super().__init__(self.message or str(rpc_error))

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} '{self}'>"


# ---------------------------------------------------------------------------
# Internal callable that represents a single RPC method
# ---------------------------------------------------------------------------
class _RPCMethod:
    """Captures an RPC method name so that ``proxy.getblockcount()`` works.

    Created by :pymethod:`NodeProxy.__getattr__`.  Supports dotted names
    via chained attribute access (e.g. ``proxy.wallet.create``).
    """

    def __init__(self, proxy: "NodeProxy", method: str) -> None:
        self._proxy = proxy
        self._method = method

    def __getattr__(self, name: str) -> "_RPCMethod":
        # Support dotted method names: proxy.some.method(...)
        return _RPCMethod(self._proxy, f"{self._method}.{name}")

    def __call__(self, *args: Any) -> Any:
        return self._proxy._call(self._method, list(args))


# ---------------------------------------------------------------------------
# NodeProxy — the public API
# ---------------------------------------------------------------------------
class NodeProxy:
    """JSON-RPC proxy for a Bitcoin Core node.

    Supports any RPC command via dynamic attribute access::

        proxy = NodeProxy("rpcuser", "rpcpassword")
        height = proxy.getblockcount()
        block_hash = proxy.getblockhash(height)

    Parameters
    ----------
    rpcuser : str
        RPC username as defined in ``bitcoin.conf``.
    rpcpassword : str
        RPC password as defined in ``bitcoin.conf``.
    host : str, optional
        Host where the Bitcoin node resides (default ``127.0.0.1``).
    port : int, optional
        Port to connect to.  Uses the default port for the active network
        (set via :func:`bitcoinutils.setup.setup`).
    timeout : int, optional
        HTTP timeout in seconds (default 30).
    use_https : bool, optional
        If *True* use HTTPS; otherwise plain HTTP (default *False*).
    max_retries : int, optional
        Maximum number of retries on retriable connection errors (default 3).
        Set to 0 to disable retries.
    backoff_base : float, optional
        Base delay in seconds for exponential back-off between retries
        (default 0.5).  The *n*-th retry waits ``backoff_base * 2^(n-1)``.

    Raises
    ------
    ValueError
        If *rpcuser* or *rpcpassword* is empty / not provided.
    """

    # Incrementing request id shared across all instances (matches upstream).
    _id_counter: int = 0

    def __init__(
        self,
        rpcuser: str,
        rpcpassword: str,
        host: Optional[str] = None,
        port: Optional[int] = None,
        timeout: int = DEFAULT_TIMEOUT,
        use_https: bool = False,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_base: float = DEFAULT_BACKOFF_BASE,
    ) -> None:
        if not rpcuser or not rpcpassword:
            raise ValueError("rpcuser or rpcpassword is missing")

        if not host:
            host = "127.0.0.1"
        if not port:
            port = NETWORK_DEFAULT_PORTS[get_network()]

        self._host = host
        self._port = port
        self._timeout = timeout
        self._use_https = use_https
        self._max_retries = max_retries
        self._backoff_base = backoff_base

        # Pre-compute the Basic-Auth header.
        credentials = f"{rpcuser}:{rpcpassword}".encode("utf-8")
        self._auth_header = "Basic " + base64.b64encode(credentials).decode("ascii")

        # Lazily created / re-created on demand.
        self._conn: Optional[
            Union[http.client.HTTPConnection, http.client.HTTPSConnection]
        ] = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------
    def _get_connection(
        self,
    ) -> Union[http.client.HTTPConnection, http.client.HTTPSConnection]:
        """Return an open HTTP(S) connection, creating one if necessary."""
        if self._conn is None:
            if self._use_https:
                self._conn = http.client.HTTPSConnection(
                    self._host, self._port, timeout=self._timeout
                )
            else:
                self._conn = http.client.HTTPConnection(
                    self._host, self._port, timeout=self._timeout
                )
        return self._conn

    def _close_connection(self) -> None:
        """Close the underlying HTTP connection (if any)."""
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    # ------------------------------------------------------------------
    # JSON-RPC call mechanics
    # ------------------------------------------------------------------
    @classmethod
    def _next_id(cls) -> int:
        cls._id_counter += 1
        return cls._id_counter

    def _call(self, method: str, params: List[Any]) -> Any:
        """Send a single JSON-RPC request to the node and return the result.

        Implements automatic reconnection and optional retry with exponential
        back-off on retriable connection errors.
        """
        request_id = self._next_id()

        payload = json.dumps(
            {
                "version": "1.1",
                "method": method,
                "params": params,
                "id": request_id,
            },
            default=_encode_decimal,
        )

        log.debug(
            "-%s-> %s %s",
            request_id,
            method,
            json.dumps(params, default=_encode_decimal),
        )

        headers = {
            "Host": self._host,
            "User-Agent": USER_AGENT,
            "Authorization": self._auth_header,
            "Content-Type": "application/json",
        }

        last_exc: Optional[Exception] = None
        attempts = 1 + self._max_retries  # first attempt + retries

        for attempt in range(attempts):
            try:
                conn = self._get_connection()
                conn.request("POST", "/", payload, headers)
                return self._read_response(conn)
            except _RETRIABLE_EXCEPTIONS as exc:
                last_exc = exc
                self._close_connection()
                if attempt < attempts - 1:
                    delay = self._backoff_base * (2**attempt)
                    log.warning(
                        "RPC connection error (%s), retrying in %.1fs (attempt %d/%d)…",
                        exc,
                        delay,
                        attempt + 2,
                        attempts,
                    )
                    time.sleep(delay)
            except RPCException:
                raise
            except Exception as exc:
                # Non-retriable errors surface immediately.
                self._close_connection()
                raise RPCException(
                    {"code": -342, "message": f"Unexpected error: {exc}"}
                ) from exc

        # All retries exhausted.
        self._close_connection()
        raise RPCException(
            {
                "code": -342,
                "message": (
                    f"Failed to connect to {self._host}:{self._port} "
                    f"after {attempts} attempts: {last_exc}"
                ),
            }
        )

    def _read_response(
        self, conn: Union[http.client.HTTPConnection, http.client.HTTPSConnection]
    ) -> Any:
        """Read and parse the JSON-RPC response from *conn*."""
        http_response = conn.getresponse()
        if http_response is None:
            raise RPCException(
                {"code": -342, "message": "Missing HTTP response from server"}
            )

        response_data = http_response.read().decode("utf-8")

        # Bitcoin Core should always respond with application/json, but
        # certain error pages (e.g. 403) may not.  Provide a clear error.
        content_type = http_response.getheader("Content-Type")
        if content_type and "application/json" not in content_type:
            raise RPCException(
                {
                    "code": -342,
                    "message": (
                        f"Non-JSON HTTP response with "
                        f"'{http_response.status} {http_response.reason}' "
                        f"from server"
                    ),
                }
            )

        response = json.loads(response_data, parse_float=decimal.Decimal)

        if response.get("error") is not None:
            log.debug("<-- %s", response_data)
            raise RPCException(response["error"])

        if "result" not in response:
            raise RPCException({"code": -343, "message": "Missing JSON-RPC result"})

        log.debug(
            "<-%s- %s",
            response.get("id"),
            json.dumps(response["result"], default=_encode_decimal),
        )
        return response["result"]

    # ------------------------------------------------------------------
    # Batch RPC
    # ------------------------------------------------------------------
    def batch_(self, rpc_calls: Sequence[List[Any]]) -> List[Any]:
        """Send a batch JSON-RPC request.

        Parameters
        ----------
        rpc_calls : list of lists
            Each inner list is ``["method", param1, param2, …]``.

        Returns
        -------
        list
            The results of each call, in the same order.

        Raises
        ------
        RPCException
            If any individual call returns an error.
        """
        batch_payload: List[Dict[str, Any]] = []
        for call in rpc_calls:
            call = list(call)  # defensive copy
            method = call.pop(0)
            batch_payload.append(
                {
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": call,
                    "id": self._next_id(),
                }
            )

        postdata = json.dumps(batch_payload, default=_encode_decimal)
        log.debug("--> %s", postdata)

        headers = {
            "Host": self._host,
            "User-Agent": USER_AGENT,
            "Authorization": self._auth_header,
            "Content-Type": "application/json",
        }

        conn = self._get_connection()
        conn.request("POST", "/", postdata, headers)

        http_response = conn.getresponse()
        if http_response is None:
            raise RPCException(
                {"code": -342, "message": "Missing HTTP response from server"}
            )

        response_data = http_response.read().decode("utf-8")
        responses = json.loads(response_data, parse_float=decimal.Decimal)

        results: List[Any] = []
        for resp in responses:
            if resp.get("error") is not None:
                raise RPCException(resp["error"])
            if "result" not in resp:
                raise RPCException({"code": -343, "message": "Missing JSON-RPC result"})
            results.append(resp["result"])
        return results

    # ------------------------------------------------------------------
    # Dynamic method dispatch
    # ------------------------------------------------------------------
    def __getattr__(self, name: str) -> _RPCMethod:
        """Return a callable that will invoke the named RPC method.

        This allows natural syntax like ``proxy.getblockcount()``.
        """
        # Avoid intercepting Python internals / dunder methods.
        if name.startswith("_"):
            raise AttributeError(name)
        return _RPCMethod(self, name)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def __del__(self) -> None:
        self._close_connection()

    def __repr__(self) -> str:
        scheme = "https" if self._use_https else "http"
        return f"<NodeProxy {scheme}://{self._host}:{self._port}>"

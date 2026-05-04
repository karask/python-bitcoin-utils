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

"""Minimal BIP-32/BIP-39 HD wallet support.

This module intentionally implements only the functionality used by
bitcoinutils: deriving private keys from a mnemonic or an extended private key
and returning them as :class:`bitcoinutils.keys.PrivateKey` objects.
"""

from __future__ import annotations

import hashlib
import hmac
import unicodedata
from typing import Optional

from base58check import b58decode  # type: ignore

from bitcoinutils.keys import PrivateKey
from bitcoinutils.utils import h_to_b


_HARDENED_OFFSET = 0x80000000
_EXTENDED_KEY_PAYLOAD_LENGTH = 78
_XPRV_VERSION = bytes.fromhex("0488ade4")
_TPRV_VERSION = bytes.fromhex("04358394")

# Order of the secp256k1 generator point.
_SECP256K1_ORDER = int(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16
)


def _normalize_bip39_text(text: str) -> str:
    """Normalize mnemonic/passphrase text as required by BIP-39."""

    return unicodedata.normalize("NFKD", text)


def _mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """Create a BIP-39 seed from a mnemonic.

    The current public wrapper has no passphrase parameter, so callers use the
    BIP-39 default: an empty passphrase.
    """

    password = _normalize_bip39_text(mnemonic).encode("utf-8")
    salt = ("mnemonic" + _normalize_bip39_text(passphrase)).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", password, salt, 2048)


def _decode_base58check(data: str) -> bytes:
    """Decode Base58Check and verify the checksum."""

    decoded = b58decode(data.encode("utf-8"))
    if len(decoded) < 4:
        raise ValueError("Invalid Base58Check data")

    payload = decoded[:-4]
    checksum = decoded[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != expected:
        raise ValueError("Invalid Base58Check checksum")
    return payload


def _parse_xprivate_key(xprivate_key: str) -> tuple[bytes, bytes]:
    """Return ``(private_key, chain_code)`` from an xprv/tprv string."""

    payload = _decode_base58check(xprivate_key)
    if len(payload) != _EXTENDED_KEY_PAYLOAD_LENGTH:
        raise ValueError("Invalid extended private key length")

    version = payload[:4]
    if version not in (_XPRV_VERSION, _TPRV_VERSION):
        raise ValueError("Unsupported extended private key version")

    key_data = payload[45:78]
    if key_data[0] != 0:
        raise ValueError("Invalid extended private key payload")

    private_key = key_data[1:]
    _validate_private_key(private_key)
    chain_code = payload[13:45]
    return private_key, chain_code


def _master_key_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    """Create BIP-32 master private key and chain code from a BIP-39 seed."""

    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    private_key = digest[:32]
    chain_code = digest[32:]
    _validate_private_key(private_key)
    return private_key, chain_code


def _validate_private_key(private_key: bytes) -> None:
    if len(private_key) != 32:
        raise ValueError("Private key must be 32 bytes")
    value = int.from_bytes(private_key, "big")
    if value == 0 or value >= _SECP256K1_ORDER:
        raise ValueError("Invalid private key")


def _parse_path(path: str) -> list[int]:
    """Parse derivation paths like ``m/44'/1'/0'/0/3``."""

    if path in ("m", "M"):
        return []
    if not path or path[0] not in ("m", "M") or not path.startswith(("m/", "M/")):
        raise ValueError("Derivation path must start with 'm/'")

    indexes: list[int] = []
    for raw_component in path.split("/")[1:]:
        if raw_component == "":
            raise ValueError("Derivation path contains an empty component")

        hardened = raw_component[-1] in ("'", "h", "H")
        component = raw_component[:-1] if hardened else raw_component
        if not component.isdigit():
            raise ValueError(f"Invalid derivation path component: {raw_component}")

        index = int(component)
        if index >= _HARDENED_OFFSET:
            raise ValueError("Derivation path index is too large")
        if hardened:
            index += _HARDENED_OFFSET
        indexes.append(index)

    return indexes


def _derive_child_private_key(
    parent_private_key: bytes, parent_chain_code: bytes, index: int
) -> tuple[bytes, bytes]:
    """Derive one BIP-32 private child key."""

    if index >= _HARDENED_OFFSET:
        data = b"\x00" + parent_private_key + index.to_bytes(4, "big")
    else:
        parent_public_key = h_to_b(
            PrivateKey(b=parent_private_key).get_public_key().to_hex(compressed=True)
        )
        data = parent_public_key + index.to_bytes(4, "big")

    digest = hmac.new(parent_chain_code, data, hashlib.sha512).digest()
    left = int.from_bytes(digest[:32], "big")
    if left >= _SECP256K1_ORDER:
        raise ValueError("Invalid child private key")

    parent = int.from_bytes(parent_private_key, "big")
    child = (left + parent) % _SECP256K1_ORDER
    if child == 0:
        raise ValueError("Invalid child private key")

    return child.to_bytes(32, "big"), digest[32:]


def _derive_path(
    root_private_key: bytes, root_chain_code: bytes, path: str
) -> tuple[bytes, bytes]:
    """Derive an absolute BIP-32 path from root private key material."""

    private_key = root_private_key
    chain_code = root_chain_code
    for index in _parse_path(path):
        private_key, chain_code = _derive_child_private_key(
            private_key, chain_code, index
        )
    return private_key, chain_code


class HDWallet:
    """Minimal HD wallet wrapper used by bitcoinutils examples and tests.

    The wrapper supports deriving Bitcoin private keys from a BIP-39 mnemonic
    or an extended private key. It does not implement the full external
    ``hdwallet`` package API.
    """

    def __init__(
        self,
        xprivate_key: Optional[str] = None,
        path: Optional[str] = None,
        mnemonic: Optional[str] = None,
    ):
        if mnemonic and xprivate_key:
            raise ValueError("Pass either mnemonic or xprivate_key, not both")

        self._root_private_key: Optional[bytes] = None
        self._root_chain_code: Optional[bytes] = None
        self._private_key: Optional[bytes] = None
        self._chain_code: Optional[bytes] = None

        if mnemonic:
            self._root_private_key, self._root_chain_code = _master_key_from_seed(
                _mnemonic_to_seed(mnemonic)
            )
            self._private_key = self._root_private_key
            self._chain_code = self._root_chain_code

        if xprivate_key:
            if path is None:
                raise ValueError("Path must be provided with xprivate key")
            self._root_private_key, self._root_chain_code = _parse_xprivate_key(
                xprivate_key
            )
            self.from_path(path)

    @classmethod
    def from_mnemonic(cls, mnemonic: str):
        """Instantiate from a BIP-39 mnemonic code."""

        return cls(mnemonic=mnemonic)

    @classmethod
    def from_xprivate_key(cls, xprivate_key: str, path: Optional[str] = None):
        """Instantiate from an extended private key and derivation path."""

        if path is None:
            raise ValueError("Path must be provided with xprivate key")
        return cls(xprivate_key=xprivate_key, path=path)

    def from_path(self, path: str):
        """Derive and select a private key from an absolute BIP-32 path."""

        if self._root_private_key is None or self._root_chain_code is None:
            raise ValueError("No mnemonic or extended private key available")
        self._private_key, self._chain_code = _derive_path(
            self._root_private_key, self._root_chain_code, path
        )

    def get_private_key(self):
        """Return a PrivateKey object used throughout bitcoinutils."""

        if self._private_key is None:
            raise ValueError("No private key has been derived")
        return PrivateKey(b=self._private_key)

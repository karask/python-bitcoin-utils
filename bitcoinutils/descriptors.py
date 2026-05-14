# Copyright (C) 2018-2026 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

"""Small fixed-key output descriptor support.

This module implements an educational subset of Bitcoin Core output
descriptors. It supports fixed public keys and address/script conversion, but
intentionally does not implement ranged descriptors, xpub derivation, private
keys, or Miniscript.

The checksum algorithm is ported from Bitcoin Core's MIT-licensed functional
test framework (``test/functional/test_framework/descriptors.py``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

import bitcoinutils.bech32
from bitcoinutils.constants import NETWORK_SEGWIT_PREFIXES
from bitcoinutils.constants import P2WSH_ADDRESS_V0
from bitcoinutils.keys import (
    Address,
    P2pkhAddress,
    P2shAddress,
    P2trAddress,
    P2wpkhAddress,
    P2wshAddress,
    PublicKey,
    SegwitAddress,
)
from bitcoinutils.script import Script
from bitcoinutils.setup import get_network
from bitcoinutils.utils import b_to_h, h_to_b


INPUT_CHARSET = (
    "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
    "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
)
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATOR = [0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD]


class DescriptorError(ValueError):
    """Raised when a descriptor is malformed or unsupported."""


def _descsum_polymod(symbols: list[int]) -> int:
    chk = 1
    for value in symbols:
        top = chk >> 35
        chk = ((chk & 0x7FFFFFFFF) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= GENERATOR[i]
    return chk


def _descsum_expand(desc: str) -> list[int]:
    groups: list[int] = []
    symbols: list[int] = []
    for char in desc:
        if char not in INPUT_CHARSET:
            raise DescriptorError(f"Invalid descriptor character: {char!r}")
        value = INPUT_CHARSET.find(char)
        symbols.append(value & 31)
        groups.append(value >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    return symbols


def descriptor_checksum(desc: str) -> str:
    """Return the 8-character Bitcoin Core descriptor checksum."""

    body = _split_checksum(desc)[0]
    symbols = _descsum_expand(body) + [0] * 8
    checksum = _descsum_polymod(symbols) ^ 1
    return "".join(
        CHECKSUM_CHARSET[(checksum >> (5 * (7 - i))) & 31] for i in range(8)
    )


def add_descriptor_checksum(desc: str) -> str:
    """Return *desc* with a Bitcoin Core compatible checksum suffix."""

    body = _split_checksum(desc)[0]
    return f"{body}#{descriptor_checksum(body)}"


def _split_checksum(desc: str) -> tuple[str, Optional[str]]:
    if desc.count("#") > 1:
        raise DescriptorError("Descriptor contains more than one checksum separator")
    if "#" not in desc:
        return desc, None
    body, checksum = desc.rsplit("#", 1)
    if len(checksum) != 8:
        raise DescriptorError("Descriptor checksum must be 8 characters")
    if any(char not in CHECKSUM_CHARSET for char in checksum):
        raise DescriptorError("Descriptor checksum contains invalid characters")
    return body, checksum


def _check_descriptor_checksum(desc: str, require: bool) -> bool:
    body, checksum = _split_checksum(desc)
    if checksum is None:
        return not require
    symbols = _descsum_expand(body) + [CHECKSUM_CHARSET.find(c) for c in checksum]
    return _descsum_polymod(symbols) == 1


@dataclass(frozen=True)
class _Key:
    hex: str

    @classmethod
    def parse(cls, value: str) -> "_Key":
        if any(marker in value for marker in ("[", "]", "/", "*")):
            raise NotImplementedError(
                "Key origins, derivation paths, and ranged keys are not supported"
            )
        if value[:4] in ("xpub", "ypub", "zpub", "tpub", "upub", "vpub"):
            raise NotImplementedError("Extended public keys are not supported")
        if value[:4] in ("xprv", "yprv", "zprv", "tprv", "uprv", "vprv"):
            raise NotImplementedError("Extended private keys are not supported")
        if re.match(r"^[5KLc9][1-9A-HJ-NP-Za-km-z]+$", value):
            raise NotImplementedError("Private keys and WIF keys are not supported")
        if not re.match(r"^[0-9a-fA-F]+$", value):
            raise DescriptorError(f"Invalid public key: {value}")
        try:
            PublicKey(value)
        except Exception as exc:
            raise DescriptorError(f"Invalid public key: {value}") from exc
        return cls(value.lower())

    def public_key(self) -> PublicKey:
        return PublicKey(self.hex)

    def is_compressed(self) -> bool:
        return len(self.hex) == 66 and self.hex[:2] in ("02", "03")

    def is_x_only(self) -> bool:
        return len(self.hex) == 64

    def compressed_hex(self) -> str:
        return self.public_key().to_hex(compressed=True)

    def legacy_hex(self) -> str:
        return self.hex if len(self.hex) == 130 else self.compressed_hex()


@dataclass(frozen=True)
class Descriptor:
    """Parsed fixed-key output descriptor."""

    name: str
    args: tuple[object, ...]
    checksum: Optional[str] = None

    @classmethod
    def from_string(cls, desc: str, require_checksum: bool = False) -> "Descriptor":
        return parse_descriptor(desc, require_checksum=require_checksum)

    def to_string(self, with_checksum: bool = False) -> str:
        body = self._body()
        return add_descriptor_checksum(body) if with_checksum else body

    def validate_checksum(self) -> bool:
        if self.checksum is None:
            return False
        return _check_descriptor_checksum(f"{self._body()}#{self.checksum}", True)

    def get_type(self) -> str:
        return self.name

    def to_script_pub_key(self) -> Script:
        if self.name == "pk":
            return Script([self._key(0).legacy_hex(), "OP_CHECKSIG"])
        if self.name == "pkh":
            return self._key(0).public_key().get_address(
                compressed=self._key(0).is_compressed()
            ).to_script_pub_key()
        if self.name == "wpkh":
            return self.to_address().to_script_pub_key()
        if self.name == "multi" or self.name == "sortedmulti":
            return self._multisig_script()
        if self.name == "sh":
            return P2shAddress(
                script=self._descriptor(0).to_script_pub_key()
            ).to_script_pub_key()
        if self.name == "wsh":
            return P2wshAddress(
                script=self._descriptor(0).to_script_pub_key()
            ).to_script_pub_key()
        if self.name == "tr":
            return self.to_address().to_script_pub_key()
        if self.name == "addr":
            return self._address_script_pub_key()
        if self.name == "raw":
            return Script.from_raw(self.args[0])  # type: ignore[arg-type]
        raise DescriptorError(f"Unsupported descriptor function: {self.name}")

    def to_address(self) -> Address | SegwitAddress:
        if self.name == "pk":
            raise DescriptorError("Bare pk() scripts do not have an address")
        if self.name == "raw":
            raise DescriptorError("raw() scripts do not have a known address type")
        if self.name == "multi" or self.name == "sortedmulti":
            raise DescriptorError("Bare multisig scripts do not have an address")
        if self.name == "pkh":
            key = self._key(0)
            return key.public_key().get_address(compressed=key.is_compressed())
        if self.name == "wpkh":
            key = self._key(0)
            if not key.is_compressed():
                raise DescriptorError("wpkh() requires a compressed public key")
            return key.public_key().get_segwit_address()
        if self.name == "sh":
            return P2shAddress(script=self._descriptor(0).to_script_pub_key())
        if self.name == "wsh":
            return P2wshAddress(script=self._descriptor(0).to_script_pub_key())
        if self.name == "tr":
            key = self._key(0)
            if not (key.is_compressed() or key.is_x_only()):
                raise DescriptorError("tr() requires a compressed or x-only public key")
            return key.public_key().get_taproot_address()
        if self.name == "addr":
            return _parse_address(self.args[0])  # type: ignore[arg-type]
        raise DescriptorError(f"Unsupported descriptor function: {self.name}")

    def _body(self) -> str:
        if self.name in ("pk", "pkh", "wpkh", "tr"):
            return f"{self.name}({self._key(0).hex})"
        if self.name in ("sh", "wsh"):
            return f"{self.name}({self._descriptor(0)._body()})"
        if self.name in ("multi", "sortedmulti"):
            threshold = self.args[0]
            keys = ",".join(key.hex for key in self.args[1:])  # type: ignore[union-attr]
            return f"{self.name}({threshold},{keys})"
        if self.name in ("addr", "raw"):
            return f"{self.name}({self.args[0]})"
        raise DescriptorError(f"Unsupported descriptor function: {self.name}")

    def _key(self, index: int) -> _Key:
        key = self.args[index]
        if not isinstance(key, _Key):
            raise DescriptorError("Expected a key argument")
        return key

    def _descriptor(self, index: int) -> "Descriptor":
        desc = self.args[index]
        if not isinstance(desc, Descriptor):
            raise DescriptorError("Expected a descriptor argument")
        return desc

    def _multisig_script(self) -> Script:
        threshold = self.args[0]
        if not isinstance(threshold, int):
            raise DescriptorError("Multisig threshold must be an integer")
        keys = list(self.args[1:])
        if self.name == "sortedmulti":
            keys.sort(key=lambda key: key.compressed_hex())  # type: ignore[union-attr]
        return Script(
            [f"OP_{threshold}"]
            + [key.compressed_hex() for key in keys]  # type: ignore[union-attr]
            + [f"OP_{len(keys)}", "OP_CHECKMULTISIG"]
        )

    def _address_script_pub_key(self) -> Script:
        address = self.to_address()
        return address.to_script_pub_key()


def parse_descriptor(desc: str, require_checksum: bool = False) -> Descriptor:
    """Parse a fixed-key output descriptor."""

    if not _check_descriptor_checksum(desc, require_checksum):
        raise DescriptorError("Invalid or missing descriptor checksum")
    body, checksum = _split_checksum(desc)
    if body == "":
        raise DescriptorError("Descriptor is empty")
    parsed, cursor = _parse_expression(body, 0)
    if cursor != len(body):
        raise DescriptorError(f"Unexpected descriptor text at position {cursor}")
    parsed = Descriptor(parsed.name, parsed.args, checksum)
    _validate_descriptor(parsed, is_top_level=True, parent=None)
    return parsed


def _parse_expression(text: str, cursor: int) -> tuple[Descriptor, int]:
    start = cursor
    while cursor < len(text) and text[cursor].isalpha():
        cursor += 1
    if cursor == start or cursor >= len(text) or text[cursor] != "(":
        raise DescriptorError(f"Expected descriptor function at position {start}")

    name = text[start:cursor]
    cursor += 1
    args, cursor = _parse_arguments(text, cursor)
    return _build_descriptor(name, args), cursor


def _parse_arguments(text: str, cursor: int) -> tuple[list[object], int]:
    args: list[object] = []
    token_start = cursor
    depth = 0
    while cursor < len(text):
        char = text[cursor]
        if char == "(":
            depth += 1
        elif char == ")":
            if depth == 0:
                if cursor > token_start:
                    args.append(_parse_argument(text[token_start:cursor]))
                elif args:
                    raise DescriptorError("Empty descriptor argument")
                return args, cursor + 1
            depth -= 1
        elif char == "," and depth == 0:
            if cursor == token_start:
                raise DescriptorError("Empty descriptor argument")
            args.append(_parse_argument(text[token_start:cursor]))
            token_start = cursor + 1
        cursor += 1
    raise DescriptorError("Unclosed descriptor expression")


def _parse_argument(value: str) -> object:
    value = value.strip()
    if value == "":
        raise DescriptorError("Empty descriptor argument")
    if "(" in value:
        parsed, cursor = _parse_expression(value, 0)
        if cursor != len(value):
            raise DescriptorError(f"Unexpected nested descriptor text: {value}")
        return parsed
    if value.isdigit():
        return int(value)
    return value


def _build_descriptor(name: str, raw_args: list[object]) -> Descriptor:
    supported = {
        "pk",
        "pkh",
        "wpkh",
        "sh",
        "wsh",
        "multi",
        "sortedmulti",
        "tr",
        "addr",
        "raw",
    }
    if name not in supported:
        if name in ("combo", "multi_a", "sortedmulti_a"):
            raise NotImplementedError(f"{name}() descriptors are not supported")
        raise DescriptorError(f"Unsupported descriptor function: {name}")

    if name in ("pk", "pkh", "wpkh", "tr"):
        if len(raw_args) != 1 or not isinstance(raw_args[0], str):
            raise DescriptorError(f"{name}() expects exactly one key")
        return Descriptor(name, (_Key.parse(raw_args[0]),))

    if name in ("sh", "wsh"):
        if len(raw_args) != 1 or not isinstance(raw_args[0], Descriptor):
            raise DescriptorError(f"{name}() expects one nested descriptor")
        return Descriptor(name, (raw_args[0],))

    if name in ("multi", "sortedmulti"):
        if len(raw_args) < 3 or not isinstance(raw_args[0], int):
            raise DescriptorError(f"{name}() expects threshold and public keys")
        threshold = raw_args[0]
        key_args = raw_args[1:]
        if not 1 <= threshold <= len(key_args) <= 16:
            raise DescriptorError("Multisig threshold must satisfy 1 <= k <= n <= 16")
        if not all(isinstance(arg, str) for arg in key_args):
            raise DescriptorError(f"{name}() accepts only public key arguments")
        keys = tuple(_Key.parse(arg) for arg in key_args)  # type: ignore[arg-type]
        if not all(key.is_compressed() for key in keys):
            raise DescriptorError(f"{name}() requires compressed public keys")
        return Descriptor(name, (threshold,) + keys)

    if name == "addr":
        if len(raw_args) != 1 or not isinstance(raw_args[0], str):
            raise DescriptorError("addr() expects exactly one address")
        _parse_address(raw_args[0])
        return Descriptor(name, (raw_args[0],))

    if name == "raw":
        if len(raw_args) != 1 or not isinstance(raw_args[0], str):
            raise DescriptorError("raw() expects exactly one hex script")
        try:
            h_to_b(raw_args[0])
            Script.from_raw(raw_args[0])
        except Exception as exc:
            raise DescriptorError("raw() expects a valid hex script") from exc
        return Descriptor(name, (raw_args[0].lower(),))

    raise DescriptorError(f"Unsupported descriptor function: {name}")


def _validate_descriptor(
    desc: Descriptor, is_top_level: bool, parent: Optional[str]
) -> None:
    name = desc.name
    if name == "sh":
        if not is_top_level:
            raise DescriptorError("sh() is only supported at the top level")
        child = desc._descriptor(0)
        if child.name not in ("wpkh", "wsh", "multi", "sortedmulti"):
            raise DescriptorError(
                "sh() supports only wpkh(), wsh(), multi(), or sortedmulti() in v1"
            )
        _validate_descriptor(child, is_top_level=False, parent="sh")
    elif name == "wsh":
        if not (is_top_level or parent == "sh"):
            raise DescriptorError("wsh() is only supported at top level or inside sh()")
        child = desc._descriptor(0)
        if child.name not in ("multi", "sortedmulti"):
            raise DescriptorError("wsh() supports only multi() or sortedmulti() in v1")
        _validate_descriptor(child, is_top_level=False, parent="wsh")
    elif name == "wpkh":
        if not (is_top_level or parent == "sh"):
            raise DescriptorError("wpkh() is only supported at top level or inside sh()")
        if not desc._key(0).is_compressed():
            raise DescriptorError("wpkh() requires a compressed public key")
    elif name == "tr":
        if not is_top_level:
            raise DescriptorError("tr() is only supported at the top level in v1")
        if not (desc._key(0).is_compressed() or desc._key(0).is_x_only()):
            raise DescriptorError("tr() requires a compressed or x-only public key in v1")
    elif name in ("addr", "raw"):
        if not is_top_level:
            raise DescriptorError(f"{name}() is only supported at the top level")
    elif name in ("pk", "pkh", "multi", "sortedmulti"):
        return


def _parse_address(address: str) -> Address | SegwitAddress:
    for address_cls in (P2pkhAddress, P2shAddress):
        try:
            return address_cls(address=address)
        except Exception:
            pass

    hrp = NETWORK_SEGWIT_PREFIXES[get_network()]
    witness_version, witness_program = bitcoinutils.bech32.decode(hrp, address)  # type: ignore[attr-defined]
    if witness_version is None or witness_program is None:
        raise DescriptorError("addr() contains an invalid address for the active network")

    witness_hex = b_to_h(bytes(witness_program))
    if witness_version == 0 and len(witness_program) == 20:
        return P2wpkhAddress(witness_program=witness_hex)
    if witness_version == 0 and len(witness_program) == 32:
        return _p2wsh_from_witness_program(witness_hex)
    if witness_version == 1 and len(witness_program) == 32:
        return P2trAddress(witness_program=witness_hex)
    raise DescriptorError("addr() contains an unsupported witness program")


def _p2wsh_from_witness_program(witness_program: str) -> P2wshAddress:
    # P2wshAddress currently only builds from a witness script. Descriptors also
    # need to represent an already-known P2WSH address, so create the object
    # with the fields SegwitAddress normally sets.
    address = object.__new__(P2wshAddress)
    address.version = P2WSH_ADDRESS_V0
    address.segwit_num_version = 0
    address.witness_program = witness_program
    return address

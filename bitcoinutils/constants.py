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

NETWORK_DEFAULT_PORTS = {
    "mainnet": 8332,
    "signet": 38332,
    "testnet": 18332,
    "regtest": 18443,
}

NETWORK_WIF_PREFIXES = {
    "mainnet": b"\x80",
    "signet": b"\xef",
    "testnet": b"\xef",
    "regtest": b"\xef",
}

NETWORK_P2PKH_PREFIXES = {
    "mainnet": b"\x00",
    "signet": b"\x6f",
    "testnet": b"\x6f",
    "regtest": b"\x6f",
}

NETWORK_P2SH_PREFIXES = {
    "mainnet": b"\x05",
    "signet": b"\xc4",
    "testnet": b"\xc4",
    "regtest": b"\xc4",
}

NETWORK_SEGWIT_PREFIXES = {
    "mainnet": "bc",
    "signet": "tb",
    "testnet": "tb",
    "regtest": "bcrt",
}


# Constants for address types
P2PKH_ADDRESS = "p2pkh"
P2SH_ADDRESS = "p2sh"
P2WPKH_ADDRESS_V0 = "p2wpkhv0"
P2WSH_ADDRESS_V0 = "p2wshv0"
P2TR_ADDRESS_V1 = "p2trv1"


# Constants related to transaction signature types
TAPROOT_SIGHASH_ALL = 0x00
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80


# Constants for time lock and RB
TYPE_ABSOLUTE_TIMELOCK = 0x101
TYPE_RELATIVE_TIMELOCK = 0x201
TYPE_REPLACE_BY_FEE = 0x301

DEFAULT_TX_LOCKTIME = b"\x00\x00\x00\x00"

EMPTY_TX_SEQUENCE = b"\x00\x00\x00\x00"
DEFAULT_TX_SEQUENCE = b"\xff\xff\xff\xff"
ABSOLUTE_TIMELOCK_SEQUENCE = b"\xfe\xff\xff\xff"

REPLACE_BY_FEE_SEQUENCE = b"\x01\x00\x00\x00"


# Constants related to transaction versions and scripts
LEAF_VERSION_TAPSCRIPT = 0xC0


# TX version 2 was introduced in BIP-68 with relative locktime -- tx v1
# does not support relative locktime
DEFAULT_TX_VERSION = b"\x02\x00\x00\x00"


# Monetary constants
SATOSHIS_PER_BITCOIN = 100000000
NEGATIVE_SATOSHI = -1

# Block
HEADER_SIZE = 80

BLOCK_MAGIC_NUMBER = {
    "f9beb4d9" : "mainnet",
    "0b110907" : "testnet",
    "fabfb5da" : "regtest",
    "0a03cf40" : "signet"
}
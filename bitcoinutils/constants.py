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

# Constants related to network configuration
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
ADDRESS_TYPES = {
    "P2PKH": "p2pkh",
    "P2SH": "p2sh",
    "P2WPKH_V0": "p2wpkhv0",
    "P2WSH_V0": "p2wshv0",
    "P2TR_V1": "p2trv1",
}

# Constants related to transaction signature types
SIGHASH_TYPES = {
    "ALL": 0x01,
    "NONE": 0x02,
    "SINGLE": 0x03,
    "ANYONECANPAY": 0x80,
    "TAPROOT_ALL": 0x00,
}

# Constants for time lock and RBF
TIMELOCK_AND_RBF_CONSTANTS = {
    "ABSOLUTE_TIMELOCK": 0x101,
    "RELATIVE_TIMELOCK": 0x201,
    "REPLACE_BY_FEE": 0x301,
    "DEFAULT_TX_LOCKTIME": b"\x00\x00\x00\x00",
    "EMPTY_TX_SEQUENCE": b"\x00\x00\x00\x00",
    "DEFAULT_TX_SEQUENCE": b"\xff\xff\xff\xff",
    "ABSOLUTE_TIMELOCK_SEQUENCE": b"\xfe\xff\xff\xff",
    "REPLACE_BY_FEE_SEQUENCE": b"\x01\x00\x00\x00",
}

# Constants related to transaction versions and scripts
TX_AND_SCRIPT_CONSTANTS = {
    "LEAF_VERSION_TAPSCRIPT": 0xC0,
    "DEFAULT_TX_VERSION": b"\x02\x00\x00\x00",
}

# Monetary constants
MONETARY_CONSTANTS = {
    "SATOSHIS_PER_BITCOIN": 100000000,
    "NEGATIVE_SATOSHI": -1,
}

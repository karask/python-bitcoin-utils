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

NETWORK = "testnet"
networks = {"mainnet", "testnet", "regtest"}

# Configuration for automatic '00' byte handling for non-witness inputs
AUTO_ADD_ZERO_BYTE_TO_NON_WITNESS = False

def setup(network: str = "testnet", auto_add_zero_byte: bool = False) -> str:
    """Setup bitcoin utils library with the specified network and options.
    
    Args:
        network: The network to use (mainnet, testnet, regtest)
        auto_add_zero_byte: Whether to automatically add '00' byte to non-witness inputs
                           in segwit transactions (default: False)
    """
    global NETWORK, AUTO_ADD_ZERO_BYTE_TO_NON_WITNESS
    NETWORK = network
    AUTO_ADD_ZERO_BYTE_TO_NON_WITNESS = auto_add_zero_byte
    return NETWORK

def get_network() -> str:
    global NETWORK
    return NETWORK

def is_mainnet() -> bool:
    global NETWORK
    if NETWORK == "mainnet":
        return True
    else:
        return False

def is_testnet() -> bool:
    global NETWORK
    if NETWORK == "testnet":
        return True
    else:
        return False

def is_regtest() -> bool:
    global NETWORK
    if NETWORK == "regtest":
        return True
    else:
        return False

def get_auto_add_zero_byte() -> bool:
    """Returns whether automatic '00' byte handling is enabled for non-witness inputs"""
    global AUTO_ADD_ZERO_BYTE_TO_NON_WITNESS
    return AUTO_ADD_ZERO_BYTE_TO_NON_WITNESS

def set_auto_add_zero_byte(value: bool) -> None:
    """Sets whether automatic '00' byte handling is enabled for non-witness inputs"""
    global AUTO_ADD_ZERO_BYTE_TO_NON_WITNESS
    AUTO_ADD_ZERO_BYTE_TO_NON_WITNESS = value
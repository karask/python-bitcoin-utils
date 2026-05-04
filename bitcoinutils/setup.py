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

NETWORK = "testnet"
SECURITY_WARNINGS = True
_SECURITY_WARNING_EMITTED = False

networks = {"mainnet", "testnet", "testnet4", "signet", "regtest"}


def setup(network: str = "testnet") -> str:
    global NETWORK
    if network not in networks:
        supported = ", ".join(sorted(networks))
        raise ValueError(
            f"Unknown network '{network}'. Supported networks: {supported}"
        )
    NETWORK = network
    return NETWORK


def get_network() -> str:
    global NETWORK
    return NETWORK


def set_security_warnings(enabled: bool) -> None:
    """Enable or disable warnings for pure-Python private-key operations."""

    global SECURITY_WARNINGS
    global _SECURITY_WARNING_EMITTED
    SECURITY_WARNINGS = enabled
    if enabled:
        _SECURITY_WARNING_EMITTED = False


def get_security_warnings() -> bool:
    """Return whether pure-Python private-key operation warnings are enabled."""

    return SECURITY_WARNINGS


def should_warn_about_private_key_use() -> bool:
    """Return True the first time a private-key operation should warn."""

    global _SECURITY_WARNING_EMITTED
    if NETWORK != "mainnet" or not SECURITY_WARNINGS or _SECURITY_WARNING_EMITTED:
        return False
    _SECURITY_WARNING_EMITTED = True
    return True


def is_mainnet() -> bool:
    return NETWORK == "mainnet"


def is_testnet() -> bool:
    return NETWORK == "testnet"


def is_testnet4() -> bool:
    return NETWORK == "testnet4"


def is_signet() -> bool:
    return NETWORK == "signet"


def is_regtest() -> bool:
    return NETWORK == "regtest"

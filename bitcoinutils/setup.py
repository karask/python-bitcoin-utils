# Copyright (C) 2018-2020 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

NETWORK = None

networks = {'mainnet', 'testnet', 'regtest'}

def setup(network='mainnet'):
    global NETWORK
    NETWORK = network
    return NETWORK


def get_network():
    global NETWORK
    return NETWORK


def is_mainnet():
    global NETWORK
    if NETWORK == 'mainnet':
        return True
    else:
        return False

def is_testnet():
    global NETWORK
    if NETWORK == 'testnet':
        return True
    else:
        return False

def is_regtest():
    global NETWORK
    if NETWORK == 'regtest':
        return True
    else:
        return False

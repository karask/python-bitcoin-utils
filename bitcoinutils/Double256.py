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

import hashlib

def double_sha256(data):
    """Applies SHA-256 twice to input data."""
    first_hash = hashlib.sha256(data).digest()
    second_hash = hashlib.sha256(first_hash).digest()
    return second_hash.hex()

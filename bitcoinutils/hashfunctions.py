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

import hashlib
import time

def hash_sha256(b: bytes) -> bytes:
    """Computes SHA-256 hash of the given bytes."""
    return hashlib.sha256(b).digest()

def hash_ripemd160(b: bytes) -> bytes:
    """Computes RIPEMD-160 hash of the given bytes."""
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(b)
    return ripemd160.digest()

def hash_sha1(b: bytes) -> bytes:
    """Computes SHA-1 hash of the given bytes."""
    return hashlib.sha1(b).digest()

def calculate_hash_rate(hash_function, duration_seconds=1):
    """Measure the number of hashes computed in a specified duration using the given hash function."""
    start_time = time.time()
    end_time = start_time + duration_seconds
    hash_count = 0
    sample_data = b"Bitcoin hash rate test data"

    while time.time() < end_time:
        hash_function(sample_data)
        hash_count += 1

    return hash_count

def estimate_computers_needed(hash_rate_per_computer, years_to_break):
    """Estimate the number of computers needed to perform a preimage attack on a cryptographic hash function."""
    HASHES_FOR_PREIMAGE = 2**256  # Assuming SHA-256 scale, adjust if necessary
    SECONDS_PER_YEAR = 31536000   # Seconds in a year

    total_hashes_in_timeframe = hash_rate_per_computer * SECONDS_PER_YEAR * years_to_break
    number_of_computers = HASHES_FOR_PREIMAGE / total_hashes_in_timeframe

    return number_of_computers

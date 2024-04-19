# Copyright (C) 2018-2022 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import hashlib
import time

def double_sha256(input_data):
    """Applies SHA-256 twice to the input data."""
    first_hash = hashlib.sha256(input_data).digest()
    return hashlib.sha256(first_hash).hexdigest()

def measure_hash_rate(duration_seconds=1):
    """Measures how many double SHA-256 hashes can be computed per second."""
    start_time = time.time()
    count = 0
    while time.time() - start_time < duration_seconds:
        data = f"sample data {count}".encode('utf-8')
        double_sha256(data)
        count += 1
    return count

def estimate_preimage_attack_time(hash_rate):
    """Estimates the time in years to perform a preimage attack on double SHA-256."""
    total_hashes = 2**256  # Number of hashes to find a preimage
    seconds = total_hashes / hash_rate
    years = seconds / (365.25 * 24 * 3600)
    return years

# Measure hash rate
hash_rate = measure_hash_rate()
print(f"Hash rate: {hash_rate} double-SHA256 hashes per second")

# Estimate attack time
attack_time_years = estimate_preimage_attack_time(hash_rate)
print(f"Estimated time to find a preimage by brute force: {attack_time_years:.2e} years")

# Age of the universe in years (approximation)
age_of_universe = 13.8e9  # 13.8 billion years
times_universe_age = attack_time_years / age_of_universe
print(f"Time required is {times_universe_age:.2e} times the age of the universe")

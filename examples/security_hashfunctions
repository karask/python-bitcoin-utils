# Copyright (C) 2018-2023 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
# No part of python-bitcoin-utils, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from bitcoinutils.hashfunctions import hash_sha256, hash_ripemd160, hash_sha1, calculate_hash_rate, \
    estimate_computers_needed


def main():
    # Measure hash rates for SHA-256, RIPEMD-160, and SHA-1
    sha256_rate = calculate_hash_rate(hash_sha256)
    ripemd160_rate = calculate_hash_rate(hash_ripemd160)
    sha1_rate = calculate_hash_rate(hash_sha1)

    print(f"SHA-256 hashes per second: {sha256_rate}")
    print(f"RIPEMD-160 hashes per second: {ripemd160_rate}")
    print(f"SHA-1 hashes per second: {sha1_rate}")

    # Estimate the number of computers needed to perform a preimage attack in 1 year
    years_to_break = 1
    computers_needed_sha256 = estimate_computers_needed(sha256_rate, years_to_break)
    computers_needed_ripemd160 = estimate_computers_needed(ripemd160_rate, years_to_break)
    computers_needed_sha1 = estimate_computers_needed(sha1_rate, years_to_break)

    print(f"Computers needed for SHA-256 attack in 1 year: {computers_needed_sha256:.2e}")
    print(f"Computers needed for RIPEMD-160 attack in 1 year: {computers_needed_ripemd160:.2e}")
    print(f"Computers needed for SHA-1 attack in 1 year: {computers_needed_sha1:.2e}")


if __name__ == "__main__":
    main()

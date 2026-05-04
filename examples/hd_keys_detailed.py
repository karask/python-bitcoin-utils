# Copyright (C) 2018-2025 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

"""Detailed HD wallet examples.

This example demonstrates the minimal HD functionality provided by
bitcoinutils:

* create a wallet from a BIP-39 mnemonic
* derive private keys from different BIP-style paths
* derive legacy, segwit v0, and taproot addresses from the same key
* switch paths on the same HDWallet instance
* create a wallet from an extended private key

The mnemonic and extended private keys below are for testnet examples only.
Do not use them with real funds.
"""

from bitcoinutils.setup import setup
from bitcoinutils.hdwallet import HDWallet


def print_key_details(title, hdw):
    """Print the currently selected key and common address types."""

    privkey = hdw.get_private_key()
    pubkey = privkey.get_public_key()

    print(f"\n{title}")
    print("-" * len(title))
    print("WIF:", privkey.to_wif())
    print("Public key:", pubkey.to_hex())
    print("Legacy P2PKH:", pubkey.get_address().to_string())
    print("Native Segwit P2WPKH:", pubkey.get_segwit_address().to_string())
    print("Taproot P2TR:", pubkey.get_taproot_address().to_string())


def derive_and_print(hdw, path):
    """Derive an absolute path and print the resulting key/address details."""

    hdw.from_path(path)
    print_key_details(f"Path {path}", hdw)


def main():
    setup("testnet")

    mnemonic = (
        "addict weather world sense idle purity rich wagon "
        "ankle fall cheese spatial"
    )

    print("Mnemonic wallet")
    print("===============")
    print("Mnemonic:", mnemonic)

    hdw_from_mnemonic = HDWallet(mnemonic=mnemonic)

    # BIP-44: legacy P2PKH-style account path.
    derive_and_print(hdw_from_mnemonic, "m/44'/1'/0'/0/0")
    derive_and_print(hdw_from_mnemonic, "m/44'/1'/0'/0/1")

    # BIP-84: native segwit account path. The private/public key can still be
    # rendered as multiple address types; the path communicates wallet intent.
    derive_and_print(hdw_from_mnemonic, "m/84'/1'/0'/0/0")

    # BIP-86: taproot account path.
    derive_and_print(hdw_from_mnemonic, "m/86'/1'/0'/0/0")

    print("\nSwitching paths")
    print("===============")
    hdw_from_mnemonic.from_path("m/44'/1'/0'/0/3")
    addr_a = hdw_from_mnemonic.get_private_key().get_public_key().get_address()
    print("m/44'/1'/0'/0/3 legacy address:", addr_a.to_string())

    hdw_from_mnemonic.from_path("m/44'/1'/0'/0/4")
    addr_b = hdw_from_mnemonic.get_private_key().get_public_key().get_address()
    print("m/44'/1'/0'/0/4 legacy address:", addr_b.to_string())

    xprivkey = (
        "tprv8ZgxMBicQKsPdQR9RuHpGGxSnNq8Jr3X4WnT6Nf2eq7FajuXyBep5KWYpYEixxx5XdTm1N"
        "tpe84f3cVcF7mZZ7mPkntaFXLGJD2tS7YJkWU"
    )

    print("\nExtended private key wallet")
    print("===========================")
    print("Extended private key:", xprivkey)

    hdw_from_xpriv = HDWallet.from_xprivate_key(xprivkey, "m/86'/1'/0'/0/1")
    print_key_details("Path m/86'/1'/0'/0/1", hdw_from_xpriv)

    hdw_from_xpriv.from_path("m/86'/1'/0'/0/5")
    print_key_details("Path m/86'/1'/0'/0/5", hdw_from_xpriv)


if __name__ == "__main__":
    main()

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

from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey
from bitcoinutils.address import UnifiedAddress
from bitcoinutils.constants import P2PKH_ADDRESS, P2WPKH_ADDRESS_V0, P2SH_ADDRESS, P2TR_ADDRESS_V1

def main():
    # always remember to setup the network
    setup('testnet')
    
    # create a private key (deterministically)
    priv = PrivateKey(secret_exponent=1)
    print("\nPrivate key WIF:", priv.to_wif())
    
    # get the public key
    pub = priv.get_public_key()
    print("Public key:", pub.to_hex())
    
    # create different address types from the public key
    p2pkh_addr = pub.get_address()
    p2wpkh_addr = pub.get_segwit_address()
    p2tr_addr = pub.get_taproot_address()
    
    print("\n--- Original Addresses ---")
    print(f"P2PKH Address: {p2pkh_addr.to_string()}")
    print(f"P2WPKH Address: {p2wpkh_addr.to_string()}")
    print(f"P2TR Address: {p2tr_addr.to_string()}")
    
    # Create unified addresses from existing addresses
    unified_p2pkh = UnifiedAddress(p2pkh_addr)
    unified_p2wpkh = UnifiedAddress(p2wpkh_addr)
    unified_p2tr = UnifiedAddress(p2tr_addr)
    
    print("\n--- Unified Address Creation ---")
    print(f"From P2PKH: {unified_p2pkh}")
    print(f"From P2WPKH: {unified_p2wpkh}")
    print(f"From P2TR: {unified_p2tr}")
    
    # Create from address strings
    print("\n--- Create from Address Strings ---")
    unified_from_str = UnifiedAddress.from_address(p2pkh_addr.to_string())
    print(f"Detected type: {unified_from_str.address_type}")
    print(f"Address: {unified_from_str.to_string()}")
    
    # Address conversion
    print("\n--- Address Conversion ---")
    
    # P2PKH to P2WPKH
    p2wpkh_converted = unified_p2pkh.to_address_type(P2WPKH_ADDRESS_V0)
    print(f"P2PKH to P2WPKH: {p2wpkh_converted}")
    
    # P2PKH to P2SH-P2WPKH (nested SegWit)
    p2sh_p2wpkh = unified_p2pkh.to_address_type(P2SH_ADDRESS)
    print(f"P2PKH to P2SH-P2WPKH: {p2sh_p2wpkh}")
    
    # P2WPKH to P2PKH
    p2pkh_converted = unified_p2wpkh.to_address_type(P2PKH_ADDRESS)
    print(f"P2WPKH to P2PKH: {p2pkh_converted}")
    
    print("\n--- Invalid Conversions ---")
    try:
        # P2PKH to P2TR (invalid conversion)
        unified_p2pkh.to_address_type(P2TR_ADDRESS_V1)
    except ValueError as e:
        print(f"P2PKH to P2TR error: {e}")
    
    try:
        # P2TR to P2PKH (invalid conversion)
        unified_p2tr.to_address_type(P2PKH_ADDRESS)
    except ValueError as e:
        print(f"P2TR to P2PKH error: {e}")
    
    # Script Pub Key access
    print("\n--- Script Pub Key Access ---")
    p2pkh_script = unified_p2pkh.to_script_pub_key()
    print(f"P2PKH Script: {p2pkh_script}")
    
    p2wpkh_script = unified_p2wpkh.to_script_pub_key()
    print(f"P2WPKH Script: {p2wpkh_script}")
    
    p2tr_script = unified_p2tr.to_script_pub_key()
    print(f"P2TR Script: {p2tr_script}")


if __name__ == "__main__":
    main()
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

import unittest

from bitcoinutils.setup import setup
from bitcoinutils.address import UnifiedAddress
from bitcoinutils.keys import PrivateKey, P2pkhAddress, P2shAddress, P2wpkhAddress, P2trAddress
from bitcoinutils.script import Script
from bitcoinutils.constants import (
    P2PKH_ADDRESS, P2SH_ADDRESS, P2WPKH_ADDRESS_V0, P2WSH_ADDRESS_V0, P2TR_ADDRESS_V1
)

class TestUnifiedAddress(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        setup('testnet')
        
        # Create keys for testing
        cls.private_key = PrivateKey.from_wif('cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo')
        cls.public_key = cls.private_key.get_public_key()
        
        # Create sample addresses for testing
        cls.p2pkh_address = cls.public_key.get_address()
        cls.p2wpkh_address = cls.public_key.get_segwit_address()
        cls.p2tr_address = cls.public_key.get_taproot_address()
        
        # Create a test script
        cls.script = Script(['OP_2', cls.public_key.to_hex(), cls.public_key.to_hex(), 'OP_2', 'OP_CHECKMULTISIG'])
        cls.p2sh_address = P2shAddress(script=cls.script)

    def test_create_from_string(self):
        # Test creation from P2PKH address
        p2pkh_address_str = self.p2pkh_address.to_string()
        unified_p2pkh = UnifiedAddress.from_address(p2pkh_address_str)
        self.assertEqual(unified_p2pkh.address_type, P2PKH_ADDRESS)
        self.assertEqual(unified_p2pkh.to_string(), p2pkh_address_str)
        
        # Test creation from P2SH address
        p2sh_address_str = self.p2sh_address.to_string()
        unified_p2sh = UnifiedAddress.from_address(p2sh_address_str)
        self.assertEqual(unified_p2sh.address_type, P2SH_ADDRESS)
        self.assertEqual(unified_p2sh.to_string(), p2sh_address_str)
        
        # Test creation from P2WPKH address
        p2wpkh_address_str = self.p2wpkh_address.to_string()
        unified_p2wpkh = UnifiedAddress.from_address(p2wpkh_address_str)
        self.assertEqual(unified_p2wpkh.address_type, P2WPKH_ADDRESS_V0)
        self.assertEqual(unified_p2wpkh.to_string(), p2wpkh_address_str)
        
        # Test creation from P2TR address
        p2tr_address_str = self.p2tr_address.to_string()
        unified_p2tr = UnifiedAddress.from_address(p2tr_address_str)
        self.assertEqual(unified_p2tr.address_type, P2TR_ADDRESS_V1)
        self.assertEqual(unified_p2tr.to_string(), p2tr_address_str)
        
    def test_create_from_script(self):
        # Test P2SH from script
        unified_p2sh = UnifiedAddress.from_script(self.script, P2SH_ADDRESS)
        self.assertEqual(unified_p2sh.address_type, P2SH_ADDRESS)
        self.assertEqual(unified_p2sh.to_string(), self.p2sh_address.to_string())
        
    def test_create_from_hash160(self):
        # Test P2PKH from hash160
        hash160 = self.p2pkh_address.to_hash160()
        unified_p2pkh = UnifiedAddress.from_hash160(hash160, P2PKH_ADDRESS)
        self.assertEqual(unified_p2pkh.address_type, P2PKH_ADDRESS)
        self.assertEqual(unified_p2pkh.to_string(), self.p2pkh_address.to_string())
        
    def test_create_from_witness_program(self):
        # Test P2WPKH from witness program
        witness_program = self.p2wpkh_address.to_witness_program()
        unified_p2wpkh = UnifiedAddress.from_witness_program(witness_program, P2WPKH_ADDRESS_V0)
        self.assertEqual(unified_p2wpkh.address_type, P2WPKH_ADDRESS_V0)
        self.assertEqual(unified_p2wpkh.to_string(), self.p2wpkh_address.to_string())
        
        # Test P2TR from witness program
        witness_program = self.p2tr_address.to_witness_program()
        unified_p2tr = UnifiedAddress.from_witness_program(witness_program, P2TR_ADDRESS_V1)
        self.assertEqual(unified_p2tr.address_type, P2TR_ADDRESS_V1)
        self.assertEqual(unified_p2tr.to_string(), self.p2tr_address.to_string())
        
    def test_to_script_pub_key(self):
        # Test P2PKH script pub key
        unified_p2pkh = UnifiedAddress(self.p2pkh_address)
        script_pub_key = unified_p2pkh.to_script_pub_key()
        self.assertEqual(script_pub_key.to_hex(), self.p2pkh_address.to_script_pub_key().to_hex())
        
    def test_address_type_conversion(self):
        # Test P2PKH to P2WPKH conversion
        unified_p2pkh = UnifiedAddress(self.p2pkh_address)
        unified_p2wpkh = unified_p2pkh.to_address_type(P2WPKH_ADDRESS_V0)
        self.assertEqual(unified_p2wpkh.address_type, P2WPKH_ADDRESS_V0)
        
        # The hash160 of both addresses should be the same
        p2pkh_hash160 = self.p2pkh_address.to_hash160()
        p2wpkh_wit_prog = unified_p2wpkh.address.to_witness_program()
        self.assertEqual(p2pkh_hash160, p2wpkh_wit_prog)
        
        # Test P2PKH to P2SH-P2WPKH conversion (nested SegWit)
        unified_p2sh_p2wpkh = unified_p2pkh.to_address_type(P2SH_ADDRESS)
        self.assertEqual(unified_p2sh_p2wpkh.address_type, P2SH_ADDRESS)
        
        # Test P2WPKH to P2PKH conversion
        unified_p2wpkh = UnifiedAddress(self.p2wpkh_address)
        unified_p2pkh_back = unified_p2wpkh.to_address_type(P2PKH_ADDRESS)
        self.assertEqual(unified_p2pkh_back.address_type, P2PKH_ADDRESS)
        self.assertEqual(unified_p2pkh_back.to_string(), unified_p2pkh.to_string())
        
    def test_invalid_conversions(self):
        # Test invalid conversion: P2PKH to P2TR
        unified_p2pkh = UnifiedAddress(self.p2pkh_address)
        with self.assertRaises(ValueError):
            unified_p2pkh.to_address_type(P2TR_ADDRESS_V1)
            
        # Test invalid conversion: P2TR to P2PKH
        unified_p2tr = UnifiedAddress(self.p2tr_address)
        with self.assertRaises(ValueError):
            unified_p2tr.to_address_type(P2PKH_ADDRESS)
            
    def test_equality(self):
        # Test equality between UnifiedAddress objects
        unified_p2pkh1 = UnifiedAddress(self.p2pkh_address)
        unified_p2pkh2 = UnifiedAddress.from_address(self.p2pkh_address.to_string())
        self.assertEqual(unified_p2pkh1, unified_p2pkh2)
        
        # Test equality with string
        self.assertEqual(unified_p2pkh1, self.p2pkh_address.to_string())
        
        # Test inequality
        unified_p2wpkh = UnifiedAddress(self.p2wpkh_address)
        self.assertNotEqual(unified_p2pkh1, unified_p2wpkh)
        
if __name__ == '__main__':
    unittest.main()
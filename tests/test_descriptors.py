# Copyright (C) 2018-2026 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import unittest

from bitcoinutils.descriptors import (
    Descriptor,
    DescriptorError,
    add_descriptor_checksum,
    descriptor_checksum,
    parse_descriptor,
)
from bitcoinutils.keys import P2pkhAddress, P2shAddress, P2wpkhAddress, P2wshAddress
from bitcoinutils.script import Script
from bitcoinutils.setup import setup


PUB1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
PUB2 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
PUB3 = "03f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
XONLY_PUB1 = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
UNCOMPRESSED_PUB1 = (
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)


class TestDescriptors(unittest.TestCase):
    def setUp(self):
        setup("testnet")

    def tearDown(self):
        setup("testnet")

    def test_checksum_matches_bitcoin_core_example(self):
        desc = "addr(mkmZxiEcEd8ZqjQWVZuC6so5dFMKEFpN2j)"
        self.assertEqual(descriptor_checksum(desc), "02wpgw69")
        self.assertEqual(add_descriptor_checksum(desc), f"{desc}#02wpgw69")
        parsed = parse_descriptor(f"{desc}#02wpgw69", require_checksum=True)
        self.assertTrue(parsed.validate_checksum())

    def test_invalid_checksum_rejected(self):
        with self.assertRaises(DescriptorError):
            parse_descriptor(f"pkh({PUB1})#02wpgw69", require_checksum=True)

    def test_pkh_descriptor(self):
        desc = Descriptor.from_string(f"pkh({PUB1})")
        expected = P2pkhAddress.from_hash160(
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        )
        self.assertEqual(desc.to_string(), f"pkh({PUB1})")
        self.assertEqual(desc.to_address().to_string(), expected.to_string())
        self.assertEqual(desc.to_script_pub_key(), expected.to_script_pub_key())

    def test_pkh_allows_uncompressed_key(self):
        desc = parse_descriptor(f"pkh({UNCOMPRESSED_PUB1})")
        expected = P2pkhAddress.from_hash160(
            "91b24bf9f5288532960ac687abb035127b1d28a5"
        )
        self.assertEqual(desc.to_address().to_string(), expected.to_string())

    def test_wpkh_descriptor(self):
        desc = parse_descriptor(f"wpkh({PUB1})")
        expected = P2wpkhAddress.from_witness_program(
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        )
        self.assertEqual(desc.to_address().to_string(), expected.to_string())
        self.assertEqual(desc.to_script_pub_key(), expected.to_script_pub_key())

    def test_sh_wpkh_descriptor(self):
        desc = parse_descriptor(f"sh(wpkh({PUB1}))")
        redeem_script = P2wpkhAddress.from_witness_program(
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        ).to_script_pub_key()
        expected = P2shAddress(script=redeem_script)
        self.assertEqual(desc.to_address().to_string(), expected.to_string())
        self.assertEqual(desc.to_script_pub_key(), expected.to_script_pub_key())

    def test_pk_descriptor_script(self):
        desc = parse_descriptor(f"pk({PUB1})")
        self.assertEqual(desc.to_script_pub_key(), Script([PUB1, "OP_CHECKSIG"]))
        with self.assertRaises(DescriptorError):
            desc.to_address()

    def test_multisig_descriptor_preserves_key_order(self):
        desc = parse_descriptor(f"multi(2,{PUB2},{PUB1},{PUB3})")
        self.assertEqual(
            desc.to_script_pub_key(),
            Script(["OP_2", PUB2, PUB1, PUB3, "OP_3", "OP_CHECKMULTISIG"]),
        )

    def test_sortedmulti_descriptor_sorts_keys(self):
        desc = parse_descriptor(f"sortedmulti(2,{PUB2},{PUB1},{PUB3})")
        self.assertEqual(
            desc.to_script_pub_key(),
            Script(["OP_2", PUB1, PUB2, PUB3, "OP_3", "OP_CHECKMULTISIG"]),
        )

    def test_wsh_and_sh_wsh_multisig_descriptors(self):
        inner = Script(["OP_2", PUB1, PUB2, PUB3, "OP_3", "OP_CHECKMULTISIG"])
        wsh = parse_descriptor(f"wsh(multi(2,{PUB1},{PUB2},{PUB3}))")
        self.assertEqual(wsh.to_script_pub_key(), inner.to_p2wsh_script_pub_key())
        self.assertEqual(wsh.to_address().to_string(), P2wshAddress(script=inner).to_string())

        sh_wsh = parse_descriptor(f"sh(wsh(multi(2,{PUB1},{PUB2},{PUB3})))")
        expected = P2shAddress(script=inner.to_p2wsh_script_pub_key())
        self.assertEqual(sh_wsh.to_address().to_string(), expected.to_string())

    def test_tr_descriptor(self):
        desc = parse_descriptor(f"tr({PUB1})")
        self.assertEqual(desc.to_script_pub_key().get_script()[0], "OP_1")
        self.assertEqual(desc.to_address().to_script_pub_key(), desc.to_script_pub_key())

    def test_tr_descriptor_accepts_xonly_key(self):
        desc = parse_descriptor(f"tr({XONLY_PUB1})")
        self.assertEqual(desc.to_string(), f"tr({XONLY_PUB1})")
        self.assertEqual(desc.to_script_pub_key().get_script()[0], "OP_1")

    def test_addr_descriptor(self):
        address = P2wpkhAddress.from_witness_program(
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        ).to_string()
        desc = parse_descriptor(f"addr({address})")
        self.assertEqual(desc.to_address().to_string(), address)
        self.assertEqual(
            desc.to_script_pub_key(),
            P2wpkhAddress.from_witness_program(
                "751e76e8199196d454941c45d1b3a323f1433bd6"
            ).to_script_pub_key(),
        )

    def test_addr_descriptor_supports_p2wsh_and_p2tr(self):
        wsh_address = parse_descriptor(
            f"wsh(multi(2,{PUB1},{PUB2},{PUB3}))"
        ).to_address().to_string()
        wsh_desc = parse_descriptor(f"addr({wsh_address})")
        self.assertEqual(wsh_desc.to_address().to_string(), wsh_address)
        self.assertEqual(wsh_desc.to_script_pub_key().get_script()[0], "OP_0")

        tr_address = parse_descriptor(f"tr({PUB1})").to_address().to_string()
        tr_desc = parse_descriptor(f"addr({tr_address})")
        self.assertEqual(tr_desc.to_address().to_string(), tr_address)
        self.assertEqual(tr_desc.to_script_pub_key().get_script()[0], "OP_1")

    def test_raw_descriptor(self):
        raw = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
        desc = parse_descriptor(f"raw({raw})")
        self.assertEqual(desc.to_script_pub_key(), Script.from_raw(raw))
        with self.assertRaises(DescriptorError):
            desc.to_address()

    def test_invalid_nesting_rejected(self):
        invalid = [
            f"wsh(wpkh({PUB1}))",
            f"wsh(pkh({PUB1}))",
            f"sh(pkh({PUB1}))",
            f"sh(sh(pkh({PUB1})))",
            f"wpkh({UNCOMPRESSED_PUB1})",
            f"sh(tr({PUB1}))",
        ]
        for desc in invalid:
            with self.subTest(desc=desc):
                with self.assertRaises(DescriptorError):
                    parse_descriptor(desc)

    def test_unsupported_syntax_rejected_clearly(self):
        unsupported = [
            "combo(" + PUB1 + ")",
            "wpkh([d34db33f/84h/1h/0h]" + PUB1 + "/0/*)",
            "wpkh(xpub661MyMwAqRbcF9F4U4XJf3r92p1)",
            "tr(" + PUB1 + ",pk(" + PUB2 + "))",
            "wsh(and_v(v:pk(" + PUB1 + "),older(10)))",
        ]
        for desc in unsupported:
            with self.subTest(desc=desc):
                with self.assertRaises((DescriptorError, NotImplementedError)):
                    parse_descriptor(desc)


if __name__ == "__main__":
    unittest.main()

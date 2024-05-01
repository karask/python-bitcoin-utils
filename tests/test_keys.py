# Copyright (C) 2018-2024 The python-bitcoin-utils developers
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

from bitcoinutils.setup import setup
from bitcoinutils.keys import (
    PrivateKey,
    PublicKey,
    P2pkhAddress,
    P2shAddress,
    P2wpkhAddress,
    P2wshAddress,
)
from bitcoinutils.script import Script
from bitcoinutils.hdwallet import HDWallet


class TestPrivateKeys(unittest.TestCase):
    def setUp(self):
        setup("mainnet")
        self.key_wifc = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        self.key_wif = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"
        self.key_bytes = (
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
        )
        self.public_key_bytes = (
            b"y\xbef~\xf9\xdc\xbb\xacU\xa0b\x95\xce\x87\x0b\x07\x02\x9b\xfc\xdb-\xce("
            b"\xd9Y\xf2\x81[\x16\xf8\x17\x98H:\xdaw&\xa3\xc4e]\xa4\xfb\xfc\x0e\x11"
            b"\x08\xa8\xfd\x17\xb4H\xa6\x85T\x19\x9cG\xd0\x8f\xfb\x10\xd4\xb8"
        )

    def test_wif_creation(self):
        p = PrivateKey(self.key_wifc)
        self.assertEqual(p.to_bytes(), self.key_bytes)
        self.assertEqual(p.to_wif(compressed=False), self.key_wif)

    def test_exponent_creation(self):
        p = PrivateKey(secret_exponent=1)
        self.assertEqual(p.to_bytes(), self.key_bytes)
        self.assertEqual(p.to_wif(compressed=False), self.key_wif)
        self.assertEqual(p.to_wif(), self.key_wifc)

    def test_public_key(self):
        p = PrivateKey(secret_exponent=1)
        self.assertEqual(p.get_public_key().to_bytes(), self.public_key_bytes)


class TestPublicKeys(unittest.TestCase):
    def setUp(self):
        setup("mainnet")
        self.public_key_hexc = (
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
        self.public_key_hex = (
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        )
        self.public_key_bytes = (
            b"y\xbef~\xf9\xdc\xbb\xacU\xa0b\x95\xce\x87\x0b\x07\x02\x9b\xfc\xdb-\xce("
            b"\xd9Y\xf2\x81[\x16\xf8\x17\x98H:\xdaw&\xa3\xc4e]\xa4\xfb\xfc\x0e\x11"
            b"\x08\xa8\xfd\x17\xb4H\xa6\x85T\x19\x9cG\xd0\x8f\xfb\x10\xd4\xb8"
        )
        self.address = "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"

    def test_pubkey_creation(self):
        pub1 = PublicKey(self.public_key_hex)
        self.assertEqual(pub1.to_bytes(), self.public_key_bytes)
        pub2 = PublicKey(self.public_key_hexc)
        self.assertEqual(pub2.to_bytes(), self.public_key_bytes)

    def test_pubkey_uncompressed(self):
        pub = PublicKey(self.public_key_hex)
        self.assertEqual(pub.to_hex(compressed=False), self.public_key_hex)

    def test_pubkey_uncompressed_from_hex(self):
        pub = PublicKey.from_hex(self.public_key_hex)
        self.assertEqual(pub.to_hex(compressed=False), self.public_key_hex)

    def test_get_uncompressed_address(self):
        pub = PublicKey(self.public_key_hex)
        self.assertEqual(pub.get_address(compressed=False).to_string(), self.address)

    def test_pubkey_to_hash160(self):
        pub = PublicKey(self.public_key_hex)
        self.assertEqual(pub.get_address().to_hash160(), pub.to_hash160())

    def test_pubkey_x_only(self):
        pub = PublicKey(self.public_key_hex)
        self.assertEqual(pub.to_x_only_hex(), self.public_key_hex[2:66])


class TestP2pkhAddresses(unittest.TestCase):
    def setUp(self):
        setup("mainnet")
        self.hash160 = "91b24bf9f5288532960ac687abb035127b1d28a5"
        self.hash160c = "751e76e8199196d454941c45d1b3a323f1433bd6"
        self.address = "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"
        self.addressc = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"

    def test_creation_hash(self):
        a1 = P2pkhAddress.from_hash160(self.hash160)
        self.assertEqual(a1.to_string(), self.address)
        a2 = P2pkhAddress.from_hash160(self.hash160c)
        self.assertEqual(a2.to_string(), self.addressc)

    def test_creation_address(self):
        a1 = P2pkhAddress.from_address(self.address)
        self.assertEqual(a1.to_hash160(), self.hash160)
        a2 = P2pkhAddress.from_address(self.addressc)
        self.assertEqual(a2.to_hash160(), self.hash160c)


class TestSignAndVerify(unittest.TestCase):
    def setUp(self):
        setup("mainnet")
        self.message = "The test!"
        self.key_wifc = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        self.priv = PrivateKey.from_wif(self.key_wifc)
        self.pub = self.priv.get_public_key()
        self.address = self.pub.get_address().to_string()
        self.external_address = "1LbxJuEHPsoFRVo3qM1YJRg7DfRD1RvUDe"
        self.deterministic_signature = (
            "IEiQ7kHfGqlxHSOcUftzR4gChjupJbuIIJCiY3Lr"
            "yQ9SXwPeRoBtJYkrNd/rgU7RP9jX6i2IaGGYMLt9bW+/bbI="
        )
        self.external_signature = (
            "H+yEsMrKoLqcdegOxYbZ4MFpQkRJligl1whXQDY2+g7"
            "EptxmOj9vC3n5ykdHkof0qEbmyV62syaKh+9C95V5R34="
        )

    def test_sign_and_verify(self):
        signature = self.priv.sign_message(self.message)
        assert signature is not None
        self.assertEqual(signature, self.deterministic_signature)
        self.assertTrue(PublicKey.verify_message(self.address, signature, self.message))

    def test_verify_external(self):
        self.assertTrue(
            PublicKey.verify_message(
                self.external_address, self.external_signature, self.message
            )
        )


class TestP2shAddresses(unittest.TestCase):
    def setUp(self):
        setup("testnet")
        self.priv = PrivateKey.from_wif(
            "cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo"
        )
        self.pub = self.priv.get_public_key()
        self.p2sh_address = "2NDkr9uD2MSY5em3rsjkff8fLZcJzCfY3W1"

    def test_p2sh_creation(self):
        script = Script([self.pub.to_hex(), "OP_CHECKSIG"])
        addr = P2shAddress.from_script(script)
        self.assertTrue(addr.to_string(), self.p2sh_address)

    def test_p2shaddress_to_script_pub_key(self):
        script = Script([self.pub.to_hex(), "OP_CHECKSIG"])
        fromScript = Script.to_p2sh_script_pub_key(script).to_hex()
        addr = P2shAddress.from_script(script)
        fromP2shAddress = addr.to_script_pub_key().to_hex()
        self.assertTrue(fromScript, fromP2shAddress)


class TestP2WPKHAddresses(unittest.TestCase):
    def setUp(self):
        setup("testnet")
        self.priv = PrivateKey.from_wif(
            "cVdte9ei2xsVjmZSPtyucG43YZgNkmKTqhwiUA8M4Fc3LdPJxPmZ"
        )
        self.pub = self.priv.get_public_key()
        self.correct_p2wpkh_address = "tb1qxmt9xgewg6mxc4mvnzvrzu4f2v0gy782fydg0w"
        self.correct_p2sh_p2wpkh_address = "2N8Z5t3GyPW1hSAEJZqQ1GUkZ9ofoGhgKPf"
        self.correct_p2wsh_address = (
            "tb1qy4kdfavhluvnhpwcqmqrd8x0ge2ynnsl7mv2mdmdskx4g3fc6ckq8f44jg"
        )
        self.correct_p2sh_p2wsh_address = (
            "tb1qy4kdfavhluvnhpwcqmqrd8x0ge2ynnsl7mv2mdmdskx4g3fc6ckq8f44jg"
        )

    def test_p2wpkh_creation_pubkey(self):
        addr = P2wpkhAddress.from_witness_program(
            self.pub.get_segwit_address().to_witness_program()
        )
        self.assertTrue(self.correct_p2wpkh_address, addr.to_string())

    def test_p2sh_p2wpkh_creation_pubkey(self):
        addr = (
            PrivateKey.from_wif("cTmyBsxMQ3vyh4J3jCKYn2Au7AhTKvqeYuxxkinsg6Rz3BBPrYKK")
            .get_public_key()
            .get_segwit_address()
        )
        p2sh_addr = P2shAddress.from_script(addr.to_script_pub_key())
        self.assertTrue(p2sh_addr.to_string(), self.correct_p2sh_p2wpkh_address)

    def test_p2wsh_creation_1multisig(self):
        p2wpkh_key = PrivateKey.from_wif(
            "cNn8itYxAng4xR4eMtrPsrPpDpTdVNuw7Jb6kfhFYZ8DLSZBCg37"
        )
        script = Script(
            ["OP_1", p2wpkh_key.get_public_key().to_hex(), "OP_1", "OP_CHECKMULTISIG"]
        )
        p2wsh_addr = P2wshAddress.from_script(script)
        self.assertTrue(p2wsh_addr.to_string(), self.correct_p2wsh_address)

    def test_p2sh_p2wsh_creation_1multisig(self):
        p2wpkh_key = PrivateKey.from_wif(
            "cNn8itYxAng4xR4eMtrPsrPpDpTdVNuw7Jb6kfhFYZ8DLSZBCg37"
        )
        script = Script(
            ["OP_1", p2wpkh_key.get_public_key().to_hex(), "OP_1", "OP_CHECKMULTISIG"]
        )
        p2wsh_addr = P2wshAddress.from_script(script)
        p2sh_p2wsh_addr = P2shAddress.from_script(p2wsh_addr.to_script_pub_key())
        self.assertTrue(p2sh_p2wsh_addr.to_string(), self.correct_p2sh_p2wsh_address)


class TestP2trAddresses(unittest.TestCase):
    def setUp(self):
        setup("testnet")
        self.priv_even = PrivateKey.from_wif(
            "cTLeemg1bCXXuRctid7PygEn7Svxj4zehjTcoayrbEYPsHQo248w"
        )
        self.correct_even_pk = (
            "0271fe85f75e97d22e74c2dd6425e843def8b662b928f24f724ae6a2fd0c4e0419"
        )
        self.correct_even_tr_addr = (
            "tb1pk426x6qvmncj5vzhtp5f2pzhdu4qxsshszswga8ea6sycj9nulmsu7syz0"
        )
        self.correct_even_tweaked_pk = (
            "b555a3680cdcf12a305758689504576f2a03421780a0e474f9eea04c48b3e7f7"
        )

        self.priv_odd = PrivateKey.from_wif(
            "cRPxBiKrJsH94FLugmiL4xnezMyoFqGcf4kdgNXGuypNERhMK6AT"
        )
        self.correct_odd_pk = (
            "03a957ff7ead882e4c95be2afa684ab0e84447149883aba60c067adc054472785b"
        )
        self.correct_odd_tr_addr = (
            "tb1pdr8q4tuqqeglxxhkxl3trxt0dy5jrnaqvg0ddwu7plraxvntp8dqv8kvyq"
        )
        self.correct_odd_tweaked_pk = (
            "68ce0aaf800651f31af637e2b1996f692921cfa0621ed6bb9e0fc7d3326b09da"
        )

    def test_even_taproot_pubkey(self):
        pubkey = self.priv_even.get_public_key()
        self.assertTrue(pubkey.to_hex(), self.correct_even_pk)

    def test_even_taproot_address(self):
        pubkey = self.priv_even.get_public_key()
        addr = pubkey.get_taproot_address()
        self.assertTrue(addr, self.correct_even_tr_addr)

    def test_even_taproot_pk_witness(self):
        pubkey = self.priv_even.get_public_key()
        addr = pubkey.get_taproot_address()
        self.assertTrue(addr.to_witness_program(), self.correct_even_tweaked_pk)

    def test_odd_taproot_pubkey(self):
        pubkey = self.priv_odd.get_public_key()
        self.assertTrue(pubkey.to_hex(), self.correct_odd_pk)

    def test_odd_taproot_address(self):
        pubkey = self.priv_odd.get_public_key()
        addr = pubkey.get_taproot_address()
        self.assertTrue(addr, self.correct_odd_tr_addr)

    def test_odd_taproot_pk_witness(self):
        pubkey = self.priv_odd.get_public_key()
        addr = pubkey.get_taproot_address()
        self.assertTrue(addr.to_witness_program(), self.correct_odd_tweaked_pk)


class TestHDWallet(unittest.TestCase):
    def setUp(self):
        setup("testnet")
        self.mnemonic = (
            "addict weather world sense idle purity rich wagon "
            "ankle fall cheese spatial"
        )
        self.xprivkey = (
            "tprv8ZgxMBicQKsPez3VhGkU7wmGPqihEoCVeSmytmPTnZcpP"
            "4kmZXr7oFy9aVUGkXQynGuJMWWDXs5MwhHHpbj8pEBThBdt1bGGmZQKrDS8Xxg"
        )
        self.privkey_m_44h_1h_0h_0_1 = (
            "cPSitUzA63SJL7oAbN1oNDrUbmmqzc23bAL2QuF4cSBc3FXCg1Ax"
        )
        self.legacy_address_m_44_1h_0h_0_3 = "mz63brMnFrXP4ZF9V75d9VrkKPM5gUyS9H"

    def test_legacy_address_from_xprivkey(self):
        hdw = HDWallet(xprivate_key=self.xprivkey, path="m/44'/1'/0'/0/1")
        self.assertTrue(hdw.get_private_key(), self.privkey_m_44h_1h_0h_0_1)

    def test_legacy_address_from_mnemonic(self):
        hdw = HDWallet(mnemonic=self.mnemonic)
        hdw.from_path("m/44'/1'/0'/0/3")
        address = hdw.get_private_key().get_public_key().get_address()
        self.assertTrue(address.to_string(), self.legacy_address_m_44_1h_0h_0_3)


if __name__ == "__main__":
    unittest.main()

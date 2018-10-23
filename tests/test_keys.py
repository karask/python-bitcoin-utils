import unittest

from context import bitcoinutils
from bitcoinutils.setup import setup, get_network
from bitcoinutils.keys import PrivateKey, PublicKey, Address

class TestPrivateKeys(unittest.TestCase):
    def setUp(self):
        setup('mainnet')
        self.key_wifc = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        self.key_wif = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"
        self.key_bytes = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
        self.public_key_bytes = b'y\xbef~\xf9\xdc\xbb\xacU\xa0b\x95\xce\x87\x0b\x07\x02\x9b\xfc\xdb-\xce(\xd9Y\xf2\x81[\x16\xf8\x17\x98H:\xdaw&\xa3\xc4e]\xa4\xfb\xfc\x0e\x11\x08\xa8\xfd\x17\xb4H\xa6\x85T\x19\x9cG\xd0\x8f\xfb\x10\xd4\xb8'

    def test_wif_creation(self):
        p = PrivateKey(self.key_wifc)
        self.assertEqual(p.to_bytes(), self.key_bytes)
        self.assertEqual(p.to_wif(compressed = False), self.key_wif)

    def test_exponent_creation(self):
        p = PrivateKey(secret_exponent=1)
        self.assertEqual(p.to_bytes(), self.key_bytes)
        self.assertEqual(p.to_wif(compressed = False), self.key_wif)
        self.assertEqual(p.to_wif(), self.key_wifc)

    def test_public_key(self):
        p = PrivateKey(secret_exponent = 1)
        self.assertEqual(p.get_public_key().to_bytes(), self.public_key_bytes)


class TestPublicKeys(unittest.TestCase):
    def setUp(self):
        setup('mainnet')
        self.public_key_hexc = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
        self.public_key_hex = '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
        self.public_key_bytes = b'y\xbef~\xf9\xdc\xbb\xacU\xa0b\x95\xce\x87\x0b\x07\x02\x9b\xfc\xdb-\xce(\xd9Y\xf2\x81[\x16\xf8\x17\x98H:\xdaw&\xa3\xc4e]\xa4\xfb\xfc\x0e\x11\x08\xa8\xfd\x17\xb4H\xa6\x85T\x19\x9cG\xd0\x8f\xfb\x10\xd4\xb8'
        self.address = '1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm'

    def test_pubkey_creation(self):
        pub1 = PublicKey(self.public_key_hex)
        self.assertEqual(pub1.to_bytes(), self.public_key_bytes)
        pub2 = PublicKey(self.public_key_hexc)
        self.assertEqual(pub2.to_bytes(), self.public_key_bytes)

    def test_pubkey_uncompressed(self):
        pub = PublicKey(self.public_key_hexc)
        self.assertEqual(pub.to_hex(compressed = False), self.public_key_hex)

    def test_get_uncompressed_address(self):
        pub = PublicKey(self.public_key_hex)
        self.assertEqual(pub.get_address(compressed=False).to_address(), self.address)


class TestAddresses(unittest.TestCase):
    def setUp(self):
        setup('mainnet')
        self.hash160 = '91b24bf9f5288532960ac687abb035127b1d28a5'
        self.hash160c = '751e76e8199196d454941c45d1b3a323f1433bd6'
        self.address = '1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm'
        self.addressc = '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'

    def test_creation_hash(self):
        a1 = Address.from_hash160(self.hash160)
        self.assertEqual(a1.to_address(), self.address)
        a2 = Address.from_hash160(self.hash160c)
        self.assertEqual(a2.to_address(), self.addressc)

    def test_creation_address(self):
        a1 = Address.from_address(self.address)
        self.assertEqual(a1.to_hash160(), self.hash160)
        a2 = Address.from_address(self.addressc)
        self.assertEqual(a2.to_hash160(), self.hash160c)


class TestSignAndVerify(unittest.TestCase):
    def setUp(self):
        setup('mainnet')
        self.message = "The test!"
        self.key_wifc = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        self.priv = PrivateKey.from_wif(self.key_wifc)
        self.pub = self.priv.get_public_key()
        self.address = self.pub.get_address().to_address()
        self.external_address = '1LbxJuEHPsoFRVo3qM1YJRg7DfRD1RvUDe'
        self.external_signature = 'H+yEsMrKoLqcdegOxYbZ4MFpQkRJligl1whXQDY2+g7EptxmOj9vC3n5ykdHkof0qEbmyV62syaKh+9C95V5R34='

    def test_sign_and_verify(self):
        signature = self.priv.sign_message(self.message)
        self.assertTrue(PublicKey.verify_message(self.address, signature, self.message))

    def test_verify_external(self):
        self.assertTrue(PublicKey.verify_message(self.external_address,
                                                 self.external_signature,
                                                 self.message))

if __name__ == '__main__':
    unittest.main()



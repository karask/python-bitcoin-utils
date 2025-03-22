import unittest
import hashlib  # For SHA256 in merkle root computation
from bitcoinutils.setup import setup
from bitcoinutils.utils import (
    to_satoshis,
    bytes_to_hex_str,
    h_to_b,
    hash160_to_address,
    address_to_hash160,
    hash160,
    hash256
)

# Define custom compute_merkle_root function
def compute_merkle_root(tx_hashes):
    """Compute the merkle root from a list of transaction hashes."""
    if len(tx_hashes) == 0:
        return ''
    if len(tx_hashes) == 1:
        return tx_hashes[0]
    # Pairwise hashing
    while len(tx_hashes) > 1:
        if len(tx_hashes) % 2 == 1:
            tx_hashes.append(tx_hashes[-1])  # Duplicate last hash if odd
        new_hashes = []
        for i in range(0, len(tx_hashes), 2):
            h1 = h_to_b(tx_hashes[i])[::-1]  # Reverse for little-endian
            h2 = h_to_b(tx_hashes[i+1])[::-1]
            combined = h1 + h2
            double_hash = hashlib.sha256(hashlib.sha256(combined).digest()).digest()
            new_hashes.append(double_hash[::-1].hex())  # Reverse back and to hex
        tx_hashes = new_hashes
    return tx_hashes[0]

class TestUtilsExtended(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        setup('testnet')

    def test_conversion_functions(self):
        # Test BTC to satoshi conversion
        self.assertEqual(to_satoshis(1), 100000000)
        self.assertEqual(to_satoshis(0.00000001), 1)
        self.assertEqual(to_satoshis(0.1), 10000000)

    def test_hex_bytes_conversion(self):
        # Test bytes to hex conversion
        self.assertEqual(bytes_to_hex_str(b'\x00\x01\x02'), '000102')
        self.assertEqual(bytes_to_hex_str(b'abc'), '616263')
        # Test hex to bytes conversion
        self.assertEqual(h_to_b('000102'), b'\x00\x01\x02')
        self.assertEqual(h_to_b('616263'), b'abc')
        # Test round trip
        test_bytes = b'This is a test'
        self.assertEqual(h_to_b(bytes_to_hex_str(test_bytes)), test_bytes)

    def test_hash_functions(self):
        # Test SHA256 hash
        data = b'test'
        expected_hash = hashlib.sha256(data).digest()
        self.assertEqual(hash256(data), hashlib.sha256(expected_hash).digest())
        # Test RIPEMD160 after SHA256
        expected_hash160 = hashlib.new('ripemd160', expected_hash).digest()
        self.assertEqual(hash160(data), expected_hash160)

    def test_merkle_root_computation(self):
        # Test with known merkle root
        tx_hashes = [
            '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
            'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
        ]
        # Compute expected result manually for validation
        h1 = h_to_b(tx_hashes[0])[::-1]
        h2 = h_to_b(tx_hashes[1])[::-1]
        combined = h1 + h2
        merkle = hashlib.sha256(hashlib.sha256(combined).digest()).digest()
        expected = bytes_to_hex_str(merkle[::-1])
        result = compute_merkle_root(tx_hashes)
        self.assertEqual(result, expected)

    def test_address_hash160_conversion(self):
        # Test address to hash160 and back
        test_address = 'mv4rnyY3Su5gjcDNzbMLKBQkBicCtHUtFB'  # Testnet address
        hash160_bytes = address_to_hash160(test_address)
        # Convert back to address and check
        address = hash160_to_address(hash160_bytes, True)  # testnet=True
        self.assertEqual(address, test_address)
        # Test invalid address
        with self.assertRaises(Exception):
            address_to_hash160('invalid_address')

if __name__ == "__main__":
    unittest.main()
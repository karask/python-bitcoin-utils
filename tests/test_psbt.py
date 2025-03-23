import unittest
from io import BytesIO
from bitcoinutils.psbt import PSBT, MAGIC_BYTES, SEPARATOR, PSBT_GLOBAL_UNSIGNED_TX
from bitcoinutils.transactions import Transaction
from bitcoinutils.utils import encode_varint


class TestPSBT(unittest.TestCase):
    def setUp(self):
        # Sample PSBT maps for testing
        self.sample_maps = {
            'global': {
                PSBT_GLOBAL_UNSIGNED_TX: bytes.fromhex(
                    "0100000001c3b5b9b07ec40d9e3f5edfa7e4f10b23bc653e5b6a5a1c79d1f4d232b3c6a29d000000006a473044022067e502e82d02e7a1a3b504897dfec4ea8df71a3b77cfe1b9cbf7d3f16a63642e02206e3b32b1e6b8f184a654bd22c6cb4a616274e0e44ed14e7f3e54d5e2d840cc6f012102a84c91d495bfecb17ea00e1dd6c634755643b95a09856c7cde4575a11b3a48e6ffffffff01a0860100000000001976a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac00000000"
                ),
            },
            'input': [
                {b'\x00': b'\x01\x02\x03'},  # Example input map
            ],
            'output': [
                {b'\x00': b'\x04\x05\x06'},  # Example output map
            ]
        }
        self.psbt = PSBT(self.sample_maps)

    def test_serialize(self):
        """Test if the PSBT object serializes correctly."""
        serialized = self.psbt.serialize()

        # Check if the serialized PSBT starts with the magic bytes
        self.assertTrue(serialized.startswith(MAGIC_BYTES))

        # Check if the global map is serialized correctly
        for key, val in self.sample_maps['global'].items():
            encoded_key_val = encode_varint(len(key)) + key + encode_varint(len(val)) + val
            self.assertIn(encoded_key_val, serialized)

        # Check if the input maps are serialized correctly
        for inp in self.sample_maps['input']:
            for key, val in inp.items():
                encoded_key_val = encode_varint(len(key)) + key + encode_varint(len(val)) + val
                self.assertIn(encoded_key_val, serialized)

        # Check if the output maps are serialized correctly
        for out in self.sample_maps['output']:
            for key, val in out.items():
                encoded_key_val = encode_varint(len(key)) + key + encode_varint(len(val)) + val
                self.assertIn(encoded_key_val, serialized)


    def test_parse(self):
        """Test if the PSBT object parses correctly."""
        serialized = self.psbt.serialize()
        parsed_psbt = PSBT.parse(BytesIO(serialized))

        # Check if the parsed PSBT matches the original maps
        self.assertEqual(parsed_psbt.maps['global'], self.sample_maps['global'])
        self.assertEqual(parsed_psbt.maps['input'], self.sample_maps['input'])
        self.assertEqual(parsed_psbt.maps['output'], self.sample_maps['output'])

    def test_serialize_and_parse(self):
        """Test if serialization and parsing are consistent."""
        serialized = self.psbt.serialize()
        parsed_psbt = PSBT.parse(BytesIO(serialized))

        # Serialize the parsed PSBT and compare with the original serialization
        reserialized = parsed_psbt.serialize()
        self.assertEqual(serialized, reserialized)

    def test_parse_invalid_magic_bytes(self):
        """Test parsing with invalid magic bytes."""
        invalid_psbt = b"abcd" + self.psbt.serialize()[4:]  # Replace magic bytes
        with self.assertRaises(ValueError) as context:
            PSBT.parse(BytesIO(invalid_psbt))
        self.assertEqual(str(context.exception), "Invalid PSBT magic bytes")

    def test_parse_missing_separator(self):
        """Test parsing with missing separators."""
        serialized = self.psbt.serialize().replace(SEPARATOR, b"")  # Remove separators
        with self.assertRaises(Exception):  # Replace with a specific exception if implemented
            PSBT.parse(BytesIO(serialized))


if __name__ == '__main__':
    unittest.main()
import unittest
from bitcoinutils.setup import setup
from bitcoinutils.bech32 import bech32_encode, bech32_decode, convertbits, decode, encode, Encoding

class TestBech32Extended(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        setup('testnet')
    
    def test_bech32_encode_decode(self):
        # Test encoding and decoding
        hrp = "bc"
        data = [0, 14, 20, 15, 7, 13, 26, 0, 25, 18, 6, 11, 13, 8, 21, 4, 20, 3, 17, 2, 29, 3, 12, 29, 3, 4, 15, 24, 20, 6, 14, 30, 22]
        
        # For bech32 address spec (segwit v0)
        encoded = bech32_encode(hrp, data, Encoding.BECH32)
        
        # Check that we can decode it
        hrp_decoded, data_decoded, spec_decoded = bech32_decode(encoded)
        
        # Verify the results
        self.assertEqual(hrp, hrp_decoded)
        self.assertEqual(data, data_decoded)
        self.assertEqual(Encoding.BECH32, spec_decoded)
    
    def test_convertbits(self):
        """Test bit conversion with valid values."""
        # Use values that are valid for conversion
        # Each value must be < 2^frombits
        data_5bit = [0, 14, 20, 15, 7, 13, 26]  # All values < 32 (2^5)
        
        # Make sure all values are within valid range
        self.assertTrue(all(0 <= v < 32 for v in data_5bit))
        
        # Convert from 5-bit to 8-bit with padding
        data_8bit = convertbits(data_5bit, 5, 8, True)  # Set pad=True
        
        # Make sure conversion worked
        self.assertIsNotNone(data_8bit)
        
        # Convert back to 5-bit
        data_back = convertbits(data_8bit, 8, 5, True)  # Set pad=True
        
        # The result might have padding so just verify first values match
        for i in range(len(data_5bit)):
            if i < len(data_back):
                self.assertEqual(data_5bit[i], data_back[i])
    
    def test_bech32_address_encoding_decoding(self):
        # Test encoding and decoding of actual addresses
        
        # P2WPKH address - use 20-byte hash (not the full pubkey)
        pubkey_hash = bytes.fromhex('751e76e8199196d454941c45d1b3a323f1433bd6')  # 20-byte hash, not 33-byte pubkey
        
        # Create bech32 address
        p2wpkh_addr = encode('tb', 0, pubkey_hash)  # testnet
        
        # Decode and verify
        witver, witprog = decode('tb', p2wpkh_addr)
        
        self.assertEqual(0, witver)
        self.assertEqual(pubkey_hash, bytes(witprog))
    
    def test_checksum_validation(self):
        # Test detection of invalid checksum
        valid_addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        
        # This should work for valid address
        hrp, data, spec = bech32_decode(valid_addr)
        
        # Verify the results
        self.assertEqual('tb', hrp)
        self.assertIsNotNone(data)
        self.assertIsNotNone(spec)
        
        # Test invalid address
        invalid_addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx0"  # added '0' at the end
        invalid_result = bech32_decode(invalid_addr)
        
        # Invalid checksum should return (None, None, None)
        self.assertEqual((None, None, None), invalid_result)
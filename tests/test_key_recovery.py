import unittest
from bitcoinutils.setup import setup
from bitcoinutils.keys import PublicKey

class TestPublicKeyRecovery:
    """Test cases for public key recovery from message and signature"""

    def setup_method(self):
        """Setup test data before each test"""
        # Initialize the library
        setup('testnet')
        
        # Message public key recovery test data
        self.valid_message = "Hello, Bitcoin!"
        # 65-byte Bitcoin signature (1-byte recovery ID + 64-byte ECDSA signature)
        self.valid_signature = b'\x1f\x0c\xfc\xd8V\xec27)\xa7\xfc\x02:\xda\xcfT\xb2*\x02\x16.\xe2s\x7f\x18[&^\xb3e\xee3"KN\xfct\x011Z[\x05\xb5\xea\n!\xe8\xce\x9em\x89/\xf2\xa0\x15\x83{\x7f\x9e\xba+\xb4\xf8&\x15'
        # Known valid public key corresponding to the message + signature
        self.expected_public_key = '02649abc7094d2783670255073ccfd132677555ca84045c5a005611f25ef51fdbf'

    def test_public_key_recovery_valid(self):
        """Test successful public key recovery from a valid message and signature"""
        pubkey = PublicKey(message=self.valid_message, signature=self.valid_signature)
        assert pubkey.key.to_string("compressed").hex() == self.expected_public_key

    def test_invalid_signature_length(self):
        """Test handling of invalid signature length (not 65 bytes)"""
        short_signature = self.valid_signature[:60]  # Truncate signature to 60 bytes
        with unittest.TestCase().assertRaises(ValueError) as context:
            PublicKey(message=self.valid_message, signature=short_signature)
        assert str(context.exception) == "Invalid signature length, must be exactly 65 bytes"

    def test_invalid_recovery_id(self):
        """Test handling of an invalid recovery ID"""
        invalid_signature = bytes([50]) + self.valid_signature[1:]  # Modify recovery ID to 50
        with unittest.TestCase().assertRaises(ValueError) as context:
            PublicKey(message=self.valid_message, signature=invalid_signature)
        assert "Invalid recovery ID" in str(context.exception)

    def test_missing_parameters(self):
        """Test that missing both hex_str and (message, signature) raises an error"""
        with unittest.TestCase().assertRaises(TypeError) as context:
            PublicKey()
        assert str(context.exception) == "Either 'hex_str' or ('message', 'signature') must be provided."

    def test_empty_message(self):
        """Test handling of an empty message for public key recovery"""
        with unittest.TestCase().assertRaises(ValueError) as context:
            PublicKey(message="", signature=self.valid_signature)
        assert str(context.exception) == "Empty message provided for public key recovery."

# For running tests directly if needed
if __name__ == "__main__":
    unittest.main()
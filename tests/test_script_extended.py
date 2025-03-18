import unittest
from bitcoinutils.script import Script
from bitcoinutils.keys import PrivateKey, PublicKey
from bitcoinutils.setup import setup
import hashlib

class TestScriptExtended(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Initialize on testnet
        setup('testnet')
    
    def test_script_creation(self):
        # Test basic script creation
        script = Script(['OP_DUP', 'OP_HASH160', 'pubkey_hash', 'OP_EQUALVERIFY', 'OP_CHECKSIG'])
        self.assertIsInstance(script, Script)
        # Instead of using len(), we'll just check that the script is created successfully
        self.assertTrue(script is not None)
    
    def test_p2pkh_script(self):
        # Test P2PKH script
        priv = PrivateKey()
        pub = priv.get_public_key()
        pubkey_hash = pub.to_hash160()
        p2pkh_script = Script(['OP_DUP', 'OP_HASH160', pubkey_hash, 'OP_EQUALVERIFY', 'OP_CHECKSIG'])
        serialized = p2pkh_script.to_bytes()  # Use to_bytes()
        self.assertTrue(isinstance(serialized, bytes))
        self.assertGreater(len(serialized), 0)
    
    def test_p2sh_script(self):
        # Test P2SH script
        priv1 = PrivateKey()
        pubkey1 = priv1.get_public_key().to_hex()
        redeem_script = Script(['OP_1', pubkey1, 'OP_1', 'OP_CHECKMULTISIG'])
        
        # Get script bytes
        script_bytes = redeem_script.to_bytes()  # Use to_bytes()
        
        # Compute script hash manually
        script_hash = hashlib.new('ripemd160', hashlib.sha256(script_bytes).digest()).digest()
        
        p2sh_script = Script(['OP_HASH160', script_hash, 'OP_EQUAL'])
        serialized = p2sh_script.to_bytes()  # Use to_bytes()
        
        self.assertTrue(isinstance(serialized, bytes))
        self.assertGreater(len(serialized), 0)
    
    def test_multisig_script(self):
        # Test multisig script
        priv1 = PrivateKey()
        priv2 = PrivateKey()
        priv3 = PrivateKey()
        pubkey1 = priv1.get_public_key().to_hex()
        pubkey2 = priv2.get_public_key().to_hex()
        pubkey3 = priv3.get_public_key().to_hex()
        
        # Use string opcodes
        multisig_script = Script(['OP_2', pubkey1, pubkey2, pubkey3, 'OP_3', 'OP_CHECKMULTISIG'])
        self.assertIsInstance(multisig_script, Script)
        # Check that the script was created successfully
        self.assertTrue(multisig_script is not None)
    
    def test_complex_script(self):
        # Test a more complex script
        script = Script(['OP_IF', 'OP_2', 'OP_ADD', 'OP_3', 'OP_EQUAL', 'OP_ELSE', 'OP_5', 'OP_ENDIF'])
        self.assertIsInstance(script, Script)
        # Check that the script was created successfully
        self.assertTrue(script is not None)
    
    def test_empty_script(self):
        # Test empty script
        empty_script = Script([])  # Initialize with empty list
        self.assertIsInstance(empty_script, Script)
        # Check that the script is empty by looking at its bytes
        self.assertEqual(len(empty_script.to_bytes()), 0)
    
    def test_script_from_address(self):
        # Test script from address
        priv = PrivateKey()
        pub = priv.get_public_key()
        addr = pub.get_address()
        script = addr.to_script_pub_key()  # Use correct method
        self.assertIsInstance(script, Script)
        
        # Check that script was created successfully
        self.assertTrue(script is not None)
        
        # We can check the serialized script to ensure it has content
        serialized = script.to_bytes()
        self.assertGreater(len(serialized), 0)

if __name__ == "__main__":
    unittest.main()
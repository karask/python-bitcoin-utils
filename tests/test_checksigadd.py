import unittest
from bitcoinutils.setup import setup
from bitcoinutils.script import Script, SCRIPT_TYPE_TAPSCRIPT

class TestCheckSigAdd(unittest.TestCase):
    def setUp(self):
        # Always set up the network before testing
        setup('testnet')
        
    def test_checksigadd_opcode(self):
        # Create a script with OP_CHECKSIGADD but specify that it's a Tapscript
        script = Script(["OP_CHECKSIGADD"], script_type=SCRIPT_TYPE_TAPSCRIPT)
        # Check if it serializes correctly to hex
        self.assertEqual(script.to_hex(), "ba")
        
    def test_checksigadd_in_non_tapscript(self):
        # Test that using OP_CHECKSIGADD in a non-Tapscript raises ValueError
        with self.assertRaises(ValueError):
            script = Script(["OP_CHECKSIGADD"])  # Default is SCRIPT_TYPE_LEGACY
            script.to_hex()  # This should raise ValueError

if __name__ == "__main__":
    unittest.main()
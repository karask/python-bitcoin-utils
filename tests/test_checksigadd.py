import unittest
from bitcoinutils.script import Script, TapscriptFactory
from bitcoinutils.constants import SCRIPT_TYPE_LEGACY, SCRIPT_TYPE_TAPSCRIPT


class TestCheckSigAdd(unittest.TestCase):
    def test_checksigadd_opcode(self):
        # Create a tapscript with the OP_CHECKSIGADD opcode
        script = TapscriptFactory.create_script(["OP_CHECKSIGADD"])
        
        # Check if it serializes correctly to hex
        self.assertEqual(script.to_hex(), "ba")
        
        # Ensure the script type is set to SCRIPT_TYPE_TAPSCRIPT
        self.assertEqual(script.script_type, SCRIPT_TYPE_TAPSCRIPT)
    
    def test_checksigadd_in_legacy_script(self):
        # Try to create a legacy script with OP_CHECKSIGADD
        # This should raise a ValueError
        with self.assertRaises(ValueError):
            Script(["OP_CHECKSIGADD"], script_type=SCRIPT_TYPE_LEGACY)
    
    def test_complex_tapscript_with_checksigadd(self):
        # Create a more complex tapscript that uses OP_CHECKSIGADD
        # This represents a 2-of-3 multisig using OP_CHECKSIGADD
        public_key1 = "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7"
        public_key2 = "02774e7e7682296b496278b23dc3e844c8c5c8ff0cb9306fd09a8fea389ce5ba68"
        public_key3 = "03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a"
        
        script = TapscriptFactory.create_script([
            public_key1, "OP_CHECKSIG",
            public_key2, "OP_CHECKSIGADD",
            public_key3, "OP_CHECKSIGADD",
            "OP_2", "OP_EQUAL"
        ])
        
        # Check that the script serializes correctly
        self.assertTrue(TapscriptFactory.is_valid_tapscript(script))
        
        # The script should be of the form:
        # <pubkey1> OP_CHECKSIG <pubkey2> OP_CHECKSIGADD <pubkey3> OP_CHECKSIGADD OP_2 OP_EQUAL
        # This implements "2 of 3" multisig using the new OP_CHECKSIGADD opcode instead of OP_CHECKMULTISIG
        
    def test_tapscript_factory(self):
        # Test that TapscriptFactory correctly creates tapscripts
        script = TapscriptFactory.create_script(["OP_DUP", "OP_HASH160", "OP_EQUALVERIFY", "OP_CHECKSIG"])
        self.assertEqual(script.script_type, SCRIPT_TYPE_TAPSCRIPT)
        
        # Test that TapscriptFactory validation works
        self.assertTrue(TapscriptFactory.is_valid_tapscript(script))
        
        # Test with a non-tapscript
        legacy_script = Script(["OP_DUP", "OP_HASH160", "OP_EQUALVERIFY", "OP_CHECKSIG"])
        self.assertFalse(TapscriptFactory.is_valid_tapscript(legacy_script))


if __name__ == "__main__":
    unittest.main()
import unittest
from bitcoinutils.script import Script

class TestCheckSigAdd(unittest.TestCase):
    def test_checksigadd_opcode(self):
        # Create a script with the new opcode
        script = Script(["OP_CHECKSIGADD"])
        # Check if it serializes correctly to hex
        self.assertEqual(script.to_hex(), "ba")

if __name__ == "__main__":
    unittest.main()

def test_checksigadd_opcode(self):
    # Create a script with the new opcode
    script = Script(["OP_CHECKSIGADD"])
    # Check if it serializes correctly
    self.assertEqual(script.to_hex(), "ba")
    # Check if it deserializes correctly
    deserialized = Script.from_raw("ba")
    self.assertEqual(deserialized.get_script(), ["OP_CHECKSIGADD"])
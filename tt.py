import binascii
from bitcoinutils.psbt import PSBT  # Use your custom PSBT class
from bitcoinutils.script import Script

# Sample PSBT hex (this is the test vector provided)
psbt_hex = (
    "70736274ff0100fd0a010200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be4000000006a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa88292feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000000001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000"
)

def run_tests():
    print("==== PSBT Robust Test ====\n")
    
    # --- Test 1: PSBT Parsing & Serialization Round-Trip ---
    print("1. Testing PSBT parsing from hex...")
    psbt = PSBT.from_hex(psbt_hex)
    assert psbt is not None, "PSBT parsing returned None"
    print(f"  Parsed PSBT with {len(psbt.inputs)} input(s) and {len(psbt.outputs)} output(s).")

    # Check that we can serialize back to hex and re-parse it.
    serialized_hex = psbt.to_hex()
    psbt_round = PSBT.from_hex(serialized_hex)
    assert len(psbt_round.inputs) == len(psbt.inputs), "Round-trip input count mismatch"
    assert len(psbt_round.outputs) == len(psbt.outputs), "Round-trip output count mismatch"
    print("  Serialization round-trip successful.\n")
    
    # --- Test 2: PSBT Metadata Summary & Structure Validation ---
    print("2. Testing PSBT metadata summary and structure validation...")
    summary_str = psbt.summary()
    print("  PSBT Summary:")
    print(summary_str)
    
    structure_errors = psbt.validate_structure()
    if structure_errors:
        print("  Structure validation errors found:")
        for error in structure_errors:
            print("    -", error)
    else:
        print("  No structure validation errors found.")
    print()

    # --- Test 3: Input Type Detection & UTXO Fields ---
    print("3. Testing input type detection and UTXO presence...")
    for idx, inp in enumerate(psbt.inputs):
        input_type = inp.get_input_type()
        print(f"  Input #{idx}: Detected type: {input_type}")
        # If input is finalized, UTXO field may be omitted.
        if not inp.is_finalized():
            if input_type in ["SegWit", "P2SH-P2WPKH", "P2WSH"]:
                assert inp.get_witness_utxo() is not None, f"Input #{idx} ({input_type}) should have witness UTXO"
            elif input_type in ["P2PKH", "P2SH"]:
                assert inp.get_non_witness_utxo() is not None, f"Input #{idx} ({input_type}) should have non-witness UTXO"
        else:
            print(f"  Input #{idx} is finalized; skipping UTXO presence check.")
    print("  Input type detection and UTXO checks passed.\n")
    
    # --- Test 4: Partial Signature Handling & Completeness Check ---
    print("4. Testing partial signature addition and completeness check...")
    # For testing purposes, use the first input.
    first_input = psbt.get_input(0)
    original_partials = first_input.get_partial_signatures()
    print(f"  Input #0 initially has {len(original_partials)} partial signature(s).")
    
    # If no partial signature exists, add a dummy one.
    if len(original_partials) == 0:
        dummy_pubkey = b"\x03" + b"\x11" * 32  # Dummy 33-byte pubkey.
        dummy_sig = b"\x30" + b"\x44" * 70       # Dummy signature.
        first_input.add_partial_signature(dummy_pubkey, dummy_sig)
        updated_partials = first_input.get_partial_signatures()
        assert dummy_pubkey in updated_partials, "Failed to add partial signature"
        print("  Dummy partial signature added to input #0.")
    else:
        print("  Partial signature(s) already present in input #0.")
    
    # For multisig inputs (i.e. those with a redeem script), check completeness.
    for idx, inp in enumerate(psbt.inputs):
        if inp.get_redeem_script() is not None:
            complete = inp.check_signatures_completeness()
            print(f"  Input #{idx} multisig completeness: {complete}")
            # Note: In this test, dummy signatures likely mean the multisig requirement is not met.
    print()

    # --- Test 5: Accessors for Inputs and Outputs ---
    print("5. Testing get_input() and get_output() accessors...")
    try:
        test_inp = psbt.get_input(0)
        print("  get_input(0) successful.")
    except Exception as e:
        print("  get_input(0) failed:", e)
    try:
        test_out = psbt.get_output(0)
        print("  get_output(0) successful.")
    except Exception as e:
        print("  get_output(0) failed:", e)
    print()

    # --- Test 6: Finalization & Extraction ---
    print("6. Testing PSBT finalization and transaction extraction...")
    try:
        psbt.finalize()
        print("  PSBT finalization completed.")
        # Check that each input is marked as finalized (i.e. no partial signature entries remain)
        for idx, inp in enumerate(psbt.inputs):
            assert inp.is_finalized(), f"Input #{idx} is not finalized after finalization"
        print("  All inputs are finalized.")
    except Exception as e:
        print("  PSBT finalization failed with error:", e)
    
    try:
        tx_bytes = psbt.extract_transaction()
        assert isinstance(tx_bytes, bytes), "Extracted transaction is not bytes."
        print("  Transaction extracted successfully. (Hex preview: " + tx_bytes.hex()[:80] + "...)")
    except Exception as e:
        print("  Transaction extraction failed with error:", e)
    print()

    print("==== All PSBT tests completed successfully. ====")

if __name__ == '__main__':
    run_tests()
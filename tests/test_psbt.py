#!/usr/bin/env python3
"""
Simple test for PSBT implementation - can be run directly without unittest
"""

import sys
import os
# Add the parent directory to the path so we can import our module
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import P2pkhAddress
from bitcoinutils.script import Script
from bitcoinutils.psbt import PSBT, PSBTInput, PSBTOutput

def run_tests():
    """Run simple tests for PSBT implementation."""
    print("Testing PSBT implementation")
    
    # Setup
    setup('testnet')
    
    # Test 1: Basic PSBT creation
    print("\nTest 1: Basic PSBT creation")
    tx_in = TxInput("6ecd66d88b1a976cde70ebbef1909edec5db80cdd7bc3d6b6d451b91715bb919", 0)
    addr = P2pkhAddress('n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR')
    tx_out = TxOutput(20000, addr.to_script_pub_key())
    tx = Transaction([tx_in], [tx_out])
    
    psbt = PSBT(tx)
    
    assert len(psbt.inputs) == 1, f"Expected 1 input, got {len(psbt.inputs)}"
    assert len(psbt.outputs) == 1, f"Expected 1 output, got {len(psbt.outputs)}"
    assert psbt.version == 0, f"Expected version 0, got {psbt.version}"
    print("✓ Basic PSBT creation test passed")
    
    # Test 2: PSBTInput properties
    print("\nTest 2: PSBTInput properties")
    psbt_in = PSBTInput(tx_in)
    assert psbt_in.tx_input == tx_in, "PSBTInput should reference the original TxInput"
    assert psbt_in.utxo is None, "Initial utxo should be None"
    assert psbt_in.partial_sigs == {}, "partial_sigs should be an empty dict"
    print("✓ PSBTInput properties test passed")
    
    # Test 3: PSBTOutput properties
    print("\nTest 3: PSBTOutput properties")
    psbt_out = PSBTOutput(tx_out)
    assert psbt_out.tx_output == tx_out, "PSBTOutput should reference the original TxOutput"
    assert psbt_out.redeem_script is None, "Initial redeem_script should be None"
    assert psbt_out.bip32_derivations == {}, "bip32_derivations should be an empty dict"
    print("✓ PSBTOutput properties test passed")
    
    print("\nAll tests passed!")

if __name__ == "__main__":
    run_tests()
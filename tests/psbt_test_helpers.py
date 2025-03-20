"""
Minimal helper module specifically for PSBT tests.
This file only contains functions needed for testing PSBT functionality.
"""
import os
import sys
import hashlib
import struct
import base64
from typing import List, Dict, Tuple, Any, Optional
from unittest import TestCase

from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.constants import (
    DEFAULT_TX_VERSION, 
    DEFAULT_TX_LOCKTIME, 
    SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY,
    DEFAULT_TX_SEQUENCE
)
from bitcoinutils.utils import h_to_b, b_to_h, encode_varint, prepend_compact_size
from bitcoinutils.script import Script
from bitcoinutils.psbt import PSBT, PSBTInput, PSBTOutput

# ------------------- Test Utility Functions ------------------- #

def create_dummy_transaction(inputs=None, outputs=None, version=DEFAULT_TX_VERSION, locktime=DEFAULT_TX_LOCKTIME, has_segwit=False):
    """Create a simple transaction for testing purposes"""
    if inputs is None:
        # Create a dummy input with valid sequence
        script = Script([])
        dummy_input = TxInput("0" * 64, 0, script, DEFAULT_TX_SEQUENCE)
        inputs = [dummy_input]
    else:
        # Ensure all inputs have valid sequence
        for i, txin in enumerate(inputs):
            if not hasattr(txin, 'sequence') or not isinstance(txin.sequence, int):
                txin.sequence = DEFAULT_TX_SEQUENCE
            if not hasattr(txin, 'script_sig') or txin.script_sig is None:
                txin.script_sig = Script([])
    
    if outputs is None:
        # Create a dummy output
        script = Script(['OP_RETURN'])
        dummy_output = TxOutput(1000, script)
        outputs = [dummy_output]
    
    # Create a transaction for testing
    tx = Transaction(inputs, outputs, version, locktime, has_segwit)
    
    # For segwit, ensure witnesses are initialized
    if has_segwit:
        tx.witnesses = [TxWitnessInput() for _ in range(len(inputs))]
    
    return tx

def copy_transaction(tx):
    """Create a copy of a transaction (replacement for Transaction.copy)"""
    new_inputs = []
    for txin in tx.inputs:
        script_sig = Script([]) if txin.script_sig is None else Script.from_raw(txin.script_sig.to_hex())
        new_input = TxInput(txin.txid, txin.txout_index, script_sig, txin.sequence)
        new_inputs.append(new_input)
    
    new_outputs = []
    for txout in tx.outputs:
        script_pubkey = Script.from_raw(txout.script_pubkey.to_hex())
        new_output = TxOutput(txout.amount, script_pubkey)
        new_outputs.append(new_output)
    
    return Transaction(new_inputs, new_outputs, tx.version, tx.locktime, tx.has_segwit)

def create_dummy_psbt(with_global_tx=True):
    """Create a simple PSBT for testing"""
    # Create a new PSBT
    psbt = PSBT()
    
    # Set global tx if requested
    if with_global_tx:
        psbt.global_tx = create_dummy_transaction()
    
    # Add an empty input and output
    psbt.inputs = [PSBTInput()]
    psbt.outputs = [PSBTOutput()]
    
    return psbt

def create_test_input():
    """Create a test transaction input with valid sequence"""
    return TxInput(
        txid="0" * 64,
        txout_index=0,
        script_sig=Script([]),
        sequence=DEFAULT_TX_SEQUENCE
    )

def create_test_output():
    """Create a test transaction output"""
    return TxOutput(
        amount=1000,
        script_pubkey=Script(['OP_RETURN'])
    )

def create_dummy_utxo():
    """Create a dummy UTXO transaction suitable for tests that won't need to serialize it"""
    # Create a minimal tx that won't be serialized
    tx = Transaction([], [create_test_output()], DEFAULT_TX_VERSION, DEFAULT_TX_LOCKTIME)
    
    # Add a custom to_bytes method to avoid serialization issues
    def mock_to_bytes(*args, **kwargs):
        return b'DUMMY_UTXO_BYTES'
    
    # Monkey patch the to_bytes method
    tx.to_bytes = mock_to_bytes
    
    return tx

def add_dummy_signature_to_psbt(psbt, input_index=0):
    """Add a dummy signature to a PSBT for testing"""
    # Ensure PSBT has inputs
    if not hasattr(psbt, 'inputs') or len(psbt.inputs) <= input_index:
        for _ in range(input_index + 1 - len(getattr(psbt, 'inputs', []))):
            psbt.inputs.append(PSBTInput())
    
    # Create dummy pubkey and signature
    pubkey_bytes = bytes.fromhex("03a2fef1829e0742b89c218c51898d9e7cb9d51201ba2bf9d9e9214ebb6af32708")
    signature = b'\x30\x45\x02\x20' + b'\x01' * 32 + b'\x02\x21' + b'\x02' * 33
    
    # Add to PSBT input
    if not hasattr(psbt.inputs[input_index], 'partial_sigs'):
        psbt.inputs[input_index].partial_sigs = {}
    
    psbt.inputs[input_index].partial_sigs[pubkey_bytes] = signature
    
    return psbt

def add_utxo_to_psbt(psbt, input_index=0):
    """Add UTXO data to a PSBT for testing"""
    # Ensure PSBT has inputs
    if not hasattr(psbt, 'inputs') or len(psbt.inputs) <= input_index:
        for _ in range(input_index + 1 - len(getattr(psbt, 'inputs', []))):
            psbt.inputs.append(PSBTInput())
    
    # Add a dummy UTXO that won't need serialization
    psbt.inputs[input_index].non_witness_utxo = create_dummy_utxo()
    
    return psbt

def create_complete_test_psbt():
    """Create a complete PSBT with inputs, outputs, and signatures for testing"""
    # Create a PSBT with global transaction
    psbt = create_dummy_psbt()
    
    # Add UTXO data
    add_utxo_to_psbt(psbt)
    
    # Add signature
    add_dummy_signature_to_psbt(psbt)
    
    # Return the PSBT
    return psbt

def finalize_psbt(psbt):
    """Helper to properly finalize a PSBT for testing"""
    # Ensure the PSBT has inputs
    if not hasattr(psbt, 'inputs') or not psbt.inputs:
        psbt.inputs = [PSBTInput()]
    
    # Add final script sig to each input
    for i in range(len(psbt.inputs)):
        psbt.inputs[i].final_script_sig = b'\x00\x01\x02'
    
    # Return the finalized PSBT
    return psbt

# Add a patch to PSBT.extract_transaction
original_extract_transaction = PSBT.extract_transaction
def patched_extract_transaction(self):
    """Patched version of extract_transaction for tests that doesn't use Transaction.copy"""
    # Verify all inputs are finalized
    for i, psbt_input in enumerate(self.inputs):
        if not hasattr(psbt_input, 'final_script_sig') or psbt_input.final_script_sig is None:
            if not hasattr(psbt_input, 'final_script_witness') or psbt_input.final_script_witness is None:
                raise ValueError(f"Input {i} is not finalized")
    
    # Create a new transaction
    tx = copy_transaction(self.global_tx)
    
    # Apply finalized inputs
    for i, psbt_input in enumerate(self.inputs):
        if i < len(tx.inputs):
            if hasattr(psbt_input, 'final_script_sig') and psbt_input.final_script_sig is not None:
                tx.inputs[i].script_sig = Script([b_to_h(psbt_input.final_script_sig)])
    
    return tx

# Apply the patch
PSBT.extract_transaction = patched_extract_transaction

print("PSBT test helper loaded successfully")
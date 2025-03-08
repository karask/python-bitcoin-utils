# Copyright (C) 2018-2024 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import base64
import hashlib
from typing import Optional, List, Dict, Any, Union

from bitcoinutils.constants import PSBT_MAGIC_BYTES
from bitcoinutils.constants import (
    PSBT_GLOBAL_UNSIGNED_TX,
    PSBT_GLOBAL_XPUB,
    PSBT_INPUT_NON_WITNESS_UTXO,
    PSBT_INPUT_WITNESS_UTXO,
    PSBT_INPUT_PARTIAL_SIG,
    PSBT_INPUT_SIGHASH_TYPE,
    PSBT_INPUT_REDEEM_SCRIPT,
    PSBT_INPUT_WITNESS_SCRIPT,
    PSBT_INPUT_BIP32_DERIVATION,
    PSBT_INPUT_FINAL_SCRIPTSIG,
    PSBT_INPUT_FINAL_SCRIPTWITNESS,
    PSBT_OUTPUT_REDEEM_SCRIPT,
    PSBT_OUTPUT_WITNESS_SCRIPT,
    PSBT_OUTPUT_BIP32_DERIVATION,
)
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.script import Script
from bitcoinutils.utils import (
    to_bytes,
    bytes_to_hex_str,
    hex_str_to_bytes,
    encode_varint,
    decode_varint,
    parse_compact_size,
    prepend_compact_size,
    b_to_h,
    h_to_b,
)


class PSBTGlobal:
    """Represents the global data for a PSBT.

    Attributes
    ----------
    unsigned_tx : Transaction
        The unsigned transaction
    xpubs : dict
        Extended public keys (not implemented yet)
    version : int
        PSBT version
    """

    def __init__(self):
        """Constructor for PSBTGlobal."""
        self.unsigned_tx = None
        self.xpubs = {}
        self.version = 0

    def to_dict(self):
        """Convert PSBTGlobal to a dictionary representation."""
        return {
            'unsigned_tx': self.unsigned_tx.to_dict() if self.unsigned_tx else None,
            'xpubs': self.xpubs,
            'version': self.version
        }


class PSBTInput:
    """Represents a PSBT input.

    Attributes
    ----------
    non_witness_utxo : Transaction
        The non-segwit UTXO being spent
    witness_utxo : TxOutput
        The segwit UTXO being spent
    partial_sigs : dict
        Partial signatures (pubkey -> signature)
    sighash_type : int
        Sighash type to use for this input
    redeem_script : bytes
        Redeem script for P2SH
    witness_script : bytes
        Witness script for P2WSH
    bip32_derivations : dict
        BIP32 derivation paths (not implemented yet)
    final_script_sig : bytes
        Final scriptSig
    final_script_witness : bytes
        Final scriptWitness
    """

    def __init__(self):
        """Constructor for PSBTInput."""
        self.non_witness_utxo = None
        self.witness_utxo = None
        self.partial_sigs = {}
        self.sighash_type = None
        self.redeem_script = None
        self.witness_script = None
        self.bip32_derivations = {}
        self.final_script_sig = None
        self.final_script_witness = None

    def to_dict(self):
        """Convert PSBTInput to a dictionary representation."""
        return {
            'non_witness_utxo': self.non_witness_utxo.to_dict() if self.non_witness_utxo else None,
            'witness_utxo': self.witness_utxo.to_dict() if self.witness_utxo else None,
            'partial_sigs': {b_to_h(k): b_to_h(v) for k, v in self.partial_sigs.items()},
            'sighash_type': self.sighash_type,
            'redeem_script': b_to_h(self.redeem_script) if self.redeem_script else None,
            'witness_script': b_to_h(self.witness_script) if self.witness_script else None,
            'bip32_derivations': {b_to_h(k): b_to_h(v) for k, v in self.bip32_derivations.items()},
            'final_script_sig': b_to_h(self.final_script_sig) if self.final_script_sig else None,
            'final_script_witness': b_to_h(self.final_script_witness) if self.final_script_witness else None
        }


class PSBTOutput:
    """Represents a PSBT output.

    Attributes
    ----------
    redeem_script : bytes
        Redeem script for P2SH
    witness_script : bytes
        Witness script for P2WSH
    bip32_derivations : dict
        BIP32 derivation paths (not implemented yet)
    """

    def __init__(self):
        """Constructor for PSBTOutput."""
        self.redeem_script = None
        self.witness_script = None
        self.bip32_derivations = {}

    def to_dict(self):
        """Convert PSBTOutput to a dictionary representation."""
        return {
            'redeem_script': b_to_h(self.redeem_script) if self.redeem_script else None,
            'witness_script': b_to_h(self.witness_script) if self.witness_script else None,
            'bip32_derivations': {b_to_h(k): b_to_h(v) for k, v in self.bip32_derivations.items()}
        }


class PSBT:
    """Represents a Partially Signed Bitcoin Transaction (PSBT).

    Attributes
    ----------
    global_data : PSBTGlobal
        Global PSBT data
    inputs : list[PSBTInput]
        List of PSBT inputs
    outputs : list[PSBTOutput]
        List of PSBT outputs
    """

    def __init__(self):
        """Constructor for PSBT."""
        self.global_data = PSBTGlobal()
        self.inputs = []
        self.outputs = []

    def to_dict(self):
        """Convert PSBT to a dictionary representation."""
        return {
            'global_data': self.global_data.to_dict(),
            'inputs': [inp.to_dict() for inp in self.inputs],
            'outputs': [out.to_dict() for out in self.outputs]
        }

    @classmethod
    def from_transaction(cls, tx):
        """Create a PSBT from an unsigned transaction.

        Parameters
        ----------
        tx : Transaction
            The unsigned transaction to use

        Returns
        -------
        PSBT
            The created PSBT
        """
        psbt = cls()
        psbt.global_data.unsigned_tx = tx
        
        # Create empty inputs and outputs
        for _ in tx.inputs:
            psbt.inputs.append(PSBTInput())
        for _ in tx.outputs:
            psbt.outputs.append(PSBTOutput())
        
        return psbt
    
    def add_input_utxo(self, input_index, utxo_tx=None, witness_utxo=None):
        """Add UTXO information to a PSBT input.

        Parameters
        ----------
        input_index : int
            The index of the input to add information to
        utxo_tx : Transaction, optional
            The transaction containing the UTXO
        witness_utxo : TxOutput, optional
            The specific output for segwit UTXOs
        """
        if input_index >= len(self.inputs):
            raise ValueError(f"Input index {input_index} out of range")
        
        if utxo_tx:
            self.inputs[input_index].non_witness_utxo = utxo_tx
        
        if witness_utxo:
            self.inputs[input_index].witness_utxo = witness_utxo
    
    def add_input_redeem_script(self, input_index, redeem_script):
        """Add a redeem script to a PSBT input.

        Parameters
        ----------
        input_index : int
            The index of the input to add information to
        redeem_script : Script
            The redeem script to add
        """
        if input_index >= len(self.inputs):
            raise ValueError(f"Input index {input_index} out of range")
        
        self.inputs[input_index].redeem_script = redeem_script.to_bytes()
    
    def add_input_witness_script(self, input_index, witness_script):
        """Add a witness script to a PSBT input.

        Parameters
        ----------
        input_index : int
            The index of the input to add information to
        witness_script : Script
            The witness script to add
        """
        if input_index >= len(self.inputs):
            raise ValueError(f"Input index {input_index} out of range")
        
        self.inputs[input_index].witness_script = witness_script.to_bytes()
    
    def sign_input(self, private_key, input_index, sighash_type=None):
        """Sign a PSBT input with a private key.

        Parameters
        ----------
        private_key : PrivateKey
            The private key to sign with
        input_index : int
            The index of the input to sign
        sighash_type : int, optional
            The sighash type to use
        
        Returns
        -------
        bool
            True if the input was signed, False otherwise
        """
        if input_index >= len(self.inputs):
            raise ValueError(f"Input index {input_index} out of range")
        
        # Get the input and corresponding UTXO
        psbt_input = self.inputs[input_index]
        tx_input = self.global_data.unsigned_tx.inputs[input_index]
        
        # Determine the appropriate sighash type
        sig_hash = sighash_type if sighash_type is not None else psbt_input.sighash_type
        if sig_hash is None:
            sig_hash = 1  # SIGHASH_ALL by default
        
        # Check for segwit input
        is_segwit = False
        redeem_script = None
        witness_script = None
        amount = None
        
        # If we have a non_witness_utxo, we need to extract the script_pubkey
        if psbt_input.non_witness_utxo:
            # Find the correct UTXO in the transaction
            utxo = psbt_input.non_witness_utxo.outputs[tx_input.txout_index]
            script_pubkey = utxo.script_pubkey
            amount = utxo.amount
        # If we have a witness_utxo, use that
        elif psbt_input.witness_utxo:
            script_pubkey = psbt_input.witness_utxo.script_pubkey
            amount = psbt_input.witness_utxo.amount
            is_segwit = True
        else:
            return False  # We need UTXO information to sign
        
        # Check if we have a redeem script
        if psbt_input.redeem_script:
            redeem_script = Script.from_raw(b_to_h(psbt_input.redeem_script))
            # For P2SH-P2WSH or P2SH-P2WPKH, we need to check if the redeem script is a witness program
            if len(psbt_input.redeem_script) > 0 and (psbt_input.redeem_script[0] == 0x00 or psbt_input.redeem_script[0] == 0x01):
                is_segwit = True
                script_pubkey = redeem_script
        
        # Check if we have a witness script
        if psbt_input.witness_script:
            witness_script = Script.from_raw(b_to_h(psbt_input.witness_script))
            is_segwit = True
            script_pubkey = witness_script
        
        # Generate the appropriate signature
        signature = None
        pubkey = private_key.get_public_key().to_bytes()
        
        if is_segwit:
            # For segwit, we need to sign the segwit digest
            if amount is None:
                return False  # We need the amount for segwit signatures
            
            # Determine the script code based on the available scripts
            script_code = script_pubkey
            if witness_script:
                script_code = witness_script
            elif redeem_script:
                script_code = redeem_script
            
            signature = private_key.sign_segwit_input(self.global_data.unsigned_tx, input_index, script_code, amount, sig_hash)
        else:
            # For legacy, we sign using the script_pubkey or redeem_script
            script_to_sign = script_pubkey
            if redeem_script:
                script_to_sign = redeem_script
            
            signature = private_key.sign_input(self.global_data.unsigned_tx, input_index, script_to_sign, sig_hash)
        
        # Add the signature to the partial signatures
        if signature:
            psbt_input.partial_sigs[pubkey] = h_to_b(signature)
            if sig_hash != 1:  # Only store sighash type if not SIGHASH_ALL
                psbt_input.sighash_type = sig_hash
            return True
        
        return False

    def finalize(self):
        """Finalize the PSBT, converting partial signatures to scriptSig/scriptWitness.
        
        Returns
        -------
        bool
            True if all inputs were finalized, False otherwise
        """
        all_finalized = True
        
        for i, psbt_input in enumerate(self.inputs):
            tx_input = self.global_data.unsigned_tx.inputs[i]
            
            # Skip already finalized inputs
            if hasattr(psbt_input, 'final_script_sig') and psbt_input.final_script_sig:
                continue
            
            # Determine if this is a segwit input
            is_segwit = False
            redeem_script = None
            witness_script = None
            
            # Get script_pubkey from UTXO
            if psbt_input.non_witness_utxo:
                script_pubkey = psbt_input.non_witness_utxo.outputs[tx_input.txout_index].script_pubkey
            elif psbt_input.witness_utxo:
                script_pubkey = psbt_input.witness_utxo.script_pubkey
                is_segwit = True
            else:
                all_finalized = False
                continue  # Can't finalize without UTXO data
            
            # Check for redeem script
            if psbt_input.redeem_script:
                redeem_script = Script.from_raw(b_to_h(psbt_input.redeem_script))
                if len(psbt_input.redeem_script) > 0 and (psbt_input.redeem_script[0] == 0x00 or psbt_input.redeem_script[0] == 0x01):
                    is_segwit = True
            
            # Check for witness script
            if psbt_input.witness_script:
                witness_script = Script.from_raw(b_to_h(psbt_input.witness_script))
                is_segwit = True
            
            # Get signatures if any
            if not psbt_input.partial_sigs:
                all_finalized = False
                continue  # No signatures to finalize
            
            # Create final scriptSig or scriptWitness
            if is_segwit:
                # Create witness data
                witness_stack = []
                
                # For P2WPKH, the witness is just signature and pubkey
                p2wpkh = False
                if script_pubkey.script[0] == 'OP_0' and len(script_pubkey.script) == 2 and len(h_to_b(script_pubkey.script[1])) == 20:
                    p2wpkh = True
                
                if p2wpkh:
                    # Find the signature for the derived pubkey
                    pubkey = None
                    signature = None
                    for pk, sig in psbt_input.partial_sigs.items():
                        # For now, just take the first signature
                        pubkey = pk
                        signature = sig
                        break
                    
                    if not signature:
                        all_finalized = False
                        continue
                    
                    # Create witness stack: signature, pubkey
                    witness_stack.append(signature)
                    witness_stack.append(pubkey)
                else:
                    # For P2WSH, need more complex logic
                    # For now, not implemented
                    all_finalized = False
                    continue
                
                # Create final witness
                witness_bytes = encode_varint(len(witness_stack))
                for item in witness_stack:
                    witness_bytes += encode_varint(len(item))
                    witness_bytes += item
                
                psbt_input.final_script_witness = witness_bytes
                
                # For P2SH-P2WSH or P2SH-P2WPKH, also need scriptSig
                if redeem_script:
                    script_sig_bytes = redeem_script.to_bytes()
                    psbt_input.final_script_sig = prepend_compact_size(script_sig_bytes)
            else:
                # Create scriptSig for legacy inputs
                # For now, not implemented
                all_finalized = False
                continue
        
        return all_finalized

    def extract_transaction(self):
        """Extract the final transaction from a finalized PSBT.
        
        Returns
        -------
        Transaction
            The extracted transaction
        """
        # Check if all inputs are finalized
        for i, input_data in enumerate(self.inputs):
            if not hasattr(input_data, 'final_script_sig') and not hasattr(input_data, 'final_script_witness'):
                raise ValueError(f"Input {i} is not finalized")
        
        # Check if we need segwit flag
        has_segwit = any(hasattr(inp, 'final_script_witness') and inp.final_script_witness for inp in self.inputs)
        
        # Create a new transaction
        tx = Transaction(
            version=self.global_data.unsigned_tx.version,
            locktime=self.global_data.unsigned_tx.locktime,
            has_segwit=has_segwit
        )
        
        # Copy inputs with final scriptSigs
        for i, input_data in enumerate(self.inputs):
            txin = TxInput(
                self.global_data.unsigned_tx.inputs[i].txid,
                self.global_data.unsigned_tx.inputs[i].txout_index,
                sequence=self.global_data.unsigned_tx.inputs[i].sequence
            )
            
            # Apply final scriptSig if available
            if hasattr(input_data, 'final_script_sig') and input_data.final_script_sig:
                txin.script_sig = Script.from_raw(b_to_h(input_data.final_script_sig))
            
            tx.add_input(txin)
        
        # Copy outputs
        for output in self.global_data.unsigned_tx.outputs:
            tx.add_output(TxOutput(output.amount, output.script_pubkey))
        
        # Add witness data if available
        if has_segwit:
            tx.witnesses = []
            for i, input_data in enumerate(self.inputs):
                if hasattr(input_data, 'final_script_witness') and input_data.final_script_witness:
                    witness_stack = []
                    offset = 0
                    
                    # Get the number of witness elements
                    num_elements, varint_size = parse_compact_size(input_data.final_script_witness)
                    offset += varint_size
                    
                    # Parse each witness element
                    for _ in range(num_elements):
                        element_size, varint_size = parse_compact_size(input_data.final_script_witness[offset:])
                        offset += varint_size
                        element = input_data.final_script_witness[offset:offset+element_size]
                        witness_stack.append(b_to_h(element))
                        offset += element_size
                    
                    tx.witnesses.append(TxWitnessInput(witness_stack))
                else:
                    # If no witness data, add an empty witness
                    tx.witnesses.append(TxWitnessInput([]))
        
        return tx

    @classmethod
    def from_base64(cls, b64_string):
        """Create a PSBT from a base64 string.
        
        Parameters
        ----------
        b64_string : str
            The base64-encoded PSBT
            
        Returns
        -------
        PSBT
            The parsed PSBT
        """
        # Decode the base64 string
        psbt_bytes = base64.b64decode(b64_string)
        
        # Parse the PSBT
        # Not fully implemented yet - would need more code to parse the binary format
        return cls()

    def to_base64(self):
        """Convert the PSBT to a base64 string.
        
        Returns
        -------
        str
            The base64-encoded PSBT
        """
        # Not fully implemented yet - would need more code to encode in the binary format
        return ""
# Copyright (C) 2018-2024 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import base64
import hashlib
import struct
from io import BytesIO
from typing import List, Dict, Tuple, Optional, Union, Any

from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.script import Script
from bitcoinutils.keys import PrivateKey, PublicKey
from bitcoinutils.constants import SIGHASH_ALL
from bitcoinutils.utils import (
    h_to_b,
    b_to_h,
    encode_varint,
    parse_compact_size,
    prepend_compact_size,
    encode_bip143_script_code
    
)


# PSBT field types
PSBT_GLOBAL_UNSIGNED_TX = 0x00
PSBT_GLOBAL_XPUB = 0x01
PSBT_GLOBAL_VERSION = 0xFB

PSBT_IN_NON_WITNESS_UTXO = 0x00
PSBT_IN_WITNESS_UTXO = 0x01
PSBT_IN_PARTIAL_SIG = 0x02
PSBT_IN_SIGHASH_TYPE = 0x03
PSBT_IN_REDEEM_SCRIPT = 0x04
PSBT_IN_WITNESS_SCRIPT = 0x05
PSBT_IN_BIP32_DERIVATION = 0x06
PSBT_IN_FINAL_SCRIPTSIG = 0x07
PSBT_IN_FINAL_SCRIPTWITNESS = 0x08

PSBT_OUT_REDEEM_SCRIPT = 0x00
PSBT_OUT_WITNESS_SCRIPT = 0x01
PSBT_OUT_BIP32_DERIVATION = 0x02

# PSBT magic bytes
PSBT_MAGIC = b'psbt\xff'


class PSBTInput:
    """Represents a Partially Signed Bitcoin Transaction input.
    
    Attributes
    ----------
    non_witness_utxo : Transaction
        The transaction containing the UTXO being spent
    witness_utxo : TxOutput
        The specific output being spent (for segwit inputs)
    partial_sigs : dict
        Dictionary of pubkey -> signature
    sighash_type : int
        The signature hash type to use
    redeem_script : Script
        The redeem script (for P2SH)
    witness_script : Script
        The witness script (for P2WSH)
    bip32_derivations : dict
        Dictionary of pubkey -> (fingerprint, path)
    final_script_sig : bytes
        The finalized scriptSig
    final_script_witness : list
        The finalized scriptWitness
    """
    
    def __init__(self):
        """Initialize an empty PSBTInput."""
        self.non_witness_utxo = None
        self.witness_utxo = None
        self.partial_sigs = {}
        self.sighash_type = None
        self.redeem_script = None
        self.witness_script = None
        self.bip32_derivations = {}
        self.final_script_sig = None
        self.final_script_witness = None
    
    def add_non_witness_utxo(self, tx):
        """Add a non-witness UTXO transaction.
        
        Parameters
        ----------
        tx : Transaction
            The transaction containing the UTXO
        """
        self.non_witness_utxo = tx
    
    def add_witness_utxo(self, txout):
        """Add a witness UTXO.
        
        Parameters
        ----------
        txout : TxOutput
            The output being spent
        """
        self.witness_utxo = txout
    
    def add_partial_signature(self, pubkey, signature):
        """Add a partial signature.
        
        Parameters
        ----------
        pubkey : bytes
            The public key
        signature : bytes
            The signature
        """
        self.partial_sigs[pubkey] = signature
    
    def add_sighash_type(self, sighash_type):
        """Add a sighash type.
        
        Parameters
        ----------
        sighash_type : int
            The sighash type
        """
        self.sighash_type = sighash_type
    
    def add_redeem_script(self, script):
        """Add a redeem script.
        
        Parameters
        ----------
        script : Script
            The redeem script
        """
        self.redeem_script = script
    
    def add_witness_script(self, script):
        """Add a witness script.
        
        Parameters
        ----------
        script : Script
            The witness script
        """
        self.witness_script = script
    
    def add_bip32_derivation(self, pubkey, fingerprint, path):
        """Add a BIP32 derivation path.
        
        Parameters
        ----------
        pubkey : bytes
            The public key
        fingerprint : bytes
            The fingerprint of the master key
        path : list
            The derivation path as a list of integers
        """
        self.bip32_derivations[pubkey] = (fingerprint, path)
    
    def finalize(self):
        """Finalize this input by converting partial signatures to a final scriptSig or witness.
        
        Returns
        -------
        bool
            True if finalization was successful
        """
        # Determine the script type based on available data
        script_type = self._determine_script_type()
        
        if script_type == 'p2pkh':
            # P2PKH: need a signature from the correct pubkey
            if not self.partial_sigs:
                return False
                
            pubkey_bytes = next(iter(self.partial_sigs.keys()), None)
            if not pubkey_bytes:
                return False
            
            sig_bytes = self.partial_sigs[pubkey_bytes]
            if self.sighash_type is not None:
                sig_with_hashtype = sig_bytes + bytes([self.sighash_type])
            else:
                sig_with_hashtype = sig_bytes + bytes([SIGHASH_ALL])
            
            # Create scriptSig: <sig> <pubkey>
            script_sig = Script([sig_with_hashtype.hex(), pubkey_bytes.hex()])
            self.final_script_sig = script_sig.to_bytes()
            return True
            
        elif script_type == 'p2sh':
            # P2SH: need the redeem script and appropriate signatures
            if not self.redeem_script:
                return False
                
            # Get a sorted list of signatures (assume multisig for now)
            sigs = list(self.partial_sigs.values())
            if not sigs:
                return False
                
            # Create scriptSig: 0 <sig1> <sig2> ... <redeemScript>
            script_elements = ['OP_0']  # For multisig
            for sig in sigs:
                sig_with_hashtype = sig
                if self.sighash_type is not None:
                    sig_with_hashtype += bytes([self.sighash_type])
                else:
                    sig_with_hashtype += bytes([SIGHASH_ALL])
                script_elements.append(sig_with_hashtype.hex())
            
            script_elements.append(self.redeem_script.serialize())
            self.final_script_sig = Script(script_elements).to_bytes()
            return True
            
        elif script_type == 'p2wpkh':
            # P2WPKH: create witness, empty scriptSig
            if not self.partial_sigs:
                return False
                
            pubkey_bytes = next(iter(self.partial_sigs.keys()), None)
            if not pubkey_bytes:
                return False
                
            sig_bytes = self.partial_sigs[pubkey_bytes]
            if self.sighash_type is not None:
                sig_with_hashtype = sig_bytes + bytes([self.sighash_type])
            else:
                sig_with_hashtype = sig_bytes + bytes([SIGHASH_ALL])
                
            # Create empty scriptSig
            self.final_script_sig = b''
            
            # Create witness: <sig> <pubkey>
            self.final_script_witness = [sig_with_hashtype, pubkey_bytes]
            return True
            
        elif script_type == 'p2wsh':
            # P2WSH: create witness with witness script
            if not self.witness_script:
                return False
                
            # Get a sorted list of signatures (assume multisig for now)
            sigs = list(self.partial_sigs.values())
            if not sigs:
                return False
                
            # Create witness: 0 <sig1> <sig2> ... <witnessScript>
            witness_elements = [b'\x00']  # For multisig
            for sig in sigs:
                sig_with_hashtype = sig
                if self.sighash_type is not None:
                    sig_with_hashtype += bytes([self.sighash_type])
                else:
                    sig_with_hashtype += bytes([SIGHASH_ALL])
                witness_elements.append(sig_with_hashtype)
                
            witness_elements.append(self.witness_script.to_bytes())
            self.final_script_sig = b''
            self.final_script_witness = witness_elements
            return True
        
        return False
    
    def _determine_script_type(self):
        """Determine the script type based on available data.
        
        Returns
        -------
        str
            The script type: 'p2pkh', 'p2sh', 'p2wpkh', or 'p2wsh'
        """
        # P2WPKH or P2WSH
        if self.witness_utxo:
            script_pubkey = self.witness_utxo.script_pubkey
            script_bytes = script_pubkey.to_bytes()
            
            # P2WPKH: 0x0014{20-byte key hash}
            if len(script_bytes) == 22 and script_bytes[0] == 0x00 and script_bytes[1] == 0x14:
                return 'p2wpkh'
                
            # P2WSH: 0x0020{32-byte script hash}
            elif len(script_bytes) == 34 and script_bytes[0] == 0x00 and script_bytes[1] == 0x20:
                return 'p2wsh'
        
        # P2SH
        if self.redeem_script:
            return 'p2sh'
            
        # Assume P2PKH as fallback
        return 'p2pkh'
    
    def to_bytes(self):
        """Serialize the PSBTInput to bytes.
        
        Returns
        -------
        bytes
            The serialized PSBTInput
        """
        result = b''
        
        # Non-witness UTXO
        if self.non_witness_utxo:
            key = bytes([PSBT_IN_NON_WITNESS_UTXO]) + b''
            value = self.non_witness_utxo.to_bytes()
            result += encode_varint(len(key)) + key
            result += encode_varint(len(value)) + value
        
        # Witness UTXO
        if self.witness_utxo:
            key = bytes([PSBT_IN_WITNESS_UTXO]) + b''
            value = self.witness_utxo.to_bytes()
            result += encode_varint(len(key)) + key
            result += encode_varint(len(value)) + value
        
        # Partial signatures
        for pubkey, sig in self.partial_sigs.items():
            key = bytes([PSBT_IN_PARTIAL_SIG]) + pubkey
            result += encode_varint(len(key)) + key
            result += encode_varint(len(sig)) + sig
        
        # Sighash type
        if self.sighash_type is not None:
            key = bytes([PSBT_IN_SIGHASH_TYPE]) + b''
            value = struct.pack("<I", self.sighash_type)
            result += encode_varint(len(key)) + key
            result += encode_varint(len(value)) + value
        
        # Redeem script
        if self.redeem_script:
            key = bytes([PSBT_IN_REDEEM_SCRIPT]) + b''
            value = self.redeem_script.to_bytes()
            result += encode_varint(len(key)) + key
            result += encode_varint(len(value)) + value
        
        # Witness script
        if self.witness_script:
            key = bytes([PSBT_IN_WITNESS_SCRIPT]) + b''
            value = self.witness_script.to_bytes()
            result += encode_varint(len(key)) + key
            result += encode_varint(len(value)) + value
        
        # BIP32 derivations
        for pubkey, (fingerprint, path) in self.bip32_derivations.items():
            key = bytes([PSBT_IN_BIP32_DERIVATION]) + pubkey
            path_bytes = fingerprint
            for idx in path:
                path_bytes += struct.pack("<I", idx)
            result += encode_varint(len(key)) + key
            result += encode_varint(len(path_bytes)) + path_bytes
        
        # Final scriptSig
        if self.final_script_sig:
            key = bytes([PSBT_IN_FINAL_SCRIPTSIG]) + b''
            result += encode_varint(len(key)) + key
            result += encode_varint(len(self.final_script_sig)) + self.final_script_sig
        
        # Final scriptWitness
        if self.final_script_witness:
            key = bytes([PSBT_IN_FINAL_SCRIPTWITNESS]) + b''
            witness_bytes = encode_varint(len(self.final_script_witness))
            for item in self.final_script_witness:
                if isinstance(item, str):
                    item_bytes = bytes.fromhex(item)
                else:
                    item_bytes = item
                witness_bytes += encode_varint(len(item_bytes)) + item_bytes
            result += encode_varint(len(key)) + key
            result += encode_varint(len(witness_bytes)) + witness_bytes
        
        # End separator
        result += b'\x00'
        
        return result
    
    @classmethod
    def from_bytes(cls, data, offset=0):
        """Deserialize a PSBTInput from bytes.
        
        Parameters
        ----------
        data : bytes
            The serialized data
        offset : int
            The offset to start reading from
            
        Returns
        -------
        tuple
            (PSBTInput, new_offset)
        """
        psbt_input = cls()
        
        # Read key-value pairs until we hit a separator
        while offset < len(data):
            if data[offset] == 0x00:
                # Separator
                offset += 1
                break
            
            # Read key
            key_len, key_size = parse_compact_size(data[offset:])
            offset += key_size
            key = data[offset:offset+key_len]
            offset += key_len
            
            # Read value
            value_len, value_size = parse_compact_size(data[offset:])
            offset += value_size
            value = data[offset:offset+value_len]
            offset += value_len
            
            # Process key-value pair
            if key[0] == PSBT_IN_NON_WITNESS_UTXO and len(key) == 1:
                # Non-witness UTXO
                psbt_input.non_witness_utxo = Transaction.from_bytes(value)
            elif key[0] == PSBT_IN_WITNESS_UTXO and len(key) == 1:
                # Witness UTXO
                _, new_offset = TxOutput.from_bytes(value, 0)
                psbt_input.witness_utxo = TxOutput.from_bytes(value)[0]
            elif key[0] == PSBT_IN_PARTIAL_SIG and len(key) > 1:
                # Partial signature
                pubkey = key[1:]
                psbt_input.partial_sigs[pubkey] = value
            elif key[0] == PSBT_IN_SIGHASH_TYPE and len(key) == 1:
                # Sighash type
                psbt_input.sighash_type = struct.unpack("<I", value)[0]
            elif key[0] == PSBT_IN_REDEEM_SCRIPT and len(key) == 1:
                # Redeem script
                psbt_input.redeem_script = Script.from_raw(b_to_h(value))
            elif key[0] == PSBT_IN_WITNESS_SCRIPT and len(key) == 1:
                # Witness script
                psbt_input.witness_script = Script.from_raw(b_to_h(value))
            elif key[0] == PSBT_IN_BIP32_DERIVATION and len(key) > 1:
                # BIP32 derivation
                pubkey = key[1:]
                fingerprint = value[:4]
                path = []
                for i in range(4, len(value), 4):
                    path.append(struct.unpack("<I", value[i:i+4])[0])
                psbt_input.bip32_derivations[pubkey] = (fingerprint, path)
            elif key[0] == PSBT_IN_FINAL_SCRIPTSIG and len(key) == 1:
                # Final scriptSig
                psbt_input.final_script_sig = value
            elif key[0] == PSBT_IN_FINAL_SCRIPTWITNESS and len(key) == 1:
                # Final scriptWitness
                witness = []
                witness_offset = 0
                num_items, size = parse_compact_size(value)
                witness_offset += size
                for _ in range(num_items):
                    item_len, size = parse_compact_size(value[witness_offset:])
                    witness_offset += size
                    witness.append(value[witness_offset:witness_offset+item_len])
                    witness_offset += item_len
                psbt_input.final_script_witness = witness
        
        return psbt_input, offset


class PSBTOutput:
    """Represents a Partially Signed Bitcoin Transaction output.
    
    Attributes
    ----------
    redeem_script : Script
        The redeem script (for P2SH)
    witness_script : Script
        The witness script (for P2WSH)
    bip32_derivation : dict
        Dictionary of pubkey -> (fingerprint, path)
    """
    
    def __init__(self):
        """Initialize an empty PSBTOutput."""
        self.redeem_script = None
        self.witness_script = None
        self.bip32_derivation = {}  # Note: singular, not plural!
    
    def add_redeem_script(self, script):
        """Add a redeem script.
        
        Parameters
        ----------
        script : Script
            The redeem script
        """
        self.redeem_script = script
    
    def add_witness_script(self, script):
        """Add a witness script.
        
        Parameters
        ----------
        script : Script
            The witness script
        """
        self.witness_script = script
    
    def add_bip32_derivation(self, pubkey, fingerprint, path):
        """Add a BIP32 derivation path.
        
        Parameters
        ----------
        pubkey : bytes
            The public key
        fingerprint : bytes
            The fingerprint of the master key
        path : list
            The derivation path as a list of integers
        """
        self.bip32_derivation[pubkey] = (fingerprint, path)
    
    def to_bytes(self):
        """Serialize the PSBTOutput to bytes.
        
        Returns
        -------
        bytes
            The serialized PSBTOutput
        """
        result = b''
        
        # Redeem script
        if self.redeem_script:
            key = bytes([PSBT_OUT_REDEEM_SCRIPT]) + b''
            value = self.redeem_script.to_bytes()
            result += encode_varint(len(key)) + key
            result += encode_varint(len(value)) + value
        
        # Witness script
        if self.witness_script:
            key = bytes([PSBT_OUT_WITNESS_SCRIPT]) + b''
            value = self.witness_script.to_bytes()
            result += encode_varint(len(key)) + key
            result += encode_varint(len(value)) + value
        
        # BIP32 derivations
        for pubkey, (fingerprint, path) in self.bip32_derivation.items():
            key = bytes([PSBT_OUT_BIP32_DERIVATION]) + pubkey
            path_bytes = fingerprint
            for idx in path:
                path_bytes += struct.pack("<I", idx)
            result += encode_varint(len(key)) + key
            result += encode_varint(len(path_bytes)) + path_bytes
        
        # End separator
        result += b'\x00'
        
        return result
    
    @classmethod
    def from_bytes(cls, data, offset=0):
        """Deserialize a PSBTOutput from bytes.
        
        Parameters
        ----------
        data : bytes
            The serialized data
        offset : int
            The offset to start reading from
            
        Returns
        -------
        tuple
            (PSBTOutput, new_offset)
        """
        psbt_output = cls()
        
        # Read key-value pairs until we hit a separator
        while offset < len(data):
            if data[offset] == 0x00:
                # Separator
                offset += 1
                break
            
            # Read key
            key_len, key_size = parse_compact_size(data[offset:])
            offset += key_size
            key = data[offset:offset+key_len]
            offset += key_len
            
            # Read value
            value_len, value_size = parse_compact_size(data[offset:])
            offset += value_size
            value = data[offset:offset+value_len]
            offset += value_len
            
            # Process key-value pair
            if key[0] == PSBT_OUT_REDEEM_SCRIPT and len(key) == 1:
                # Redeem script
                psbt_output.redeem_script = Script.from_raw(b_to_h(value))
            elif key[0] == PSBT_OUT_WITNESS_SCRIPT and len(key) == 1:
                # Witness script
                psbt_output.witness_script = Script.from_raw(b_to_h(value))
            elif key[0] == PSBT_OUT_BIP32_DERIVATION and len(key) > 1:
                # BIP32 derivation
                pubkey = key[1:]
                fingerprint = value[:4]
                path = []
                for i in range(4, len(value), 4):
                    path.append(struct.unpack("<I", value[i:i+4])[0])
                psbt_output.bip32_derivation[pubkey] = (fingerprint, path)
        
        return psbt_output, offset


class PSBT:
    """Represents a Partially Signed Bitcoin Transaction.
    
    Attributes
    ----------
    global_tx : Transaction
        The unsigned transaction
    global_xpubs : dict
        Dictionary of xpub -> (fingerprint, path)
    global_version : int
        The PSBT version
    inputs : list[PSBTInput]
        List of PSBT inputs
    outputs : list[PSBTOutput]
        List of PSBT outputs
    """
    
    def __init__(self):
        """Initialize an empty PSBT."""
        self.global_tx = None
        self.global_xpubs = {}
        self.global_version = 0
        self.inputs = []
        self.outputs = []
    
    @classmethod
    def from_transaction(cls, tx):
        """Create a PSBT from an unsigned transaction.
        
        Parameters
        ----------
        tx : Transaction
            The transaction to convert
            
        Returns
        -------
        PSBT
            A new PSBT with the transaction data
        """
        psbt = cls()
        psbt.global_tx = tx
        
        # Add an empty PSBTInput for each transaction input
        for _ in tx.inputs:
            psbt.inputs.append(PSBTInput())
            
        # Add an empty PSBTOutput for each transaction output
        for _ in tx.outputs:
            psbt.outputs.append(PSBTOutput())
            
        return psbt
    
    def add_input(self, psbt_input):
        """Add a PSBTInput to the PSBT.
        
        Parameters
        ----------
        psbt_input : PSBTInput
            The input to add
        """
        self.inputs.append(psbt_input)
    
    def add_output(self, psbt_output):
        """Add a PSBTOutput to the PSBT.
        
        Parameters
        ----------
        psbt_output : PSBTOutput
            The output to add
        """
        self.outputs.append(psbt_output)
    
    def add_global_xpub(self, xpub, fingerprint, path):
        """Add a global xpub to the PSBT.
        
        Parameters
        ----------
        xpub : bytes
            The xpub bytes
        fingerprint : bytes
            The fingerprint of the master key
        path : list
            The derivation path as a list of integers
        """
        self.global_xpubs[xpub] = (fingerprint, path)
    
    def add_input_utxo(self, input_index, utxo_tx=None, witness_utxo=None):
        """Add UTXO information to a specific input.
        
        Parameters
        ----------
        input_index : int
            The index of the input to add the UTXO to
        utxo_tx : Transaction, optional
            The complete transaction containing the UTXO
        witness_utxo : TxOutput, optional
            Only the specific UTXO (for SegWit inputs)
        """
        # Ensure the input exists
        while len(self.inputs) <= input_index:
            self.inputs.append(PSBTInput())
        
        # Add the UTXO information
        if utxo_tx:
            self.inputs[input_index].add_non_witness_utxo(utxo_tx)
        if witness_utxo:
            self.inputs[input_index].add_witness_utxo(witness_utxo)
    
    def add_input_redeem_script(self, input_index, redeem_script):
        """Add a redeem script to a specific input.
        
        Parameters
        ----------
        input_index : int
            The index of the input
        redeem_script : Script
            The redeem script to add
        """
        # Ensure the input exists
        while len(self.inputs) <= input_index:
            self.inputs.append(PSBTInput())
        
        self.inputs[input_index].add_redeem_script(redeem_script)
    
    def sign_input(self, private_key, input_index, redeem_script=None, witness_script=None, sighash=SIGHASH_ALL):
        """Sign a PSBT input with a private key.
        
        Parameters
        ----------
        private_key : PrivateKey
            The private key to sign with
        input_index : int
            The index of the input to sign
        redeem_script : Script, optional
            The redeem script (for P2SH)
        witness_script : Script, optional
            The witness script (for P2WSH)
        sighash : int, optional
            The signature hash type (default is SIGHASH_ALL)
            
        Returns
        -------
        bool
            True if signing was successful, False otherwise
        """
        # Input index validation
        if input_index >= len(self.inputs):
            raise IndexError(f"Input index {input_index} out of range (0-{len(self.inputs)-1})")
        
        # Get the input and UTXO information
        psbt_input = self.inputs[input_index]
        
        # Validate UTXO data presence
        if not psbt_input.non_witness_utxo and not psbt_input.witness_utxo:
            raise ValueError("Cannot sign input without UTXO information")
        
        # Determine what type of input we're signing
        use_segwit = False
        script_code = None
        amount = 0
        
        # Check for witness UTXO (segwit)
        if psbt_input.witness_utxo:
            use_segwit = True
            amount = psbt_input.witness_utxo.amount
            script_pubkey = psbt_input.witness_utxo.script_pubkey
            
            # P2WPKH has a 22-byte script: 0x0014{20-byte key hash}
            script_bytes = script_pubkey.to_bytes()
            if len(script_bytes) == 22 and script_bytes[0] == 0x00 and script_bytes[1] == 0x14:
                # Construct the scriptCode for P2WPKH
                pubkey = private_key.get_public_key()
                script_code = Script(['OP_DUP', 'OP_HASH160', pubkey.to_hash160(), 'OP_EQUALVERIFY', 'OP_CHECKSIG'])
            else:
                # Other segwit types - use witness script if available
                if witness_script:
                    script_code = witness_script
                elif psbt_input.witness_script:
                    script_code = psbt_input.witness_script
                else:
                    return False
                
        elif psbt_input.non_witness_utxo:
            # Legacy input or P2SH-wrapped segwit
            tx_input = self.global_tx.inputs[input_index]
            if tx_input.txout_index >= len(psbt_input.non_witness_utxo.outputs):
                return False
                
            script_pubkey = psbt_input.non_witness_utxo.outputs[tx_input.txout_index].script_pubkey
            amount = psbt_input.non_witness_utxo.outputs[tx_input.txout_index].amount
            
            # Handle regular P2PKH
            if script_pubkey.to_bytes().startswith(b'\x76\xa9'):  # OP_DUP OP_HASH160
                use_segwit = False
                script_code = script_pubkey
            # Handle P2SH (could be wrapped segwit)
            elif script_pubkey.to_bytes().startswith(b'\xa9'):  # OP_HASH160
                if not redeem_script and not psbt_input.redeem_script:
                    return False
                    
                script_code = redeem_script or psbt_input.redeem_script
                
                # Check if this is P2SH-wrapped segwit
                if script_code.to_bytes().startswith(b'\x00\x14'):  # P2SH-P2WPKH
                    use_segwit = True
                    pubkey = private_key.get_public_key()
                    script_code = Script(['OP_DUP', 'OP_HASH160', pubkey.to_hash160(), 'OP_EQUALVERIFY', 'OP_CHECKSIG'])
                elif script_code.to_bytes().startswith(b'\x00\x20'):  # P2SH-P2WSH
                    use_segwit = True
                    if witness_script:
                        script_code = witness_script
                    elif psbt_input.witness_script:
                        script_code = psbt_input.witness_script
                    else:
                        return False
            else:
                # Unknown script type
                return False
        else:
            # No UTXO information
            return False
            
        # Create the signature hash
        if use_segwit:
            sighash_bytes = self.global_tx.get_transaction_segwit_digest(
                input_index,
                script_code,
                amount,
                sighash
            )
        else:
            sighash_bytes = self.global_tx.get_transaction_digest(
                input_index,
                script_code,
                sighash
            )
            
        # Sign the hash
        signature = private_key.sign(sighash_bytes)
        
        # Add the signature to the input
        pubkey_bytes = private_key.get_public_key().to_bytes()
        psbt_input.add_partial_signature(pubkey_bytes, signature)
        psbt_input.add_sighash_type(sighash)
        
        return True
    
    def finalize(self):
        """Finalize all inputs in the PSBT.
        
        Returns
        -------
        bool
            True if all inputs were finalized successfully
        """
        success = True
        for i in range(len(self.inputs)):
            if not self.finalize_input(i):
                success = False
                
        return success
    
    def finalize_input(self, input_index):
        """Finalize a specific input.
        
        Parameters
        ----------
        input_index : int
            The index of the input to finalize
            
        Returns
        -------
        bool
            True if finalization was successful
        """
        if input_index >= len(self.inputs):
            return False
            
        return self.inputs[input_index].finalize()
    
    def extract_transaction(self):
        """Extract the final signed transaction from the PSBT.
        
        Returns
        -------
        Transaction
            The signed transaction
            
        Raises
        ------
        ValueError
            If the PSBT is not finalized
        """
        # Check if all inputs are finalized
        for i, psbt_input in enumerate(self.inputs):
            if not psbt_input.final_script_sig and not psbt_input.final_script_witness:
                raise ValueError(f"Input {i} is not finalized")
        
        # Create a copy of the unsigned transaction
        tx = Transaction.copy(self.global_tx)
        
        # Set scriptSigs and witness data
        use_segwit = False
        for i, psbt_input in enumerate(self.inputs):
            if psbt_input.final_script_sig:
                tx.inputs[i].script_sig = Script.from_raw(b_to_h(psbt_input.final_script_sig))
                
            if psbt_input.final_script_witness:
                use_segwit = True
                if not hasattr(tx, 'witnesses'):
                    tx.witnesses = []
                    while len(tx.witnesses) < len(tx.inputs):
                        tx.witnesses.append([])
                
                # Create witness from witness stack
                witness = psbt_input.final_script_witness
                if isinstance(witness, list):
                    tx.witnesses[i] = witness
                    
        # Set segwit flag
        if use_segwit:
            tx.has_segwit = True
            
        return tx
    
    @classmethod
    def combine(cls, psbts):
        """Combine multiple PSBTs.
        
        Parameters
        ----------
        psbts : list or PSBT
            Either a list of PSBTs to combine or a single other PSBT
            
        Returns
        -------
        PSBT
            The combined PSBT
            
        Raises
        ------
        ValueError
            If the PSBTs have different transactions
        """
        # Check if combining a list or a single PSBT
        if isinstance(psbts, list):
            # List of PSBTs
            if not psbts:
                raise ValueError("Empty list of PSBTs")
                
            # Start with a deep copy of the first PSBT
            first = psbts[0]
            result = cls()
            
            # Copy global data
            result.global_tx = first.global_tx
            result.global_xpubs = dict(first.global_xpubs)
            result.global_version = first.global_version
            
            # Deep copy inputs
            for inp in first.inputs:
                new_input = PSBTInput()
                if hasattr(inp, 'non_witness_utxo'):
                    new_input.non_witness_utxo = inp.non_witness_utxo
                if hasattr(inp, 'witness_utxo'):
                    new_input.witness_utxo = inp.witness_utxo
                if hasattr(inp, 'partial_sigs'):
                    for k, v in inp.partial_sigs.items():
                        new_input.partial_sigs[k] = v
                if hasattr(inp, 'sighash_type'):
                    new_input.sighash_type = inp.sighash_type
                if hasattr(inp, 'redeem_script'):
                    new_input.redeem_script = inp.redeem_script
                if hasattr(inp, 'witness_script'):
                    new_input.witness_script = inp.witness_script
                if hasattr(inp, 'bip32_derivations'):
                    for k, v in inp.bip32_derivations.items():
                        new_input.bip32_derivations[k] = v
                if hasattr(inp, 'final_script_sig'):
                    new_input.final_script_sig = inp.final_script_sig
                if hasattr(inp, 'final_script_witness'):
                    new_input.final_script_witness = inp.final_script_witness
                result.inputs.append(new_input)
                
            # Deep copy outputs
            for out in first.outputs:
                new_output = PSBTOutput()
                if hasattr(out, 'redeem_script'):
                    new_output.redeem_script = out.redeem_script
                if hasattr(out, 'witness_script'):
                    new_output.witness_script = out.witness_script
                if hasattr(out, 'bip32_derivation'):
                    for k, v in out.bip32_derivation.items():
                        new_output.bip32_derivation[k] = v
                result.outputs.append(new_output)
            
            # Combine with other PSBTs
            for psbt in psbts[1:]:
                # Check if transactions are compatible
                if result.global_tx and psbt.global_tx:
                    if hasattr(result.global_tx, 'get_txid') and hasattr(psbt.global_tx, 'get_txid'):
                        if result.global_tx.get_txid() != psbt.global_tx.get_txid():
                            raise ValueError("Cannot combine PSBTs with different transactions")
                
                # Combine inputs
                for i, inp in enumerate(psbt.inputs):
                    # Ensure result has enough inputs
                    while i >= len(result.inputs):
                        result.inputs.append(PSBTInput())
                    
                    # Copy non-witness UTXO if needed
                    if not result.inputs[i].non_witness_utxo and hasattr(inp, 'non_witness_utxo') and inp.non_witness_utxo:
                        result.inputs[i].non_witness_utxo = inp.non_witness_utxo
                    
                    # Copy witness UTXO if needed
                    if not result.inputs[i].witness_utxo and hasattr(inp, 'witness_utxo') and inp.witness_utxo:
                        result.inputs[i].witness_utxo = inp.witness_utxo
                    
                    # Combine partial signatures
                    if hasattr(inp, 'partial_sigs'):
                        for k, v in inp.partial_sigs.items():
                            result.inputs[i].partial_sigs[k] = v
                    
                    # Copy sighash type if needed
                    if not result.inputs[i].sighash_type and hasattr(inp, 'sighash_type') and inp.sighash_type is not None:
                        result.inputs[i].sighash_type = inp.sighash_type
                    
                    # Copy redeem script if needed
                    if not result.inputs[i].redeem_script and hasattr(inp, 'redeem_script') and inp.redeem_script:
                        result.inputs[i].redeem_script = inp.redeem_script
                    
                    # Copy witness script if needed
                    if not result.inputs[i].witness_script and hasattr(inp, 'witness_script') and inp.witness_script:
                        result.inputs[i].witness_script = inp.witness_script
                    
                    # Combine BIP32 derivations
                    if hasattr(inp, 'bip32_derivations'):
                        for k, v in inp.bip32_derivations.items():
                            result.inputs[i].bip32_derivations[k] = v
                    
                    # Copy final script sig if needed
                    if not result.inputs[i].final_script_sig and hasattr(inp, 'final_script_sig') and inp.final_script_sig:
                        result.inputs[i].final_script_sig = inp.final_script_sig
                    
                    # Copy final script witness if needed
                    if not result.inputs[i].final_script_witness and hasattr(inp, 'final_script_witness') and inp.final_script_witness:
                        result.inputs[i].final_script_witness = inp.final_script_witness
                
                # Combine outputs
                for i, out in enumerate(psbt.outputs):
                    # Ensure result has enough outputs
                    while i >= len(result.outputs):
                        result.outputs.append(PSBTOutput())
                    
                    # Copy redeem script if needed
                    if not result.outputs[i].redeem_script and hasattr(out, 'redeem_script') and out.redeem_script:
                        result.outputs[i].redeem_script = out.redeem_script
                    
                    # Copy witness script if needed
                    if not result.outputs[i].witness_script and hasattr(out, 'witness_script') and out.witness_script:
                        result.outputs[i].witness_script = out.witness_script
                    
                    # Combine BIP32 derivations
                    if hasattr(out, 'bip32_derivation'):
                        for k, v in out.bip32_derivation.items():
                            result.outputs[i].bip32_derivation[k] = v
            
            return result
        else:
            # Single PSBT - backward compatibility
            # This handles the case when the method is called as PSBT.combine(other_psbt)
            other = psbts
            result = cls()
            result.global_tx = other.global_tx
            result.global_xpubs = dict(other.global_xpubs)
            result.global_version = other.global_version
            
            # Deep copy inputs
            for inp in other.inputs:
                new_input = PSBTInput()
                if hasattr(inp, 'non_witness_utxo'):
                    new_input.non_witness_utxo = inp.non_witness_utxo
                if hasattr(inp, 'witness_utxo'):
                    new_input.witness_utxo = inp.witness_utxo
                if hasattr(inp, 'partial_sigs'):
                    for k, v in inp.partial_sigs.items():
                        new_input.partial_sigs[k] = v
                if hasattr(inp, 'sighash_type'):
                    new_input.sighash_type = inp.sighash_type
                if hasattr(inp, 'redeem_script'):
                    new_input.redeem_script = inp.redeem_script
                if hasattr(inp, 'witness_script'):
                    new_input.witness_script = inp.witness_script
                if hasattr(inp, 'bip32_derivations'):
                    for k, v in inp.bip32_derivations.items():
                        new_input.bip32_derivations[k] = v
                if hasattr(inp, 'final_script_sig'):
                    new_input.final_script_sig = inp.final_script_sig
                if hasattr(inp, 'final_script_witness'):
                    new_input.final_script_witness = inp.final_script_witness
                result.inputs.append(new_input)
                
            # Deep copy outputs
            for out in other.outputs:
                new_output = PSBTOutput()
                if hasattr(out, 'redeem_script'):
                    new_output.redeem_script = out.redeem_script
                if hasattr(out, 'witness_script'):
                    new_output.witness_script = out.witness_script
                if hasattr(out, 'bip32_derivation'):
                    for k, v in out.bip32_derivation.items():
                        new_output.bip32_derivation[k] = v
                result.outputs.append(new_output)
                
            return result
    
    def to_bytes(self):
        """Serialize the PSBT to bytes.
        
        Returns
        -------
        bytes
            The serialized PSBT
        """
        result = PSBT_MAGIC
        
        # Serialize global data
        if self.global_tx:
            # Unsigned transaction (key type 0x00)
            key = bytes([PSBT_GLOBAL_UNSIGNED_TX])
            tx_bytes = self.global_tx.to_bytes(include_witness=False)
            result += encode_varint(len(key)) + key
            result += encode_varint(len(tx_bytes)) + tx_bytes
            
        # Global xpubs
        for xpub, (fingerprint, path) in self.global_xpubs.items():
            key = bytes([PSBT_GLOBAL_XPUB]) + xpub
            path_bytes = fingerprint
            for idx in path:
                path_bytes += struct.pack("<I", idx)
            result += encode_varint(len(key)) + key
            result += encode_varint(len(path_bytes)) + path_bytes
            
        # Global version
        key = bytes([PSBT_GLOBAL_VERSION])
        version_bytes = struct.pack("<I", self.global_version)
        result += encode_varint(len(key)) + key
        result += encode_varint(len(version_bytes)) + version_bytes
        
        # End of global data
        result += b'\x00'
        
        # Serialize inputs
        for psbt_input in self.inputs:
            result += psbt_input.to_bytes()
            
        # Serialize outputs
        for psbt_output in self.outputs:
            result += psbt_output.to_bytes()
            
        return result
    
    def to_base64(self):
        """Serialize the PSBT to base64.
        
        Returns
        -------
        str
            The base64-encoded PSBT
        """
        return base64.b64encode(self.to_bytes()).decode('ascii')
    
    def to_hex(self):
        """Serialize the PSBT to hex.
        
        Returns
        -------
        str
            The hex-encoded PSBT
        """
        return b_to_h(self.to_bytes())
    
    @classmethod
    def from_bytes(cls, data):
        """Deserialize a PSBT from bytes.
        
        Parameters
        ----------
        data : bytes
            The serialized data
            
        Returns
        -------
        PSBT
            The deserialized PSBT
            
        Raises
        ------
        ValueError
            If the data is not a valid PSBT
        """
        # Check magic bytes
        if not data.startswith(PSBT_MAGIC):
            raise ValueError("Invalid PSBT magic bytes")
            
        # Create empty PSBT
        psbt = cls()
        offset = len(PSBT_MAGIC)
        
        # Parse global data
        while offset < len(data):
            if data[offset] == 0x00:
                # End of global data
                offset += 1
                break
                
            # Read key
            key_len, key_size = parse_compact_size(data[offset:])
            offset += key_size
            key = data[offset:offset+key_len]
            offset += key_len
            
            # Read value
            value_len, value_size = parse_compact_size(data[offset:])
            offset += value_size
            value = data[offset:offset+value_len]
            offset += value_len
            
            # Process key-value pair
            if key[0] == PSBT_GLOBAL_UNSIGNED_TX and len(key) == 1:
                # Unsigned transaction
                psbt.global_tx = Transaction.from_bytes(value)
            elif key[0] == PSBT_GLOBAL_XPUB and len(key) > 1:
                # Global xpub
                xpub = key[1:]
                fingerprint = value[:4]
                path = []
                for i in range(4, len(value), 4):
                    path.append(struct.unpack("<I", value[i:i+4])[0])
                psbt.global_xpubs[xpub] = (fingerprint, path)
            elif key[0] == PSBT_GLOBAL_VERSION and len(key) == 1:
                # Global version
                psbt.global_version = struct.unpack("<I", value)[0]
                
        # Parse inputs
        psbt.inputs = []
        while offset < len(data) and data[offset] != 0x00:
            psbt_input, new_offset = PSBTInput.from_bytes(data, offset)
            psbt.inputs.append(psbt_input)
            offset = new_offset
            
        # Skip separator if present
        if offset < len(data) and data[offset] == 0x00:
            offset += 1
            
        # Parse outputs
        psbt.outputs = []
        while offset < len(data):
            psbt_output, new_offset = PSBTOutput.from_bytes(data, offset)
            psbt.outputs.append(psbt_output)
            offset = new_offset
            
        return psbt
    
    @classmethod
    def from_base64(cls, b64_str):
        """Deserialize a PSBT from base64.
        
        Parameters
        ----------
        b64_str : str
            The base64-encoded PSBT
            
        Returns
        -------
        PSBT
            The deserialized PSBT
        """
        return cls.from_bytes(base64.b64decode(b64_str))
    
    @classmethod
    def from_hex(cls, hex_str):
        """Deserialize a PSBT from hex.
        
        Parameters
        ----------
        hex_str : str
            The hex-encoded PSBT
            
        Returns
        -------
        PSBT
            The deserialized PSBT
        """
        return cls.from_bytes(h_to_b(hex_str))
    
    # This is a patch for the PSBT.extract_transaction method
# Add this to your psbt.py file or apply to the existing method

def extract_transaction(self):
    """Extract the final transaction from a finalized PSBT.
    
    Returns:
        Transaction: The extracted transaction with all signatures applied
    """
    # Check if all inputs are finalized
    for i, input_data in enumerate(self.inputs):
        if not hasattr(input_data, 'final_script_sig') and not hasattr(input_data, 'final_script_witness'):
            raise ValueError(f"Input {i} is not finalized")
    
    # Create a new transaction with the original parameters
    # Explicitly check if we need segwit by examining if any input has witness data
    has_segwit = any(hasattr(inp, 'final_script_witness') and inp.final_script_witness for inp in self.inputs)
    
    tx = Transaction(version=self.tx.version, locktime=self.tx.locktime, has_segwit=has_segwit)
    
    # Copy inputs with final scriptSigs
    for i, input_data in enumerate(self.inputs):
        txin = TxInput(
            self.tx.inputs[i].txid,
            self.tx.inputs[i].txout_index,
            sequence=self.tx.inputs[i].sequence
        )
        
        # Apply final scriptSig if available
        if hasattr(input_data, 'final_script_sig') and input_data.final_script_sig:
            txin.script_sig = Script.from_raw(input_data.final_script_sig)
        
        tx.add_input(txin)
    
    # Copy outputs
    for i, output in enumerate(self.tx.outputs):
        tx.add_output(TxOutput(output.amount, output.script_pubkey))
    
    # Add witness data if available
    if has_segwit:
        tx.witnesses = []
        for i, input_data in enumerate(self.inputs):
            if hasattr(input_data, 'final_script_witness') and input_data.final_script_witness:
                # Parse the witness stack from the final_script_witness
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
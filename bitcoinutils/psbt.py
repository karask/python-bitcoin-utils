"""
Partially Signed Bitcoin Transaction (PSBT) - BIP-174 Implementation

This module provides classes and methods to create, parse, and manipulate
Partially Signed Bitcoin Transactions as defined in BIP-174.

References:
    - BIP-174: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""

from enum import Enum
from typing import Dict, List, Optional, Union, Any

# Magic bytes for PSBT format (hex representation)
PSBT_MAGIC_BYTES = b'\x70\x73\x62\x74'  # "psbt" in ASCII
PSBT_SEPARATOR = b'\xff'  # Separator between maps
PSBT_DEFAULT_VERSION = 0  # Current PSBT version is 0

class PSBTTypeField(Enum):
    """PSBT field types as defined in BIP-174."""
    # Global Types
    UNSIGNED_TX = 0x00
    XPUB = 0x01
    VERSION = 0xfb
    PROPRIETARY = 0xfc
    
    # Input Types
    NON_WITNESS_UTXO = 0x00
    WITNESS_UTXO = 0x01
    PARTIAL_SIG = 0x02
    SIGHASH_TYPE = 0x03
    REDEEM_SCRIPT = 0x04
    WITNESS_SCRIPT = 0x05
    BIP32_DERIVATION = 0x06
    FINAL_SCRIPTSIG = 0x07
    FINAL_SCRIPTWITNESS = 0x08
    POR_COMMITMENT = 0x09
    
    # Output Types
    REDEEM_SCRIPT_OUTPUT = 0x00
    WITNESS_SCRIPT_OUTPUT = 0x01
    BIP32_DERIVATION_OUTPUT = 0x02


class PSBTInput:
    """Class representing a PSBT input with associated data."""

    def __init__(self, tx_input=None):
        """Initialize a PSBT input.
        
        Args:
            tx_input: Related transaction input (optional)
        """
        self.utxo = None  # Non-witness UTXO (complete transaction)
        self.witness_utxo = None  # Witness UTXO (just the output)
        self.partial_sigs = {}  # {pubkey: signature}
        self.sighash_type = None  # Signature hash type if specified
        self.redeem_script = None  # Redeem script for P2SH
        self.witness_script = None  # Witness script for P2WSH
        self.bip32_derivations = {}  # {pubkey: (fingerprint, path)}
        self.final_script_sig = None  # Final scriptSig
        self.final_script_witness = None  # Final scriptWitness
        self.proprietary = {}  # Proprietary fields
        self.unknown = {}  # Unknown fields
        
        # Link to transaction input if provided
        self.tx_input = tx_input


class PSBTOutput:
    """Class representing a PSBT output with associated data."""

    def __init__(self, tx_output=None):
        """Initialize a PSBT output.
        
        Args:
            tx_output: Related transaction output (optional)
        """
        self.redeem_script = None  # Redeem script
        self.witness_script = None  # Witness script
        self.bip32_derivations = {}  # {pubkey: (fingerprint, path)}
        self.proprietary = {}  # Proprietary fields
        self.unknown = {}  # Unknown fields
        
        # Link to transaction output if provided
        self.tx_output = tx_output


class PSBT:
    """Class representing a Partially Signed Bitcoin Transaction."""

    def __init__(self, tx=None):
        """Initialize a new PSBT object.
        
        Args:
            tx: The unsigned transaction this PSBT is based on (optional)
        """
        self.version = PSBT_DEFAULT_VERSION
        self.tx = tx  # Unsigned transaction
        self.inputs = []  # List of PSBTInput objects
        self.outputs = []  # List of PSBTOutput objects
        self.xpubs = {}  # Extended public keys: {xpub: (master_fingerprint, derivation_path)}
        self.proprietary = {}  # Proprietary fields
        self.unknown = {}  # Unknown fields

        # Initialize inputs and outputs based on transaction if provided
        if tx:
            for tx_in in tx.inputs:
                self.inputs.append(PSBTInput(tx_in))
            
            for tx_out in tx.outputs:
                self.outputs.append(PSBTOutput(tx_out))

    # Serialization methods will be implemented in future PRs
"""
Partially Signed Bitcoin Transaction (PSBT) implementation following
BIP-174.

This module provides the PSBT class which represents a partially signed
bitcoin transaction that can be shared between multiple parties for signing
before broadcasting to the network.

A PSBT contains:
- The unsigned transaction
- Input metadata needed for signing (UTXOs, scripts, keys, etc.)
- Output metadata for validation
- Partial signatures from different signers

The PSBT workflow typically involves:
1. Creator: Creates the PSBT with the unsigned transaction
2. Updater: Adds input/output metadata needed for signing
3. Signer: Signs inputs they can sign (sign_input() handles all script types automatically)
4. Combiner: Combines multiple PSBTs with different signatures
5. Finalizer: Finalizes the PSBT by adding final scriptSig/witness
6. Extractor: Extracts the final signed transaction
"""

import struct
from io import BytesIO
from typing import Dict, List, Optional, Tuple, Union
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.script import Script
from bitcoinutils.keys import PrivateKey, PublicKey
from bitcoinutils.utils import to_satoshis

class PSBTInput:
    """
    Represents a single input in a PSBT with all associated metadata.

    Contains information needed to sign this input including:
    - Non-witness UTXO (for legacy inputs)
    - Witness UTXO (for segwit inputs)
    - Partial signatures
    - Sighash type
    - Redeem script (for P2SH)
    - Witness script (for P2WSH)
    - BIP32 derivation paths
    - Final scriptSig and witness
    """

    def __init__(self):
        # BIP-174 defined fields
        self.non_witness_utxo: Optional[Transaction] = None
        self.witness_utxo: Optional[TxOutput] = None
        self.partial_sigs: Dict[bytes, bytes] = {}  # pubkey -> signature
        self.sighash_type: Optional[int] = None
        self.redeem_script: Optional[Script] = None
        self.witness_script: Optional[Script] = None
        self.bip32_derivs: Dict[bytes, Tuple[bytes, List[int]]] = {}  # pubkey -> (fingerprint, path)
        self.final_scriptsig: Optional[Script] = None
        self.final_scriptwitness: List[bytes] = []

        # Additional fields for validation
        self.ripemd160_preimages: Dict[bytes, bytes] = {}
        self.sha256_preimages: Dict[bytes, bytes] = {}
        self.hash160_preimages: Dict[bytes, bytes] = {}
        self.hash256_preimages: Dict[bytes, bytes] = {}

        # Proprietary fields
        self.proprietary: Dict[bytes, bytes] = {}
        self.unknown: Dict[bytes, bytes] = {}

class PSBTOutput:
    """
    Represents a single output in a PSBT with associated metadata.

    Contains information about the output including:
    - Redeem script (for P2SH outputs)
    - Witness script (for P2WSH outputs)
    - BIP32 derivation paths
    """

    def __init__(self):
        # BIP-174 defined fields
        self.redeem_script: Optional[Script] = None
        self.witness_script: Optional[Script] = None
        self.bip32_derivs: Dict[bytes, Tuple[bytes, List[int]]] = {}  # pubkey -> (fingerprint, path)

        # Proprietary fields
        self.proprietary: Dict[bytes, bytes] = {}
        self.unknown: Dict[bytes, bytes] = {}

class PSBT:
    """
    Partially Signed Bitcoin Transaction implementation following BIP-174.

    A PSBT is a data format that allows multiple parties to collaboratively
    sign a bitcoin transaction. The PSBT contains the unsigned transaction
    along with metadata needed for signing.

    Example usage:
    # Create PSBT from unsigned transaction
    psbt = PSBT(unsigned_tx)

    # Add input metadata
    psbt.inputs[0].witness_utxo = prev_output

    # Sign with private key (automatically detects script type)
    psbt.sign_input(0, private_key)

    # Finalize and extract signed transaction
    final_tx = psbt.finalize()
    """

    # PSBT magic bytes and version
    MAGIC = b'psbt'
    VERSION = 0

    # Key types as defined in BIP-174
    class GlobalTypes:
        UNSIGNED_TX = 0x00
        XPUB = 0x01
        VERSION = 0xFB
        PROPRIETARY = 0xFC

    class InputTypes:
        NON_WITNESS_UTXO = 0x00
        WITNESS_UTXO = 0x01
        PARTIAL_SIG = 0x02
        SIGHASH_TYPE = 0x03
        REDEEM_SCRIPT = 0x04
        WITNESS_SCRIPT = 0x05
        BIP32_DERIVATION = 0x06
        FINAL_SCRIPTSIG = 0x07
        FINAL_SCRIPTWITNESS = 0x08
        RIPEMD160 = 0x0A
        SHA256 = 0x0B
        HASH160 = 0x0C
        HASH256 = 0x0D
        PROPRIETARY = 0xFC

    class OutputTypes:
        REDEEM_SCRIPT = 0x00
        WITNESS_SCRIPT = 0x01
        BIP32_DERIVATION = 0x02
        PROPRIETARY = 0xFC

    def __init__(self, unsigned_tx: Optional[Transaction] = None):
        """
        Initialize a new PSBT.

        Args:
            unsigned_tx: The unsigned transaction. If None, an empty transaction is created.
        """
        if unsigned_tx is None:
            # Create empty transaction
            self.tx = Transaction([], [])
        else:
            # Ensure transaction has no scripts/witnesses (must be unsigned)
            inputs = []
            for tx_input in unsigned_tx.inputs:
                # Create input without scriptSig
                clean_input = TxInput(tx_input.txid, tx_input.txout_index)
                inputs.append(clean_input)

            self.tx = Transaction(inputs, unsigned_tx.outputs[:], unsigned_tx.locktime, unsigned_tx.version)

        # Initialize PSBT-specific data
        self.inputs: List[PSBTInput] = [PSBTInput() for _ in self.tx.inputs]
        self.outputs: List[PSBTOutput] = [PSBTOutput() for _ in self.tx.outputs]

        # Global fields
        self.version = self.VERSION
        self.xpubs: Dict[bytes, Tuple[bytes, List[int]]] = {}  # xpub -> (fingerprint, path)
        self.proprietary: Dict[bytes, bytes] = {}
        self.unknown: Dict[bytes, bytes] = {}

    @classmethod
    def from_base64(cls, psbt_str: str) -> 'PSBT':
        """
        Create PSBT from base64 encoded string.

        Args:
            psbt_str: Base64 encoded PSBT

        Returns:
            PSBT object
        """
        import base64
        psbt_bytes = base64.b64decode(psbt_str)
        return cls.from_bytes(psbt_bytes)

    @classmethod
    def from_bytes(cls, psbt_bytes: bytes) -> 'PSBT':
        """
        Deserialize PSBT from bytes.

        Args:
            psbt_bytes: Serialized PSBT bytes

        Returns:
            PSBT object
        """
        stream = BytesIO(psbt_bytes)

        # Read and verify magic
        magic = stream.read(4)
        if magic != cls.MAGIC:
            raise ValueError(f"Invalid PSBT magic: {magic.hex()}")

        # Read separator
        separator = stream.read(1)
        if separator != b'\xff':
            raise ValueError("Invalid PSBT separator")

        # Parse global section
        psbt = cls()
        psbt._parse_global_section(stream)

        # Parse input sections
        for i in range(len(psbt.tx.inputs)):
            psbt._parse_input_section(stream, i)

        # Parse output sections
        for i in range(len(psbt.tx.outputs)):
            psbt._parse_output_section(stream, i)

        return psbt

    def to_base64(self) -> str:
        """
        Serialize PSBT to base64 string.

        Returns:
            Base64 encoded PSBT
        """
        import base64
        return base64.b64encode(self.to_bytes()).decode('ascii')

    def to_bytes(self) -> bytes:
        """
        Serialize PSBT to bytes.

        Returns:
            Serialized PSBT bytes
        """
        result = BytesIO()

        # Write magic and separator
        result.write(self.MAGIC)
        result.write(b'\xff')

        # Write global section
        self._serialize_global_section(result)

        # Write input sections
        for i, psbt_input in enumerate(self.inputs):
            self._serialize_input_section(result, i)

        # Write output sections
        for i, psbt_output in enumerate(self.outputs):
            self._serialize_output_section(result, i)

        return result.getvalue()

    def add_input(self, tx_input: TxInput, psbt_input: Optional[PSBTInput] = None) -> None:
        """
        Add input to the PSBT transaction.

        Args:
            tx_input: Transaction input to add
            psbt_input: PSBT input metadata. If None, empty metadata is created.
        """
        # Create clean input without scriptSig
        clean_input = TxInput(tx_input.txid, tx_input.txout_index)
        self.tx.inputs.append(clean_input)

        if psbt_input is None:
            psbt_input = PSBTInput()
        self.inputs.append(psbt_input)

    def add_output(self, tx_output: TxOutput, psbt_output: Optional[PSBTOutput] = None) -> None:
        """
        Add output to the PSBT transaction.

        Args:
            tx_output: Transaction output to add
            psbt_output: PSBT output metadata. If None, empty metadata is created.
        """
        self.tx.outputs.append(tx_output)

        if psbt_output is None:
            psbt_output = PSBTOutput()
        self.outputs.append(psbt_output)

    def sign(self, private_key: PrivateKey, input_index: int, sighash_type: int = 1) -> bool:
        """
        Legacy method for backward compatibility. Use sign_input() instead.

        Args:
            private_key: Private key to sign with
            input_index: Index of input to sign
            sighash_type: Signature hash type (default: SIGHASH_ALL)

        Returns:
            True if signature was added, False if input couldn't be signed
        """
        return self.sign_input(input_index, private_key, sighash_type)

    def sign_input(self, input_index: int, private_key: PrivateKey, sighash_type: int = 1) -> bool:
        """
        Sign a specific input with the given private key.

        Automatically detects the script type and uses appropriate signing method:
        - P2PKH: Legacy pay-to-public-key-hash
        - P2SH: Pay-to-script-hash (including nested SegWit)
        - P2WPKH: Native SegWit pay-to-witness-public-key-hash
        - P2WSH: Native SegWit pay-to-witness-script-hash
        - P2TR: Taproot pay-to-taproot

        Args:
            input_index: Index of input to sign
            private_key: Private key to sign with
            sighash_type: Signature hash type (default: SIGHASH_ALL)

        Returns:
            True if signature was added, False if input couldn't be signed
        """
        try:
            # Validate input index
            if input_index >= len(self.inputs):
                return False

            input_data = self.inputs[input_index]
            tx_input = self.tx.inputs[input_index]

            # Get the appropriate signature for this input
            signature = self._get_signature_for_input(input_index, private_key, sighash_type)

            if signature:
                # Add the signature to the PSBT
                public_key_bytes = private_key.get_public_key().to_bytes()
                input_data.partial_sigs[public_key_bytes] = signature

                # Set sighash type if not already set
                if input_data.sighash_type is None:
                    input_data.sighash_type = sighash_type

                return True
            else:
                return False

        except Exception:
            return False

    def _get_signature_for_input(self, input_index: int, private_key: PrivateKey, sighash_type: int) -> bytes:
        """
        Get the appropriate signature for an input based on its script type.

        Args:
            input_index: Input index
            private_key: Private key to sign with
            sighash_type: Signature hash type

        Returns:
            bytes: Signature if successful, None otherwise
        """
        input_data = self.inputs[input_index]
        tx_input = self.tx.inputs[input_index]

        try:
            if input_data.redeem_script:
                # P2SH-P2WSH or P2SH-P2WPKH or regular P2SH
                redeem_script = input_data.redeem_script

                # Check if it's a P2SH-wrapped SegWit
                if input_data.witness_script:
                    # P2SH-P2WSH
                    witness_script = input_data.witness_script
                    if input_data.witness_utxo:
                        amount = to_satoshis(input_data.witness_utxo.amount)
                        return private_key.sign_segwit_input(self.tx, input_index, witness_script, amount, sighash_type)

                elif self._is_p2wpkh_script(redeem_script):
                    # P2SH-P2WPKH
                    if input_data.witness_utxo:
                        amount = to_satoshis(input_data.witness_utxo.amount)
                        p2pkh_script = private_key.get_public_key().get_address().to_script_pub_key()
                        return private_key.sign_segwit_input(self.tx, input_index, p2pkh_script, amount, sighash_type)

                else:
                    # Regular P2SH
                    return private_key.sign_input(self.tx, input_index, redeem_script, sighash_type)

            elif input_data.witness_script:
                # P2WSH input
                witness_script = input_data.witness_script
                if input_data.witness_utxo:
                    amount = to_satoshis(input_data.witness_utxo.amount)
                    return private_key.sign_segwit_input(self.tx, input_index, witness_script, amount, sighash_type)

            elif input_data.witness_utxo:
                # Check if it's P2WPKH or P2TR
                script_pubkey = input_data.witness_utxo.script_pubkey
                amount = to_satoshis(input_data.witness_utxo.amount)

                if self._is_p2wpkh_script(script_pubkey):
                    # P2WPKH input
                    p2pkh_script = private_key.get_public_key().get_address().to_script_pub_key()
                    return private_key.sign_segwit_input(self.tx, input_index, p2pkh_script, amount, sighash_type)

                elif self._is_p2tr_script(script_pubkey):
                    # P2TR input
                    return private_key.sign_taproot_input(self.tx, input_index, amount, sighash_type)

            elif input_data.non_witness_utxo:
                # Legacy P2PKH or P2SH
                prev_tx_out = input_data.non_witness_utxo.outputs[tx_input.txout_index]
                script_pubkey = prev_tx_out.script_pubkey

                if self._is_p2pkh_script(script_pubkey):
                    # P2PKH input
                    return private_key.sign_input(self.tx, input_index, script_pubkey, sighash_type)

            return None

        except Exception:
            return None

    def _is_p2pkh_script(self, script) -> bool:
        """Check if script is P2PKH (OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG)."""
        try:
            return script.is_p2pkh() if hasattr(script, 'is_p2pkh') else False
        except:
            return False

    def _is_p2wpkh_script(self, script) -> bool:
        """Check if script is P2WPKH (OP_0 <20-byte-pubkeyhash>)."""
        try:
            return script.is_p2wpkh() if hasattr(script, 'is_p2wpkh') else False
        except:
            return False

    def _is_p2tr_script(self, script) -> bool:
        """Check if script is P2TR (OP_1 <32-byte-taproot-output>)."""
        try:
            return script.is_p2tr() if hasattr(script, 'is_p2tr') else False
        except:
            return False

    def _is_input_finalized(self, input_data: PSBTInput) -> bool:
        """
        Check if an input is already finalized.
        
        Args:
            input_data: PSBT input to check
            
        Returns:
            True if input is finalized
        """
        return bool(input_data.final_scriptsig or input_data.final_scriptwitness)

    def _apply_final_fields(self, tx_input: TxInput, input_data: PSBTInput) -> None:
        """
        Apply final scriptSig and witness to a transaction input.
        
        Args:
            tx_input: Transaction input to modify
            input_data: PSBT input with final fields
        """
        if input_data.final_scriptsig:
            tx_input.script_sig = input_data.final_scriptsig
        else:
            tx_input.script_sig = Script([])

    def _validate_final_tx(self, tx: Transaction) -> Dict[str, any]:
        """
        Validate a finalized transaction.
        
        Args:
            tx: Transaction to validate
            
        Returns:
            Dictionary with validation results
        """
        validation_info = {
            'is_valid': True,
            'errors': [],
            'warnings': []
        }

        # Basic validation
        if not tx.inputs:
            validation_info['is_valid'] = False
            validation_info['errors'].append("Transaction has no inputs")

        if not tx.outputs:
            validation_info['is_valid'] = False
            validation_info['errors'].append("Transaction has no outputs")

        # Check for empty scripts where they shouldn't be
        for i, (tx_input, psbt_input) in enumerate(zip(tx.inputs, self.inputs)):
            if not tx_input.script_sig and not psbt_input.final_scriptwitness:
                validation_info['warnings'].append(f"Input {i} has empty scriptSig and witness")

        return validation_info

    def combine(self, other: 'PSBT') -> 'PSBT':
        """
        Combine this PSBT with another PSBT (combiner role).
        
        Args:
            other: Another PSBT to combine with
            
        Returns:
            New combined PSBT
        """
        # Ensure both PSBTs have the same unsigned transaction
        if self.tx.serialize() != other.tx.serialize():
            raise ValueError("Cannot combine PSBTs with different transactions")
        
        # Create new PSBT with combined data
        combined = PSBT(self.tx)
        
        # Combine global data
        combined.xpubs.update(self.xpubs)
        combined.xpubs.update(other.xpubs)
        combined.proprietary.update(self.proprietary)
        combined.proprietary.update(other.proprietary)
        combined.unknown.update(self.unknown)
        combined.unknown.update(other.unknown)
        
        # Combine input data
        for i, (input1, input2) in enumerate(zip(self.inputs, other.inputs)):
            combined_input = combined.inputs[i]
            
            # Combine UTXOs (prefer witness_utxo)
            if input1.witness_utxo:
                combined_input.witness_utxo = input1.witness_utxo
            elif input2.witness_utxo:
                combined_input.witness_utxo = input2.witness_utxo
            elif input1.non_witness_utxo:
                combined_input.non_witness_utxo = input1.non_witness_utxo
            elif input2.non_witness_utxo:
                combined_input.non_witness_utxo = input2.non_witness_utxo
            
            # Combine partial signatures
            combined_input.partial_sigs.update(input1.partial_sigs)
            combined_input.partial_sigs.update(input2.partial_sigs)
            
            # Combine other fields
            combined_input.sighash_type = input1.sighash_type or input2.sighash_type
            combined_input.redeem_script = input1.redeem_script or input2.redeem_script
            combined_input.witness_script = input1.witness_script or input2.witness_script
            combined_input.bip32_derivs.update(input1.bip32_derivs)
            combined_input.bip32_derivs.update(input2.bip32_derivs)
            
            # Final scripts (should be same or one empty)
            combined_input.final_scriptsig = input1.final_scriptsig or input2.final_scriptsig
            if input1.final_scriptwitness:
                combined_input.final_scriptwitness = input1.final_scriptwitness
            elif input2.final_scriptwitness:
                combined_input.final_scriptwitness = input2.final_scriptwitness
            
            # Combine preimages and proprietary data
            combined_input.ripemd160_preimages.update(input1.ripemd160_preimages)
            combined_input.ripemd160_preimages.update(input2.ripemd160_preimages)
            combined_input.sha256_preimages.update(input1.sha256_preimages)
            combined_input.sha256_preimages.update(input2.sha256_preimages)
            combined_input.hash160_preimages.update(input1.hash160_preimages)
            combined_input.hash160_preimages.update(input2.hash160_preimages)
            combined_input.hash256_preimages.update(input1.hash256_preimages)
            combined_input.hash256_preimages.update(input2.hash256_preimages)
            combined_input.proprietary.update(input1.proprietary)
            combined_input.proprietary.update(input2.proprietary)
            combined_input.unknown.update(input1.unknown)
            combined_input.unknown.update(input2.unknown)
        
        # Combine output data
        for i, (output1, output2) in enumerate(zip(self.outputs, other.outputs)):
            combined_output = combined.outputs[i]
            combined_output.redeem_script = output1.redeem_script or output2.redeem_script
            combined_output.witness_script = output1.witness_script or output2.witness_script
            combined_output.bip32_derivs.update(output1.bip32_derivs)
            combined_output.bip32_derivs.update(output2.bip32_derivs)
            combined_output.proprietary.update(output1.proprietary)
            combined_output.proprietary.update(output2.proprietary)
            combined_output.unknown.update(output1.unknown)
            combined_output.unknown.update(output2.unknown)
        
        return combined

    def combine_psbts(self, other_psbts: List['PSBT']) -> 'PSBT':
        """
        Combine this PSBT with multiple other PSBTs.

        Wraps the pairwise `combine()` method in a loop for batch combining.

        Args:
            other_psbts (List[PSBT]): A list of PSBTs to combine

        Returns:
            PSBT: The final combined PSBT
        """
        combined = self
        for other in other_psbts:
            combined = combined.combine(other)
        return combined

    def finalize(self, validate: bool = False) -> Union[Transaction, Tuple[Transaction, Dict], bool]:
        """
        Finalize all inputs and create the final broadcastable transaction or check if all inputs are finalized.

        If called with validate=False and no additional arguments, returns a boolean indicating if all inputs were finalized successfully.
        If called with validate=True or no arguments, builds a complete Transaction object with all final scriptSigs and witnesses.

        Args:
            validate: If True, validate the final transaction and return validation info

        Returns:
            If validate=False: Transaction object ready for broadcast or boolean if simple finalize
            If validate=True: Tuple of (Transaction, validation_info dict)

        Raises:
            ValueError: If not all inputs can be finalized
        """
        # Simple finalize returning boolean
        if not validate:
            all_finalized = True
            for i in range(len(self.inputs)):
                if not self._finalize_input(i):
                    all_finalized = False
            return all_finalized

        # Existing finalize logic from Untitled document-10.docx
        finalized_count = 0
        for i in range(len(self.inputs)):
            if self._finalize_input(i):
                finalized_count += 1

        if finalized_count != len(self.inputs):
            raise ValueError(f"Could not finalize all inputs. Finalized: {finalized_count}/{len(self.inputs)}")

        final_inputs = []
        for i, (tx_input, psbt_input) in enumerate(zip(self.tx.inputs, self.inputs)):
            final_input = TxInput(
                tx_input.txid,
                tx_input.txout_index,
                psbt_input.final_scriptsig or Script([]),
                tx_input.sequence
            )
            final_inputs.append(final_input)

        final_tx = Transaction(
            final_inputs,
            self.tx.outputs[:],
            self.tx.locktime,
            self.tx.version
        )

        final_tx.witnesses = []
        for psbt_input in self.inputs:
            if psbt_input.final_scriptwitness:
                final_tx.witnesses.append(psbt_input.final_scriptwitness)
            else:
                final_tx.witnesses.append([])

        if validate:
            validation_info = self._validate_final_tx(final_tx)
            return final_tx, validation_info
        else:
            return final_tx

    def finalize_input(self, input_index: int) -> bool:
        """
        Finalize a specific input by constructing final scriptSig and witness.

        Args:
            input_index: Index of input to finalize

        Returns:
            True if input was finalized successfully
        """
        if input_index >= len(self.inputs):
            raise ValueError(f"Input index {input_index} out of range")

        return self._finalize_input(input_index)

    def _finalize_input(self, input_index: int) -> bool:
        """
        Enhanced input finalization with better script type detection.
        
        Args:
            input_index: Index of input to finalize
            
        Returns:
            True if input was finalized successfully
        """
        psbt_input = self.inputs[input_index]

        # Skip if already finalized
        if self._is_input_finalized(psbt_input):
            return True

        # Need partial signatures to finalize
        if not psbt_input.partial_sigs:
            return False

        # Get UTXO info
        if psbt_input.witness_utxo:
            prev_output = psbt_input.witness_utxo
            script_pubkey = prev_output.script_pubkey
        elif psbt_input.non_witness_utxo:
            prev_vout = self.tx.inputs[input_index].txout_index
            prev_output = psbt_input.non_witness_utxo.outputs[prev_vout]
            script_pubkey = prev_output.script_pubkey
        else:
            return False

        # Handle different script types with improved detection
        try:
            if script_pubkey.is_p2pkh():
                return self._finalize_p2pkh(psbt_input)
            elif script_pubkey.is_p2wpkh():
                return self._finalize_p2wpkh(psbt_input)
            elif script_pubkey.is_p2sh():
                return self._finalize_p2sh(psbt_input)
            elif script_pubkey.is_p2wsh():
                return self._finalize_p2wsh(psbt_input)
            elif self._is_p2tr_script(script_pubkey):
                return self._finalize_p2tr(psbt_input)
        except Exception:
            pass

        return False

    def _finalize_p2pkh(self, psbt_input: PSBTInput) -> bool:
        """Finalize P2PKH input."""
        if len(psbt_input.partial_sigs) != 1:
            return False

        pubkey, signature = next(iter(psbt_input.partial_sigs.items()))
        psbt_input.final_scriptsig = Script([signature, pubkey])
        return True

    def _finalize_p2wpkh(self, psbt_input: PSBTInput) -> bool:
        """Finalize P2WPKH input."""
        if len(psbt_input.partial_sigs) != 1:
            return False

        pubkey, signature = next(iter(psbt_input.partial_sigs.items()))
        psbt_input.final_scriptsig = Script([])
        psbt_input.final_scriptwitness = [signature, pubkey]
        return True

    def _finalize_p2sh(self, psbt_input: PSBTInput) -> bool:
        """Finalize P2SH input with support for nested SegWit."""
        if not psbt_input.redeem_script:
            return False

        redeem_script = psbt_input.redeem_script

        # Handle P2SH-wrapped SegWit
        if redeem_script.is_p2wpkh():
            return self._finalize_p2sh_p2wpkh(psbt_input)
        elif redeem_script.is_p2wsh():
            return self._finalize_p2sh_p2wsh(psbt_input)
        else:
            # Regular P2SH
            success = self._finalize_script(psbt_input, redeem_script, is_witness=False)
            if success:
                # Add redeem script to the end of scriptSig
                current_elements = psbt_input.final_scriptsig.script if psbt_input.final_scriptsig else []
                psbt_input.final_scriptsig = Script(current_elements + [redeem_script.to_bytes()])
            return success

    def _finalize_p2sh_p2wpkh(self, psbt_input: PSBTInput) -> bool:
        """Finalize P2SH-wrapped P2WPKH input."""
        if len(psbt_input.partial_sigs) != 1:
            return False

        pubkey, signature = next(iter(psbt_input.partial_sigs.items()))
        
        # scriptSig contains just the redeem script
        psbt_input.final_scriptsig = Script([psbt_input.redeem_script.to_bytes()])
        # Witness contains signature and pubkey
        psbt_input.final_scriptwitness = [signature, pubkey]
        return True

    def _finalize_p2sh_p2wsh(self, psbt_input: PSBTInput) -> bool:
        """Finalize P2SH-wrapped P2WSH input."""
        if not psbt_input.witness_script:
            return False

        # Finalize the witness script part
        success = self._finalize_script(psbt_input, psbt_input.witness_script, is_witness=True)
        if success:
            # Add the redeem script to scriptSig
            psbt_input.final_scriptsig = Script([psbt_input.redeem_script.to_bytes()])
            # Add witness script to the end of witness
            psbt_input.final_scriptwitness.append(psbt_input.witness_script.to_bytes())
        return success

    def _finalize_p2wsh(self, psbt_input: PSBTInput) -> bool:
        """Finalize P2WSH input."""
        if not psbt_input.witness_script:
            return False

        return self._finalize_script(psbt_input, psbt_input.witness_script, is_witness=True)

    def _finalize_p2tr(self, psbt_input: PSBTInput) -> bool:
        """Finalize P2TR (Taproot) input."""
        if len(psbt_input.partial_sigs) != 1:
            return False

        # For key-path spending, we expect a single signature
        signature = next(iter(psbt_input.partial_sigs.values()))
        psbt_input.final_scriptsig = Script([])
        psbt_input.final_scriptwitness = [signature]
        return True

    def _finalize_script(self, psbt_input: PSBTInput, script: Script, is_witness: bool) -> bool:
        """
        Enhanced script finalization with better multisig support.
        
        Args:
            psbt_input: PSBT input to finalize
            script: Script to finalize against
            is_witness: Whether this is a witness script
            
        Returns:
            True if finalized successfully
        """
        script_ops = script.script
        
        # Enhanced multisig detection and handling
        if (len(script_ops) >= 4 and
            isinstance(script_ops[0], int) and 1 <= script_ops[0] <= 16 and
            isinstance(script_ops[-2], int) and 1 <= script_ops[-2] <= 16 and
            script_ops[-1] == 174):  # OP_CHECKMULTISIG
            
            m = script_ops[0]  # Required signatures
            n = script_ops[-2]  # Total pubkeys
            
            # Extract public keys from script
            pubkeys = []
            for i in range(1, n + 1):
                if i < len(script_ops) and isinstance(script_ops[i], bytes):
                    pubkeys.append(script_ops[i])
            
            # Collect signatures in the correct order
            signatures = []
            valid_sig_count = 0
            
            for pubkey in pubkeys:
                if pubkey in psbt_input.partial_sigs:
                    signatures.append(psbt_input.partial_sigs[pubkey])
                    valid_sig_count += 1
                else:
                    signatures.append(b'')  # Placeholder for missing signature
                
                if valid_sig_count >= m:
                    break
            
            # Check if we have enough signatures
            if valid_sig_count < m:
                return False
            
            # Trim signatures to required amount, keeping only valid ones
            final_sigs = []
            sig_count = 0
            for sig in signatures:
                if sig and sig_count < m:
                    final_sigs.append(sig)
                    sig_count += 1
            
            # Multisig requires OP_0 prefix due to Bitcoin's off-by-one bug
            final_script_elements = [b''] + final_sigs
            
            if is_witness:
                final_script_elements.append(script.to_bytes())
                psbt_input.final_scriptsig = Script([])
                psbt_input.final_scriptwitness = final_script_elements
            else:
                final_script_elements.append(script.to_bytes())
                psbt_input.final_scriptsig = Script(final_script_elements)
            
            return True
        
        # Handle single-sig scripts (P2PK, custom scripts, etc.)
        elif len(psbt_input.partial_sigs) == 1:
            pubkey, signature = next(iter(psbt_input.partial_sigs.items()))
            
            if is_witness:
                psbt_input.final_scriptsig = Script([])
                psbt_input.final_scriptwitness = [signature, pubkey, script.to_bytes()]
            else:
                psbt_input.final_scriptsig = Script([signature, pubkey, script.to_bytes()])
            
            return True
        
        # Handle other script types (can be extended)
        return False

    def _parse_global_section(self, stream: BytesIO) -> None:
        """Parse the global section of a PSBT."""
        while True:
            # Read key-value pair
            key_data = self._read_key_value_pair(stream)
            if key_data is None:
                break
            
            key_type, key_data, value_data = key_data
            
            if key_type == self.GlobalTypes.UNSIGNED_TX:
                self.tx = Transaction.from_bytes(value_data)
                # Initialize input/output arrays
                self.inputs = [PSBTInput() for _ in self.tx.inputs]
                self.outputs = [PSBTOutput() for _ in self.tx.outputs]
            elif key_type == self.GlobalTypes.XPUB:
                fingerprint_path = struct.unpack('<I', key_data[:4])[0], list(struct.unpack('<' + 'I' * ((len(key_data) - 4) // 4), key_data[4:]))
                self.xpubs[value_data] = fingerprint_path
            elif key_type == self.GlobalTypes.VERSION:
                self.version = struct.unpack('<I', value_data)[0]
            elif key_type == self.GlobalTypes.PROPRIETARY:
                self.proprietary[key_data] = value_data
            else:
                self.unknown[key_data] = value_data

    def _parse_input_section(self, stream: BytesIO, input_index: int) -> None:
        """Parse an input section of a PSBT."""
        psbt_input = self.inputs[input_index]
        
        while True:
            key_data = self._read_key_value_pair(stream)
            if key_data is None:
                break
            
            key_type, key_data, value_data = key_data
            
            if key_type == self.InputTypes.NON_WITNESS_UTXO:
                psbt_input.non_witness_utxo = Transaction.from_bytes(value_data)
            elif key_type == self.InputTypes.WITNESS_UTXO:
                psbt_input.witness_utxo = TxOutput.from_bytes(value_data)
            elif key_type == self.InputTypes.PARTIAL_SIG:
                psbt_input.partial_sigs[key_data] = value_data
            elif key_type == self.InputTypes.SIGHASH_TYPE:
                psbt_input.sighash_type = struct.unpack('<I', value_data)[0]
            elif key_type == self.InputTypes.REDEEM_SCRIPT:
                psbt_input.redeem_script = Script.from_bytes(value_data)
            elif key_type == self.InputTypes.WITNESS_SCRIPT:
                psbt_input.witness_script = Script.from_bytes(value_data)
            elif key_type == self.InputTypes.BIP32_DERIVATION:
                fingerprint = struct.unpack('<I', value_data[:4])[0]
                path = list(struct.unpack('<' + 'I' * ((len(value_data) - 4) // 4), value_data[4:]))
                psbt_input.bip32_derivs[key_data] = (fingerprint, path)
            elif key_type == self.InputTypes.FINAL_SCRIPTSIG:
                psbt_input.final_scriptsig = Script.from_bytes(value_data)
            elif key_type == self.InputTypes.FINAL_SCRIPTWITNESS:
                # Parse witness stack
                witness_stack = []
                offset = 0
                while offset < len(value_data):
                    item_len = value_data[offset]
                    offset += 1
                    witness_stack.append(value_data[offset:offset + item_len])
                    offset += item_len
                psbt_input.final_scriptwitness = witness_stack
            elif key_type == self.InputTypes.RIPEMD160:
                psbt_input.ripemd160_preimages[key_data] = value_data
            elif key_type == self.InputTypes.SHA256:
                psbt_input.sha256_preimages[key_data] = value_data
            elif key_type == self.InputTypes.HASH160:
                psbt_input.hash160_preimages[key_data] = value_data
            elif key_type == self.InputTypes.HASH256:
                psbt_input.hash256_preimages[key_data] = value_data
            elif key_type == self.InputTypes.PROPRIETARY:
                psbt_input.proprietary[key_data] = value_data
            else:
                psbt_input.unknown[key_data] = value_data

    def _parse_output_section(self, stream: BytesIO, output_index: int) -> None:
        """Parse an output section of a PSBT."""
        psbt_output = self.outputs[output_index]
        
        while True:
            key_data = self._read_key_value_pair(stream)
            if key_data is None:
                break
            
            key_type, key_data, value_data = key_data
            
            if key_type == self.OutputTypes.REDEEM_SCRIPT:
                psbt_output.redeem_script = Script.from_bytes(value_data)
            elif key_type == self.OutputTypes.WITNESS_SCRIPT:
                psbt_output.witness_script = Script.from_bytes(value_data)
            elif key_type == self.OutputTypes.BIP32_DERIVATION:
                fingerprint = struct.unpack('<I', value_data[:4])[0]
                path = list(struct.unpack('<' + 'I' * ((len(value_data) - 4) // 4), value_data[4:]))
                psbt_output.bip32_derivs[key_data] = (fingerprint, path)
            elif key_type == self.OutputTypes.PROPRIETARY:
                psbt_output.proprietary[key_data] = value_data
            else:
                psbt_output.unknown[key_data] = value_data

    def _read_key_value_pair(self, stream: BytesIO) -> Optional[Tuple[int, bytes, bytes]]:
        """
        Read a key-value pair from the stream.
        
        Returns:
            Tuple of (key_type, key_data, value_data) or None if separator found
        """
        # Read key length
        key_len_bytes = stream.read(1)
        if not key_len_bytes or key_len_bytes == b'\x00':
            return None
        
        key_len = key_len_bytes[0]
        if key_len == 0:
            return None
        
        # Read key
        key = stream.read(key_len)
        if len(key) != key_len:
            raise ValueError("Unexpected end of stream reading key")
        
        # Read value length
        value_len_bytes = stream.read(1)
        if not value_len_bytes:
            raise ValueError("Unexpected end of stream reading value length")
        
        value_len = value_len_bytes[0]
        
        # Read value
        value = stream.read(value_len)
        if len(value) != value_len:
            raise ValueError("Unexpected end of stream reading value")
        
        # Parse key
        key_type = key[0]
        key_data = key[1:] if len(key) > 1 else b''
        
        return key_type, key_data, value

    def _serialize_global_section(self, result: BytesIO) -> None:
        """Serialize the global section."""
        # Unsigned transaction
        self._write_key_value_pair(result, self.GlobalTypes.UNSIGNED_TX, b'', self.tx.serialize())
        
        # XPubs
        for xpub, (fingerprint, path) in self.xpubs.items():
            key_data = struct.pack('<I', fingerprint) + struct.pack('<' + 'I' * len(path), *path)
            self._write_key_value_pair(result, self.GlobalTypes.XPUB, key_data, xpub)
        
        # Version
        if self.version != self.VERSION:
            self._write_key_value_pair(result, self.GlobalTypes.VERSION, b'', struct.pack('<I', self.version))
        
        # Proprietary
        for key_data, value_data in self.proprietary.items():
            self._write_key_value_pair(result, self.GlobalTypes.PROPRIETARY, key_data, value_data)
        
        # Unknown
        for key_data, value_data in self.unknown.items():
            result.write(bytes([len(key_data) + 1]))  # Key length
            result.write(key_data)  # Key data includes type
            result.write(bytes([len(value_data)]))  # Value length
            result.write(value_data)  # Value data
        
        # Section separator
        result.write(b'\x00')

    def _serialize_input_section(self, result: BytesIO, input_index: int) -> None:
        """Serialize an input section."""
        psbt_input = self.inputs[input_index]
        
        # Non-witness UTXO
        if psbt_input.non_witness_utxo:
            self._write_key_value_pair(result, self.InputTypes.NON_WITNESS_UTXO, b'', 
                                       psbt_input.non_witness_utxo.serialize())
        
        # Witness UTXO
        if psbt_input.witness_utxo:
            self._write_key_value_pair(result, self.InputTypes.WITNESS_UTXO, b'', 
                                       psbt_input.witness_utxo.serialize())
        
        # Partial signatures
        for pubkey, signature in psbt_input.partial_sigs.items():
            self._write_key_value_pair(result, self.InputTypes.PARTIAL_SIG, pubkey, signature)
        
        # Sighash type
        if psbt_input.sighash_type is not None:
            self._write_key_value_pair(result, self.InputTypes.SIGHASH_TYPE, b'', 
                                       struct.pack('<I', psbt_input.sighash_type))
        
        # Redeem script
        if psbt_input.redeem_script:
            self._write_key_value_pair(result, self.InputTypes.REDEEM_SCRIPT, b'', 
                                       psbt_input.redeem_script.to_bytes())
        
        # Witness script
        if psbt_input.witness_script:
            self._write_key_value_pair(result, self.InputTypes.WITNESS_SCRIPT, b'', 
                                       psbt_input.witness_script.to_bytes())
        
        # BIP32 derivations
        for pubkey, (fingerprint, path) in psbt_input.bip32_derivs.items():
            value_data = struct.pack('<I', fingerprint) + struct.pack('<' + 'I' * len(path), *path)
            self._write_key_value_pair(result, self.InputTypes.BIP32_DERIVATION, pubkey, value_data)
        
        # Final scriptSig
        if psbt_input.final_scriptsig:
            self._write_key_value_pair(result, self.InputTypes.FINAL_SCRIPTSIG, b'', 
                                       psbt_input.final_scriptsig.to_bytes())
        
        # Final script witness
        if psbt_input.final_scriptwitness:
            witness_data = b''.join(bytes([len(item)]) + item for item in psbt_input.final_scriptwitness)
            self._write_key_value_pair(result, self.InputTypes.FINAL_SCRIPTWITNESS, b'', witness_data)
        
        # Hash preimages
        for hash_val, preimage in psbt_input.ripemd160_preimages.items():
            self._write_key_value_pair(result, self.InputTypes.RIPEMD160, hash_val, preimage)
        
        for hash_val, preimage in psbt_input.sha256_preimages.items():
            self._write_key_value_pair(result, self.InputTypes.SHA256, hash_val, preimage)
        
        for hash_val, preimage in psbt_input.hash160_preimages.items():
            self._write_key_value_pair(result, self.InputTypes.HASH160, hash_val, preimage)
        
        for hash_val, preimage in psbt_input.hash256_preimages.items():
            self._write_key_value_pair(result, self.InputTypes.HASH256, hash_val, preimage)
        
        # Proprietary and unknown
        for key_data, value_data in psbt_input.proprietary.items():
            self._write_key_value_pair(result, self.InputTypes.PROPRIETARY, key_data, value_data)
        
        for key_data, value_data in psbt_input.unknown.items():
            result.write(bytes([len(key_data) + 1]))
            result.write(key_data)
            result.write(bytes([len(value_data)]))
            result.write(value_data)
        
        # Section separator
        result.write(b'\x00')

    def _serialize_output_section(self, result: BytesIO, output_index: int) -> None:
        """Serialize an output section."""
        psbt_output = self.outputs[output_index]
        
        # Redeem script
        if psbt_output.redeem_script:
            self._write_key_value_pair(result, self.OutputTypes.REDEEM_SCRIPT, b'', 
                                       psbt_output.redeem_script.to_bytes())
        
        # Witness script
        if psbt_output.witness_script:
            self._write_key_value_pair(result, self.OutputTypes.WITNESS_SCRIPT, b'', 
                                       psbt_output.witness_script.to_bytes())
        
        # BIP32 derivations
        for pubkey, (fingerprint, path) in psbt_output.bip32_derivs.items():
            value_data = struct.pack('<I', fingerprint) + struct.pack('<' + 'I' * len(path), *path)
            self._write_key_value_pair(result, self.OutputTypes.BIP32_DERIVATION, pubkey, value_data)
        
        # Proprietary and unknown
        for key_data, value_data in psbt_output.proprietary.items():
            self._write_key_value_pair(result, self.OutputTypes.PROPRIETARY, key_data, value_data)
        
        for key_data, value_data in psbt_output.unknown.items():
            result.write(bytes([len(key_data) + 1]))
            result.write(key_data)
            result.write(bytes([len(value_data)]))
            result.write(value_data)
        
        # Section separator
        result.write(b'\x00')

    def _write_key_value_pair(self, result: BytesIO, key_type: int, key_data: bytes, value_data: bytes) -> None:
        """Write a key-value pair to the stream."""
        key = bytes([key_type]) + key_data
        result.write(bytes([len(key)]))  # Key length
        result.write(key)  # Key
        result.write(bytes([len(value_data)]))  # Value length
        result.write(value_data)  # Value



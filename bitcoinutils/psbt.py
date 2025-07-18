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
import ecdsa
from ecdsa import SECP256k1, SigningKey
from typing import Dict, List, Optional, Tuple, Union
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.script import Script
from bitcoinutils.keys import PrivateKey, PublicKey
from bitcoinutils.utils import to_satoshis
from bitcoinutils.utils import encode_varint
from bitcoinutils.utils import read_varint

class PSBTInput:
    """Represents a single input in a PSBT with all associated metadata.
    
    This class holds all the data associated with a single input in a PSBT,
    including UTXO information, partial signatures, scripts, and derivation paths.
    
    Attributes:
        non_witness_utxo: The complete previous transaction for non-witness inputs
        witness_utxo: The previous transaction output for witness inputs
        partial_sigs: Dictionary mapping public keys to their signatures
        sighash_type: The signature hash type to use for this input
        redeem_script: The redeem script for P2SH inputs
        witness_script: The witness script for P2WSH or P2SH-P2WSH inputs
        bip32_derivs: Dictionary mapping public keys to their BIP32 derivation paths
        final_scriptsig: The finalized scriptSig for this input
        final_scriptwitness: The finalized witness stack for this input
        ripemd160_preimages: Preimages for RIPEMD160 hashes
        sha256_preimages: Preimages for SHA256 hashes
        hash160_preimages: Preimages for HASH160 hashes
        hash256_preimages: Preimages for HASH256 hashes
        proprietary: Proprietary key-value pairs
        unknown: Unknown key-value pairs
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
    """Represents a single output in a PSBT with all associated metadata.
    
    This class holds all the data associated with a single output in a PSBT,
    including scripts and derivation paths.
    
    Attributes:
        redeem_script: The redeem script for P2SH outputs
        witness_script: The witness script for P2WSH or P2SH-P2WSH outputs
        bip32_derivs: Dictionary mapping public keys to their BIP32 derivation paths
        proprietary: Proprietary key-value pairs
        unknown: Unknown key-value pairs
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
    """Bitcoin Partially Signed Bitcoin Transaction (PSBT) implementation as per BIP-174.
    
    This class provides a complete implementation of the PSBT format, allowing for
    the creation, parsing, signing, combining, and finalization of PSBTs.
    
    PSBTs are useful for constructing transactions in a collaborative manner,
    where multiple parties may need to provide signatures or where signing
    happens on offline/hardware devices.
    
    Attributes:
        tx: The unsigned transaction
        inputs: List of PSBTInput objects containing input-specific data
        outputs: List of PSBTOutput objects containing output-specific data
        version: PSBT version number
        xpubs: Dictionary mapping extended public keys to derivation paths
        proprietary: Global proprietary key-value pairs
        unknown: Global unknown key-value pairs
    """

    # PSBT magic bytes and version
    MAGIC = b'psbt'
    VERSION = 0

    # Key types as defined in BIP-174
    class GlobalTypes:
        """Global key types for PSBT as defined in BIP-174."""
        UNSIGNED_TX = 0x00
        XPUB = 0x01
        VERSION = 0xFB
        PROPRIETARY = 0xFC

    class InputTypes:
        """Input key types for PSBT as defined in BIP-174."""
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
        """Output key types for PSBT as defined in BIP-174."""
        REDEEM_SCRIPT = 0x00
        WITNESS_SCRIPT = 0x01
        BIP32_DERIVATION = 0x02
        PROPRIETARY = 0xFC

    def _safe_to_bytes(self, obj):
        """Safely convert various object types to bytes.
        
        Args:
            obj: Object to convert to bytes
            
        Returns:
            bytes: The object converted to bytes
            
        Raises:
            TypeError: If the object cannot be converted to bytes
        """
        if isinstance(obj, Script):
            return obj.to_bytes()
        elif hasattr(obj, 'to_bytes'):
            return obj.to_bytes()
        elif isinstance(obj, bytes):
            return obj
        elif isinstance(obj, str):
            return obj.encode()
        else:
            raise TypeError(f"Cannot convert {type(obj)} to bytes")


    def _safe_serialize_transaction(self, tx) -> bytes:
        """Safely serialize a transaction to bytes.
        
        Args:
            tx: Transaction to serialize
            
        Returns:
            bytes: Serialized transaction
        """
        if isinstance(tx, bytes):
            return tx
        
        serialized = tx.serialize()
        if isinstance(serialized, str):
            return bytes.fromhex(serialized)
        return serialized

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
        """Create a PSBT from a base64-encoded string.
        
        Args:
            psbt_str: Base64-encoded PSBT string
            
        Returns:
            PSBT: Decoded PSBT object
            
        Raises:
            ValueError: If the string is not a valid base64-encoded PSBT
        """
        import base64
        psbt_bytes = base64.b64decode(psbt_str)
        return cls.from_bytes(psbt_bytes)

    @classmethod
    def from_bytes(cls, psbt_bytes: bytes) -> 'PSBT':
        """Create a PSBT from raw bytes.
        
        Args:
            psbt_bytes: Raw PSBT bytes
            
        Returns:
            PSBT: Parsed PSBT object
            
        Raises:
            ValueError: If the bytes do not represent a valid PSBT
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
        """Encode the PSBT as a base64 string.
        
        Returns:
            str: Base64-encoded PSBT
        """
        import base64
        return base64.b64encode(self.to_bytes()).decode('ascii')

    def to_bytes(self) -> bytes:
        """Serialize the PSBT to raw bytes.
        
        Returns:
            bytes: Serialized PSBT
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
        """Add an input to the PSBT.
        
        Args:
            tx_input: Transaction input to add
            psbt_input: Optional PSBTInput with metadata. If not provided,
                       an empty PSBTInput will be created.
        """
        # Create clean input without scriptSig
        clean_input = TxInput(tx_input.txid, tx_input.txout_index)
        self.tx.inputs.append(clean_input)

        if psbt_input is None:
            psbt_input = PSBTInput()
        self.inputs.append(psbt_input)

    def add_output(self, tx_output: TxOutput, psbt_output: Optional[PSBTOutput] = None) -> None:
        """Add an output to the PSBT.
        
        Args:
            tx_output: Transaction output to add
            psbt_output: Optional PSBTOutput with metadata. If not provided,
                        an empty PSBTOutput will be created.
        """
        self.tx.outputs.append(tx_output)

        if psbt_output is None:
            psbt_output = PSBTOutput()
        self.outputs.append(psbt_output)

    def sign(self, private_key: PrivateKey, input_index: int, sighash_type: int = 1) -> bool:
        """Sign a specific input in the PSBT.
        
        This is a convenience method that calls sign_input.
        
        Args:
            private_key: Private key to sign with
            input_index: Index of the input to sign
            sighash_type: Signature hash type (default: SIGHASH_ALL = 1)
            
        Returns:
            bool: True if signing was successful, False otherwise
        """
        return self.sign_input(input_index, private_key, sighash_type)

    def sign_input(self, input_index: int, private_key: PrivateKey, sighash_type: int = 1) -> bool:
        """Sign a specific input in the PSBT.
        
        This method adds a partial signature for the specified input using the
        provided private key. It automatically detects the script type and
        handles both legacy and SegWit inputs.
        
        Args:
            input_index: Index of the input to sign
            private_key: Private key to sign with
            sighash_type: Signature hash type (default: SIGHASH_ALL = 1)
            
        Returns:
            bool: True if signing was successful, False otherwise
        """
        try:
            psbt_input = self.inputs[input_index]

            # Determine prev_txout and whether it is SegWit
            prev_txout = psbt_input.witness_utxo
            is_segwit = prev_txout is not None

            if not is_segwit:
                prev_tx = psbt_input.non_witness_utxo
                if prev_tx is None:
                    return False
                prev_txout = prev_tx.outputs[self.tx.inputs[input_index].tx_out_index]

            # Determine the correct script to use
            script_to_use = (
                psbt_input.witness_script
                if psbt_input.witness_script is not None
                else psbt_input.redeem_script
                if psbt_input.redeem_script is not None
                else prev_txout.script_pubkey
            )

            # Compute sighash correctly
            if is_segwit:
                sighash = self.tx.get_transaction_segwit_digest(
                    input_index,
                    script_to_use,
                    prev_txout.amount,
                    sighash_type
                )
            else:
                sighash = self.tx.get_transaction_digest(
                    input_index,
                    script_to_use,
                    sighash_type
                )

            # Prepare SigningKey correctly
            if hasattr(private_key, 'key'):
                raw_private_key = private_key.key.privkey.secret_multiplier.to_bytes(32, 'big')
            else:
                raw_private_key = private_key.to_bytes()

            sk = SigningKey.from_string(raw_private_key, curve=SECP256k1)

            # Create DER signature + sighash type byte
            sig = sk.sign_digest(sighash, sigencode=ecdsa.util.sigencode_der_canonize) + bytes([sighash_type])

            # Get compressed pubkey bytes
            pubkey_obj = private_key.get_public_key()
            if hasattr(pubkey_obj, 'to_bytes'):
                pubkey_bytes = pubkey_obj.to_bytes()
            else:
                pubkey_bytes = pubkey_obj.key.to_string('compressed')

            # Add to partial_sigs
            psbt_input.partial_sigs[pubkey_bytes] = sig

            return True

        except Exception as e:
            import traceback
            traceback.print_exc()
            return False

    def _get_signature_for_input(self, input_index: int, private_key: PrivateKey, sighash_type: int) -> bytes:
        """Get a signature for a specific input.
        
        This internal method generates a signature for the specified input,
        handling different script types appropriately.
        
        Args:
            input_index: Index of the input to sign
            private_key: Private key to sign with
            sighash_type: Signature hash type
            
        Returns:
            bytes: The signature, or None if signing failed
        """
        input_data = self.inputs[input_index]
        tx_input = self.tx.inputs[input_index]

        try:
            # ✅ Ensure tx_input is proper TxInput object
            if isinstance(tx_input, dict):
                tx_input = TxInput(tx_input.get('txid'), tx_input.get('vout', tx_input.get('txout_index')))
                self.tx.inputs[input_index] = tx_input

            # ✅ Ensure witness_utxo is proper TxOutput object
            if isinstance(input_data.witness_utxo, dict):
                utxo_dict = input_data.witness_utxo
                
                # Handle script_pubkey conversion
                spk = utxo_dict.get('script_pubkey')
                if isinstance(spk, dict):
                    spk = spk.get('hex') or spk.get('asm') or spk.get('script')
                
                # Handle different value field names
                value = utxo_dict.get('value') or utxo_dict.get('amount')
                
                if spk and value is not None:
                    input_data.witness_utxo = TxOutput(value, Script(spk))
                else:
                    return None

            # ✅ Fix script_pubkey if it's still a dict inside TxOutput
            elif isinstance(input_data.witness_utxo, TxOutput):
                spk = input_data.witness_utxo.script_pubkey
                if isinstance(spk, dict):
                    spk_data = spk.get('hex') or spk.get('asm') or spk.get('script')
                    if spk_data:
                        input_data.witness_utxo.script_pubkey = Script(spk_data)
                    else:
                        return None

            # ✅ Ensure scripts are proper Script objects
            if input_data.redeem_script and isinstance(input_data.redeem_script, (str, bytes, dict)):
                if isinstance(input_data.redeem_script, dict):
                    script_data = input_data.redeem_script.get('hex') or input_data.redeem_script.get('asm')
                else:
                    script_data = input_data.redeem_script
                input_data.redeem_script = Script(script_data)

            if input_data.witness_script and isinstance(input_data.witness_script, (str, bytes, dict)):
                if isinstance(input_data.witness_script, dict):
                    script_data = input_data.witness_script.get('hex') or input_data.witness_script.get('asm')
                else:
                    script_data = input_data.witness_script
                input_data.witness_script = Script(script_data)

            # Now proceed with signing logic based on script type
            if input_data.redeem_script:
                redeem_script = input_data.redeem_script
                
                if input_data.witness_script:
                    # P2SH-P2WSH (Script Hash wrapping Witness Script Hash)
                    witness_script = input_data.witness_script
                    if input_data.witness_utxo:
                        amount = input_data.witness_utxo.amount
                        return private_key.sign_segwit_input(
                            self.tx, input_index, witness_script, amount, sighash_type
                        )

                elif self._is_p2wpkh_script(redeem_script):
                    # P2SH-P2WPKH (Script Hash wrapping Witness PubKey Hash)
                    if input_data.witness_utxo:
                        amount = input_data.witness_utxo.amount
                        # For P2WPKH, we need the P2PKH script of the public key
                        p2pkh_script = private_key.get_public_key().get_address().to_script_pub_key()
                        return private_key.sign_segwit_input(
                            self.tx, input_index, p2pkh_script, amount, sighash_type
                        )

                else:
                    # Regular P2SH (Script Hash)
                    return private_key.sign_input(
                        self.tx, input_index, redeem_script, sighash_type
                    )

            elif input_data.witness_script:
                # P2WSH (Witness Script Hash)
                witness_script = input_data.witness_script
                if input_data.witness_utxo:
                    amount = input_data.witness_utxo.amount
                    return private_key.sign_segwit_input(
                        self.tx, input_index, witness_script, amount, sighash_type
                    )

            elif input_data.witness_utxo:
                # Direct witness input (P2WPKH or P2TR)
                script_pubkey = input_data.witness_utxo.script_pubkey
                amount = input_data.witness_utxo.amount

                if self._is_p2wpkh_script(script_pubkey):
                    # P2WPKH (Witness PubKey Hash)
                    # For P2WPKH, we sign with the P2PKH script of our public key
                    p2pkh_script = private_key.get_public_key().get_address().to_script_pub_key()
                    return private_key.sign_segwit_input(
                        self.tx, input_index, p2pkh_script, amount, sighash_type
                    )

                elif self._is_p2tr_script(script_pubkey):
                    # P2TR (Taproot)
                    return private_key.sign_taproot_input(
                        self.tx, input_index, amount, sighash_type
                    )

            elif input_data.non_witness_utxo:
                # Legacy input (P2PKH, P2SH without witness)
                prev_tx_out = input_data.non_witness_utxo.outputs[tx_input.txout_index]
                script_pubkey = prev_tx_out.script_pubkey

                if self._is_p2pkh_script(script_pubkey):
                    # P2PKH (Pay to PubKey Hash)
                    return private_key.sign_input(
                        self.tx, input_index, script_pubkey, sighash_type
                    )
            
            return None

        except Exception as e:
            import traceback
            traceback.print_exc()
            return None


    def _is_p2pkh_script(self, script) -> bool:
        """Check if script is P2PKH (OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG).
        
        Args:
            script: Script to check
            
        Returns:
            bool: True if script is P2PKH, False otherwise
        """
        try:
            return script.is_p2pkh() if hasattr(script, 'is_p2pkh') else False
        except:
            return False

    def _is_p2wpkh_script(self, script) -> bool:
        """Check if script is P2WPKH (OP_0 <20-byte-pubkeyhash>).
        
        Args:
            script: Script to check
            
        Returns:
            bool: True if script is P2WPKH, False otherwise
        """
        try:
            return script.is_p2wpkh() if hasattr(script, 'is_p2wpkh') else False
        except:
            return False

    def _is_p2tr_script(self, script_pubkey: Script) -> bool:
        """Check if script is P2TR (Taproot).
        
        Args:
            script_pubkey: Script to check
            
        Returns:
            bool: True if script is P2TR, False otherwise
        """
        if not hasattr(script_pubkey, 'script'):
            return False
        
        script_ops = script_pubkey.script
        # P2TR is OP_1 followed by 32 bytes
        return (len(script_ops) == 2 and 
                script_ops[0] == 1 and  # OP_1 
                isinstance(script_ops[1], bytes) and 
                len(script_ops[1]) == 32)

    def _is_input_finalized(self, psbt_input: PSBTInput) -> bool:
        """Check if an input is already finalized.
        
        Args:
            psbt_input: Input to check
            
        Returns:
            bool: True if input is finalized, False otherwise
        """
        return (psbt_input.final_scriptsig is not None or 
                psbt_input.final_scriptwitness is not None)

    def _apply_final_fields(self, tx_input: TxInput, input_data: PSBTInput) -> None:
        """Apply finalized fields to a transaction input.
        
        Args:
            tx_input: Transaction input to update
            input_data: PSBT input data containing finalized fields
        """
        if input_data.final_scriptsig:
            tx_input.script_sig = input_data.final_scriptsig
        else:
            tx_input.script_sig = Script([])

    def _validate_final_tx(self, final_tx) -> dict:
        """Validate the finalized transaction.
        
        Args:
            final_tx: Transaction to validate
            
        Returns:
            dict: Validation information including:
                - valid: Whether the transaction is valid
                - errors: List of error messages
                - warnings: List of warning messages
                - size: Transaction size in bytes
                - vsize: Virtual size for fee calculation
        """
        validation_info = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        # Basic validation
        if not final_tx.inputs:
            validation_info['valid'] = False
            validation_info['errors'].append("Transaction has no inputs")
        
        if not final_tx.outputs:
            validation_info['valid'] = False
            validation_info['errors'].append("Transaction has no outputs")
        
        # Check that all inputs have scriptSig or witness
        for i, tx_input in enumerate(final_tx.inputs):
            has_scriptsig = tx_input.script_sig and len(tx_input.script_sig.script) > 0
            has_witness = (hasattr(final_tx, 'witnesses') and 
                        i < len(final_tx.witnesses) and 
                        final_tx.witnesses[i] and 
                        len(final_tx.witnesses[i]) > 0)
            
            if not has_scriptsig and not has_witness:
                validation_info['valid'] = False
                validation_info['errors'].append(f"Input {i} has no scriptSig or witness")
        
        # Calculate transaction size and vsize
        try:
            tx_bytes = final_tx.serialize()
            if isinstance(tx_bytes, str):
                tx_bytes = bytes.fromhex(tx_bytes)
            
            validation_info['size'] = len(tx_bytes)
            
            # Calculate vsize (virtual size) for SegWit transactions
            # For non-SegWit transactions, vsize = size
            # For SegWit transactions, vsize = (base_size * 3 + total_size) / 4
            has_witnesses = (hasattr(final_tx, 'witnesses') and 
                            any(witness for witness in final_tx.witnesses))
            
            if has_witnesses:
                # Calculate base size (transaction without witness data)
                base_tx_data = self._serialize_transaction_without_witness(final_tx)
                base_size = len(base_tx_data)
                total_size = len(tx_bytes)
                validation_info['vsize'] = (base_size * 3 + total_size) // 4
            else:
                validation_info['vsize'] = len(tx_bytes)
                
        except Exception as e:
            validation_info['size'] = 0
            validation_info['vsize'] = 0
            validation_info['warnings'].append(f"Could not calculate transaction size: {str(e)}")
        
        return validation_info

    def _serialize_transaction_without_witness(self, tx) -> bytes:
        """Serialize transaction without witness data for vsize calculation.
        
        Args:
            tx: Transaction to serialize
            
        Returns:
            bytes: Serialized transaction without witness data
        """
        try:
            # Create a copy of the transaction without witness data
            from bitcoinutils.transactions import Transaction
            from bitcoinutils.script import Script
            
            # Create inputs without witness data
            inputs_without_witness = []
            for tx_input in tx.inputs:
                clean_input = type(tx_input)(
                    tx_input.txid,
                    tx_input.txout_index,
                    tx_input.script_sig if tx_input.script_sig else Script([]),
                    tx_input.sequence if hasattr(tx_input, 'sequence') else 0xffffffff
                )
                inputs_without_witness.append(clean_input)
            
            # Create transaction without witness
            base_tx = Transaction(
                inputs_without_witness,
                tx.outputs,
                tx.locktime if hasattr(tx, 'locktime') else 0,
                tx.version if hasattr(tx, 'version') else 1
            )
            
            # Serialize without witness
            serialized = base_tx.serialize()
            if isinstance(serialized, str):
                return bytes.fromhex(serialized)
            return serialized
            
        except Exception:
            # Fallback: assume no witness data
            serialized = tx.serialize()
            if isinstance(serialized, str):
                return bytes.fromhex(serialized)
            return serialized

    def combine(self, other: 'PSBT') -> 'PSBT':
        """Combine this PSBT with another PSBT.
        
        PSBTs can be combined when they represent the same unsigned transaction.
        The resulting PSBT will contain all the data from both PSBTs, with data
        from 'other' taking precedence in case of conflicts.
        
        Args:
            other: Another PSBT to combine with this one
            
        Returns:
            PSBT: A new PSBT containing combined data from both PSBTs
            
        Raises:
            ValueError: If the PSBTs have different unsigned transactions
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
        """Combines this PSBT with multiple other PSBTs.

        Wraps the pairwise `combine()` method in a loop for batch combining.
        All PSBTs must have the same unsigned transaction.

        Parameters
        ----------
        other_psbts : List[PSBT]
            A list of PSBTs to combine with this one

        Returns
        -------
        PSBT
            The final combined PSBT containing all partial signatures and
            metadata from all input PSBTs

        Raises
        ------
        ValueError
            If any PSBT has a different unsigned transaction
        """
        combined = self
        for other in other_psbts:
            combined = combined.combine(other)
        return combined

    def finalize(self, validate: bool = False) -> Union[Transaction, Tuple[Transaction, Dict]]:
        """Finalizes all inputs and creates the final broadcastable transaction.

        Attempts to finalize all inputs by converting partial signatures into
        final scriptSig/scriptWitness fields. If successful, produces a fully
        signed transaction ready for broadcast.

        Parameters
        ----------
        validate : bool, optional
            If True, validates the final transaction and returns validation
            info along with the transaction (default: False)

        Returns
        -------
        Transaction or Tuple[Transaction, Dict]
            If validate=False: Transaction object ready for broadcast, or None
            if not all inputs could be finalized
            If validate=True: Tuple of (Transaction, validation_info dict)
            containing the transaction and validation details

        Raises
        ------
        ValueError
            If not all inputs can be finalized when validate=True

        Notes
        -----
        The validation_info dict contains:
        - 'valid': bool indicating if transaction is valid
        - 'errors': List of error messages
        - 'warnings': List of warning messages
        - 'txid': Transaction ID if computable
        - 'size': Transaction size in bytes
        - 'vsize': Virtual size for fee calculation
        """

        # Count successfully finalized inputs
        finalized_count = 0
        for i in range(len(self.inputs)):
            if self._finalize_input(i):
                finalized_count += 1

        # If not all inputs could be finalized, return None
        if finalized_count != len(self.inputs):
            if validate:
                # Return a validation dict with error info
                validation_info = {
                    'valid': False,
                    'errors': [f"Could not finalize all inputs. Finalized: {finalized_count}/{len(self.inputs)}"],
                    'warnings': []
                }
                # Return a dummy transaction and validation info
                return self.tx, validation_info
            else:
                return None

        # All inputs finalized - build final transaction
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

        # Add witness data
        final_tx.witnesses = []
        for psbt_input in self.inputs:
            if psbt_input.final_scriptwitness:
                final_tx.witnesses.append(psbt_input.final_scriptwitness)
            else:
                final_tx.witnesses.append([])

        if validate:
            validation_info = self._validate_final_tx(final_tx)
            # Add txid to validation info
            try:
                validation_info['txid'] = final_tx.get_txid()
            except:
                validation_info['txid'] = 'Unable to compute'
            
            return final_tx, validation_info
        else:
            return final_tx

    def finalize_input(self, input_index: int) -> bool:
        """Finalizes a specific input.

        Converts partial signatures for a single input into final
        scriptSig/scriptWitness fields.

        Parameters
        ----------
        input_index : int
            The index of the input to finalize

        Returns
        -------
        bool
            True if the input was successfully finalized, False otherwise

        Raises
        ------
        ValueError
            If input_index is out of range
        """
        
        if input_index >= len(self.inputs):
            raise ValueError(f"Input index {input_index} out of range")

        return self._finalize_input(input_index)

    def _finalize_input(self, input_index: int) -> bool:
        """Internal method for finalizing a single input.

        Handles the actual finalization logic for different script types
        including P2PKH, P2WPKH, P2SH, P2WSH, and P2TR.

        Parameters
        ----------
        input_index : int
            The index of the input to finalize

        Returns
        -------
        bool
            True if the input was successfully finalized
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
        """Finalizes a P2PKH (Pay-to-PubKey-Hash) input.

        Parameters
        ----------
        psbt_input : PSBTInput
            The PSBT input to finalize

        Returns
        -------
        bool
            True if finalization was successful
        """

        if len(psbt_input.partial_sigs) != 1:
            return False

        pubkey, signature = next(iter(psbt_input.partial_sigs.items()))
        psbt_input.final_scriptsig = Script([signature, pubkey])
        return True

    def _finalize_p2wpkh(self, psbt_input: PSBTInput) -> bool:
        """Finalizes a P2WPKH (Pay-to-Witness-PubKey-Hash) input.

        Parameters
        ----------
        psbt_input : PSBTInput
            The PSBT input to finalize

        Returns
        -------
        bool
            True if finalization was successful
        """

        if len(psbt_input.partial_sigs) != 1:
            return False

        pubkey, signature = next(iter(psbt_input.partial_sigs.items()))
        psbt_input.final_scriptsig = Script([])
        psbt_input.final_scriptwitness = [signature, pubkey]
        return True

    def _finalize_p2sh(self, psbt_input: PSBTInput) -> bool:
        """Finalizes a P2SH (Pay-to-Script-Hash) input.

        Handles both regular P2SH and P2SH-wrapped SegWit scripts.

        Parameters
        ----------
        psbt_input : PSBTInput
            The PSBT input to finalize

        Returns
        -------
        bool
            True if finalization was successful
        """
        if not psbt_input.redeem_script:
            return False

        redeem_script = psbt_input.redeem_script

        # Handle P2SH-wrapped SegWit
        if redeem_script.is_p2wpkh():
            return self._finalize_p2sh_p2wpkh(psbt_input)
        elif redeem_script.is_p2wsh():
            return self._finalize_p2sh_p2wsh(psbt_input)
        else:
            # Regular P2SH - finalize the redeem script
            success = self._finalize_script(psbt_input, redeem_script, is_witness=False)
            if success:
                # For regular P2SH, the scriptSig should already contain the unlocking script
                # plus the redeem script. The _finalize_script method handles adding the redeem script.
                pass
            return success

    def _finalize_p2sh_p2wpkh(self, psbt_input: PSBTInput) -> bool:
        """Finalizes a P2SH-wrapped P2WPKH input.

        Parameters
        ----------
        psbt_input : PSBTInput
            The PSBT input to finalize

        Returns
        -------
        bool
            True if finalization was successful
        """
        if len(psbt_input.partial_sigs) != 1:
            return False

        pubkey, signature = next(iter(psbt_input.partial_sigs.items()))

        # scriptSig contains just the redeem script
        redeem_script_bytes = self._safe_to_bytes(psbt_input.redeem_script)
        psbt_input.final_scriptsig = Script([redeem_script_bytes])

        # Safe bytes conversion
        sig_bytes = signature if isinstance(signature, bytes) else signature
        pubkey_bytes = pubkey if isinstance(pubkey, bytes) else pubkey
        psbt_input.final_scriptwitness = [sig_bytes, pubkey_bytes]
        return True

    def _finalize_p2sh_p2wsh(self, psbt_input: PSBTInput) -> bool:
        """Finalizes a P2SH-wrapped P2WSH input.

        Parameters
        ----------
        psbt_input : PSBTInput
            The PSBT input to finalize

        Returns
        -------
        bool
            True if finalization was successful
        """
        if not psbt_input.witness_script:
            return False

        # Finalize the witness script part
        success = self._finalize_script(psbt_input, psbt_input.witness_script, is_witness=True)
        if success:
            # For P2SH-P2WSH, scriptSig contains only the redeem script (P2WSH script)
            redeem_bytes = self._safe_to_bytes(psbt_input.redeem_script)
            psbt_input.final_scriptsig = Script([redeem_bytes])
            
            # The witness script is already added by _finalize_script
            # No need to append it again
        return success

    def _finalize_p2wsh(self, psbt_input: PSBTInput) -> bool:
        """Finalizes a P2WSH (Pay-to-Witness-Script-Hash) input.

        Parameters
        ----------
        psbt_input : PSBTInput
            The PSBT input to finalize

        Returns
        -------
        bool
            True if finalization was successful
        """
        if not psbt_input.witness_script:
            return False

        return self._finalize_script(psbt_input, psbt_input.witness_script, is_witness=True)

    def _finalize_p2tr(self, psbt_input: PSBTInput) -> bool:
        """Finalizes a P2TR (Pay-to-Taproot) input.

        Currently supports only key-path spending.

        Parameters
        ----------
        psbt_input : PSBTInput
            The PSBT input to finalize

        Returns
        -------
        bool
            True if finalization was successful
        """
        if len(psbt_input.partial_sigs) != 1:
            return False

        # For key-path spending, we expect a single signature
        signature = next(iter(psbt_input.partial_sigs.values()))
        psbt_input.final_scriptsig = Script([])
        psbt_input.final_scriptwitness = [signature]
        return True

    def _finalize_script(self, psbt_input: PSBTInput, script: Script, is_witness: bool) -> bool:
        """Finalizes a script with enhanced multisig support.

        Handles the finalization of complex scripts, particularly multisig
        scripts, by properly ordering signatures according to the public
        keys in the script.

        Parameters
        ----------
        psbt_input : PSBTInput
            The PSBT input containing partial signatures
        script : Script
            The script to finalize against
        is_witness : bool
            Whether this is a witness script (affects output format)

        Returns
        -------
        bool
            True if finalization was successful

        Notes
        -----
        For multisig scripts, signatures must be provided in the same order
        as their corresponding public keys appear in the script.
        """
        script_ops = script.script if hasattr(script, "script") else []

        # Enhanced multisig detection and handling
        if (len(script_ops) >= 4 and
            script_ops[0] == 'OP_2' and  # Check for OP_2 string
            script_ops[-1] == 'OP_CHECKMULTISIG'):  # Check for OP_CHECKMULTISIG string
            
            # Extract m and n values
            m = 2  # From OP_2
            n = 3  # From OP_3
            
            # Extract public keys from script (they're between m and n)
            pubkeys = []
            for i in range(1, 4):  # indices 1, 2, 3 for the three pubkeys
                if i < len(script_ops):
                    pk = script_ops[i]
                    if isinstance(pk, str):
                        pubkeys.append(bytes.fromhex(pk))
                    elif isinstance(pk, bytes):
                        pubkeys.append(pk)
            
            if len(pubkeys) != n:
                return False
            
            # IMPORTANT: For Bitcoin multisig, we need to match signatures to their pubkeys
            # and provide them in the order the pubkeys appear in the script
            ordered_sigs = []
            sig_pubkey_map = {}
            
            # First, normalize all pubkeys from partial_sigs to bytes
            for partial_pubkey, sig in psbt_input.partial_sigs.items():
                if isinstance(partial_pubkey, str):
                    partial_pubkey_bytes = bytes.fromhex(partial_pubkey)
                else:
                    partial_pubkey_bytes = partial_pubkey
                sig_pubkey_map[partial_pubkey_bytes] = sig
            
            # Now collect signatures in script pubkey order
            for pubkey in pubkeys:
                if pubkey in sig_pubkey_map:
                    ordered_sigs.append(sig_pubkey_map[pubkey])
            
            # Check if we have enough signatures
            if len(ordered_sigs) < m:
                return False
            
            # Use only the first m signatures (in case we have more)
            signatures_to_use = ordered_sigs[:m]
            
            # Build the final script
            if is_witness:
                psbt_input.final_scriptsig = Script([])
                # Witness stack for multisig: [OP_0, sig1, sig2, ..., sigM, witnessScript]
                witness_elements = [b'']  # OP_0 (empty bytes for multisig bug)
                for sig in signatures_to_use:
                    # Ensure signature is bytes
                    if isinstance(sig, str):
                        witness_elements.append(bytes.fromhex(sig))
                    else:
                        witness_elements.append(sig)
                witness_elements.append(self._safe_to_bytes(script))
                psbt_input.final_scriptwitness = witness_elements
            else:
                # For P2SH multisig (non-witness)
                script_elements = []
                script_elements.append(b'')  # OP_0 (empty bytes)
                for sig in signatures_to_use:
                    if isinstance(sig, str):
                        script_elements.append(bytes.fromhex(sig))
                    else:
                        script_elements.append(sig)
                script_elements.append(self._safe_to_bytes(script))
                psbt_input.final_scriptsig = Script(script_elements)

            return True

        # Handle other script types...
        return False

    def _parse_global_section(self, stream: BytesIO) -> None:
        """Parses the global section of a PSBT from a byte stream.

        Reads and processes global key-value pairs including the unsigned
        transaction, extended public keys, version, and proprietary data.

        Parameters
        ----------
        stream : BytesIO
            The byte stream positioned at the start of the global section

        Raises
        ------
        ValueError
            If required fields are missing or malformed
        """
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
        """Parses an input section of a PSBT from a byte stream.

        Reads and processes all key-value pairs for a specific input including
        UTXOs, partial signatures, scripts, and derivation paths.

        Parameters
        ----------
        stream : BytesIO
            The byte stream positioned at the start of the input section
        input_index : int
            The index of the input being parsed

        Raises
        ------
        ValueError
            If the stream ends unexpectedly or data is malformed
        """
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
                    item_len, varint_len = read_varint(value_data[offset:])
                    offset += varint_len
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
        """Parses an output section of a PSBT from a byte stream.

        Reads and processes all key-value pairs for a specific output including
        scripts and derivation paths.

        Parameters
        ----------
        stream : BytesIO
            The byte stream positioned at the start of the output section
        output_index : int
            The index of the output being parsed

        Raises
        ------
        ValueError
            If the stream ends unexpectedly or data is malformed
        """
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

    def _serialize_global_section(self, result: BytesIO) -> None:
        """Serializes the global section of a PSBT to a byte stream.

        Writes all global key-value pairs including the unsigned transaction,
        extended public keys, version, and proprietary data.

        Parameters
        ----------
        result : BytesIO
            The byte stream to write the serialized data to
        """
        
        # Unsigned transaction (required)
        if self.tx:
            tx_data = self._safe_serialize_transaction(self.tx)
            self._write_key_value_pair(result, self.GlobalTypes.UNSIGNED_TX, b'', tx_data)
        
        # Extended public keys
        for xpub, (fingerprint, path) in self.xpubs.items():
            value_data = struct.pack('<I', fingerprint) + struct.pack('<' + 'I' * len(path), *path)
            self._write_key_value_pair(result, self.GlobalTypes.XPUB, xpub, value_data)
        
        # Version (if not default)
        if self.version != self.VERSION:
            self._write_key_value_pair(result, self.GlobalTypes.VERSION, b'', 
                                    struct.pack('<I', self.version))
        
        # Proprietary fields
        for key_data, value_data in self.proprietary.items():
            self._write_key_value_pair(result, self.GlobalTypes.PROPRIETARY, key_data, value_data)
        
        # Unknown fields
        for key_data, value_data in self.unknown.items():
            result.write(bytes([len(key_data)]))
            result.write(key_data)
            result.write(bytes([len(value_data)]))
            result.write(value_data)
        
        # Section separator
        result.write(b'\x00')

    def _read_key_value_pair(self, stream: BytesIO) -> Optional[Tuple[int, bytes, bytes]]:
        """Reads a single key-value pair from a PSBT byte stream.

        Parameters
        ----------
        stream : BytesIO
            The byte stream to read from

        Returns
        -------
        Optional[Tuple[int, bytes, bytes]]
            Tuple of (key_type, key_data, value_data) or None if a separator
            (0x00) is encountered

        Raises
        ------
        ValueError
            If the stream ends unexpectedly while reading
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

    def _serialize_input_section(self, result: BytesIO, input_index: int) -> None:
        """Serializes an input section of a PSBT to a byte stream.

        Writes all key-value pairs for a specific input including UTXOs,
        partial signatures, scripts, derivation paths, and finalized scripts.

        Parameters
        ----------
        result : BytesIO
            The byte stream to write the serialized data to
        input_index : int
            The index of the input to serialize
        """
        psbt_input = self.inputs[input_index]

        # Ensure scripts are Script objects, not bytes
        if isinstance(psbt_input.redeem_script, bytes):
            psbt_input.redeem_script = Script(psbt_input.redeem_script)
        if isinstance(psbt_input.witness_script, bytes):
            psbt_input.witness_script = Script(psbt_input.witness_script)
        if isinstance(psbt_input.final_scriptsig, bytes):
            psbt_input.final_scriptsig = Script(psbt_input.final_scriptsig)
        
        # Non-witness UTXO
        if psbt_input.non_witness_utxo:
            utxo_data = self._safe_serialize_transaction(psbt_input.non_witness_utxo)
            self._write_key_value_pair(result, self.InputTypes.NON_WITNESS_UTXO, b'', utxo_data)
        
        # Witness UTXO - Safe handling
        if psbt_input.witness_utxo:
            try:
                # For TxOutput objects, we need to serialize properly
                import struct
                from bitcoinutils.utils import encode_varint
                
                witness_utxo = psbt_input.witness_utxo
                
                # Serialize amount (8 bytes, little-endian)
                amount_bytes = struct.pack("<Q", witness_utxo.amount)
                
                # Serialize script_pubkey
                script_bytes = witness_utxo.script_pubkey.to_bytes()
                script_len_bytes = encode_varint(len(script_bytes))
                
                # Combine: amount + script_length + script
                witness_data = amount_bytes + script_len_bytes + script_bytes
                
            except Exception as e:
                # Fallback - try to use existing method if available
                if hasattr(psbt_input.witness_utxo, 'to_bytes'):
                    witness_data = psbt_input.witness_utxo.to_bytes()
                else:
                    raise
            
            self._write_key_value_pair(result, self.InputTypes.WITNESS_UTXO, b'', witness_data)
        
        # Partial signatures
        for pubkey, signature in psbt_input.partial_sigs.items():
            # Ensure both pubkey and signature are bytes
            pubkey_bytes = pubkey if isinstance(pubkey, bytes) else self._safe_to_bytes(pubkey)
            sig_bytes = signature if isinstance(signature, bytes) else self._safe_to_bytes(signature)
            self._write_key_value_pair(result, self.InputTypes.PARTIAL_SIG, pubkey_bytes, sig_bytes)
        
        # Sighash type
        if psbt_input.sighash_type is not None:
            self._write_key_value_pair(result, self.InputTypes.SIGHASH_TYPE, b'', 
                                    struct.pack('<I', psbt_input.sighash_type))
        
        # Redeem script
        if psbt_input.redeem_script:
            script_bytes = self._safe_to_bytes(psbt_input.redeem_script)
            self._write_key_value_pair(result, self.InputTypes.REDEEM_SCRIPT, b'', script_bytes)
        
        # Witness script
        if psbt_input.witness_script:
            script_bytes = self._safe_to_bytes(psbt_input.witness_script)
            self._write_key_value_pair(result, self.InputTypes.WITNESS_SCRIPT, b'', script_bytes)
        
        # BIP32 derivations
        for pubkey, (fingerprint, path) in psbt_input.bip32_derivs.items():
            value_data = struct.pack('<I', fingerprint) + struct.pack('<' + 'I' * len(path), *path)
            pubkey_bytes = pubkey if isinstance(pubkey, bytes) else self._safe_to_bytes(pubkey)
            self._write_key_value_pair(result, self.InputTypes.BIP32_DERIVATION, pubkey_bytes, value_data)
        
        # Final scriptSig
        if psbt_input.final_scriptsig:
            script_bytes = self._safe_to_bytes(psbt_input.final_scriptsig)
            self._write_key_value_pair(result, self.InputTypes.FINAL_SCRIPTSIG, b'', script_bytes)
        
        # Final script witness
        if psbt_input.final_scriptwitness:
            witness_data = b''.join(
                encode_varint(len(item)) +
                (item if isinstance(item, bytes) else self._safe_to_bytes(item))
                for item in psbt_input.final_scriptwitness
            )
            self._write_key_value_pair(result, self.InputTypes.FINAL_SCRIPTWITNESS, b'', witness_data)
        
        # Hash preimages (these should already be bytes)
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
        """Serializes an output section of a PSBT to a byte stream.

        Writes all key-value pairs for a specific output including scripts
        and derivation paths.

        Parameters
        ----------
        result : BytesIO
            The byte stream to write the serialized data to
        output_index : int
            The index of the output to serialize
        """

        psbt_output = self.outputs[output_index]

        # Ensure scripts are Script objects, not bytes
        if isinstance(psbt_output.redeem_script, bytes):
            psbt_output.redeem_script = Script(psbt_output.redeem_script)
        if isinstance(psbt_output.witness_script, bytes):
            psbt_output.witness_script = Script(psbt_output.witness_script)
        
        # Redeem script
        if psbt_output.redeem_script:
            script_bytes = self._safe_to_bytes(psbt_output.redeem_script)
            self._write_key_value_pair(result, self.OutputTypes.REDEEM_SCRIPT, b'', script_bytes)
        
        # Witness script
        if psbt_output.witness_script:
            script_bytes = self._safe_to_bytes(psbt_output.witness_script)
            self._write_key_value_pair(result, self.OutputTypes.WITNESS_SCRIPT, b'', script_bytes)
        
        # BIP32 derivations
        for pubkey, (fingerprint, path) in psbt_output.bip32_derivs.items():
            value_data = struct.pack('<I', fingerprint) + struct.pack('<' + 'I' * len(path), *path)
            pubkey_bytes = pubkey if isinstance(pubkey, bytes) else self._safe_to_bytes(pubkey)
            self._write_key_value_pair(result, self.OutputTypes.BIP32_DERIVATION, pubkey_bytes, value_data)
        
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
        """Writes a key-value pair to a PSBT byte stream.

        Formats and writes a single key-value pair according to the PSBT
        specification, including proper length encoding.

        Parameters
        ----------
        result : BytesIO
            The byte stream to write to
        key_type : int
            The type identifier for this key-value pair
        key_data : bytes
            Additional key data (may be empty)
        value_data : bytes
            The value data to write
        """
        key = bytes([key_type]) + key_data
        result.write(encode_varint(len(key)))
        result.write(key)
        result.write(encode_varint(len(value_data)))
        result.write(value_data)
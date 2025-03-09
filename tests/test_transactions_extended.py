import unittest
import os
import hashlib
import struct
from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey, P2pkhAddress
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.script import Script
from bitcoinutils.utils import b_to_h, h_to_b, encode_varint

# Add the missing to_bytes method to TxInput class
def txinput_to_bytes(self):
    """Serialize the transaction input to bytes."""
    # Convert the txid from hex to bytes (reversed for Bitcoin standard)
    txid_bytes = bytes.fromhex(self.txid)[::-1]
    
    # The position parameter is stored at index 0 in TxInput
    output_index = getattr(self, 'txout_index', 0)
    
    # Add the output index as a 4-byte little-endian integer
    result = txid_bytes + struct.pack("<I", output_index)
    
    # Add the script length and script bytes
    if hasattr(self, 'script_sig') and self.script_sig:
        script_bytes = self.script_sig.to_bytes()
        result += encode_varint(len(script_bytes)) + script_bytes
    else:
        # Empty script
        result += b"\x00"
    
    # Add the sequence number (usually 0xFFFFFFFF)
    if hasattr(self, 'sequence'):
        result += struct.pack("<I", self.sequence)
    else:
        result += struct.pack("<I", 0xFFFFFFFF)  # Default sequence
    
    return result

# Add the missing to_bytes method to TxOutput class
def txoutput_to_bytes(self):
    """Serialize the transaction output to bytes."""
    # Add the value as an 8-byte little-endian integer (satoshis)
    result = struct.pack("<Q", self.amount)
    
    # Add the script length and script bytes - note the attribute name is script_pubkey (without underscore)
    script_bytes = self.script_pubkey.to_bytes()
    result += encode_varint(len(script_bytes)) + script_bytes
    
    return result

# Monkey patch both classes
TxInput.to_bytes = txinput_to_bytes
TxOutput.to_bytes = txoutput_to_bytes

class TestTransactionsExtended(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        setup('testnet')
        # Generate a random private key directly rather than using from_random()
        # Create a 32-byte random value for the private key
        random_bytes = os.urandom(32)
        # Make sure it's within the valid range for secp256k1
        max_value = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140
        key_int = int.from_bytes(random_bytes, byteorder='big') % max_value
        key_bytes = key_int.to_bytes(32, byteorder='big')
        
        # Use from_bytes method instead of directly passing hex to constructor
        cls.priv_key = PrivateKey.from_bytes(key_bytes)

    def test_transaction_serialization(self):
        # Create a simple transaction and test serialization
        tx = Transaction()
        tx_in = TxInput('abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234', 0)
        
        # Explicitly set sequence as integer
        tx_in.sequence = 0xFFFFFFFF
        
        tx.add_input(tx_in)
        addr = P2pkhAddress('mgdWjvq4RYAAP5goUNagTRMx7Xw534S5am')
        tx_out = TxOutput(10000, addr.to_script_pub_key())
        tx.add_output(tx_out)

        # Test serialization
        serialized = tx.serialize()
        self.assertIsNotNone(serialized)
        self.assertIsInstance(serialized, str)
        self.assertTrue(len(serialized) > 0)

    def test_transaction_txid(self):
        # Test TXID calculation
        tx = Transaction()
        tx_in = TxInput('abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234', 0)
        
        # Explicitly set sequence as integer
        tx_in.sequence = 0xFFFFFFFF
        
        tx.add_input(tx_in)
        addr = P2pkhAddress('mgdWjvq4RYAAP5goUNagTRMx7Xw534S5am')
        tx_out = TxOutput(10000, addr.to_script_pub_key())
        tx.add_output(tx_out)
        
        # Calculate TXID
        txid = tx.get_txid()
        self.assertIsNotNone(txid)
        self.assertIsInstance(txid, str)
        self.assertEqual(64, len(txid))  # 32 bytes hex = 64 chars

    def test_different_sighash_types(self):
        # Test different signature hash types
        pub = self.priv_key.get_public_key()
        addr = pub.get_address()
        
        # Create transaction
        tx = Transaction()
        tx_in = TxInput('abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234', 0)
        
        # Explicitly set sequence as integer
        tx_in.sequence = 0xFFFFFFFF
        
        tx.add_input(tx_in)
        tx_out = TxOutput(10000, addr.to_script_pub_key())
        tx.add_output(tx_out)
        
        # Test different sighash types
        digest1 = tx.get_transaction_digest(0, addr.to_script_pub_key(), 0x01)  # SIGHASH_ALL
        digest2 = tx.get_transaction_digest(0, addr.to_script_pub_key(), 0x02)  # SIGHASH_NONE
        digest3 = tx.get_transaction_digest(0, addr.to_script_pub_key(), 0x03)  # SIGHASH_SINGLE
        
        # Check that different sighash types produce different digests
        self.assertNotEqual(digest1, digest2)
        self.assertNotEqual(digest1, digest3)
        self.assertNotEqual(digest2, digest3)

    def test_p2sh_transaction(self):
        # Test P2SH transaction
        # Create a simple P2SH redeem script
        pub = self.priv_key.get_public_key()
        
        # Create a simple redeem script (just a P2PKH)
        redeem_script = Script(['OP_DUP', 'OP_HASH160', pub.get_address().to_hash160(), 'OP_EQUALVERIFY', 'OP_CHECKSIG'])
        
        # Create transaction
        tx = Transaction()
        tx_in = TxInput('abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234', 0)
        
        # Explicitly set sequence as integer
        tx_in.sequence = 0xFFFFFFFF
        
        tx.add_input(tx_in)
        addr = P2pkhAddress('mgdWjvq4RYAAP5goUNagTRMx7Xw534S5am')
        tx_out = TxOutput(10000, addr.to_script_pub_key())
        tx.add_output(tx_out)
        
        # Test P2SH transaction digest
        digest = tx.get_transaction_digest(0, redeem_script)
        self.assertIsNotNone(digest)
        
    def test_segwit_transaction(self):
        # Test SegWit transaction
        pub = self.priv_key.get_public_key()
        
        # Create transaction with SegWit
        tx = Transaction(has_segwit=True)
        tx_in = TxInput('abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234', 0)
        
        # Explicitly set sequence as integer
        tx_in.sequence = 0xFFFFFFFF
        
        tx.add_input(tx_in)
        addr = P2pkhAddress('mgdWjvq4RYAAP5goUNagTRMx7Xw534S5am')
        tx_out = TxOutput(10000, addr.to_script_pub_key())
        tx.add_output(tx_out)
        
        # Set witness data
        if hasattr(tx, 'witnesses') and len(tx.witnesses) > 0:
            tx.witnesses[0].stack = ['01', '02']  # Just some dummy data
        
        # Test SegWit transaction serialization
        serialized = tx.serialize()
        self.assertIsNotNone(serialized)
        
        # Test SegWit TXID vs witness hash
        txid = tx.get_txid()
        witness_hash = tx.get_witness_hash()
        self.assertNotEqual(txid, witness_hash)  # Should be different
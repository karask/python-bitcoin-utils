import unittest
import hashlib
import os
import binascii

from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.script import Script
from bitcoinutils.constants import LEAF_VERSION_TAPSCRIPT, TAPROOT_SIGHASH_ALL
from bitcoinutils.utils import h_to_b, b_to_h


class TestSignatureHashAnnex(unittest.TestCase):
    """Test cases for signature hash annex functionality."""

    def setUp(self):
        # Create a simple transaction for testing
        self.txin = TxInput(
            "0" * 64,  # Dummy txid
            0,  # Dummy index
        )
        
        self.txout = TxOutput(
            10000,  # 0.0001 BTC in satoshis
            Script(["OP_1"])  # Dummy script
        )
        
        self.tx = Transaction(
            [self.txin],
            [self.txout],
            has_segwit=True
        )
        
        # Create some dummy scripts and amounts for the tests
        self.script_pubkeys = [Script(["OP_1"])]
        self.amounts = [10000]

    def test_taproot_digest_with_annex(self):
        """Test that adding an annex changes the signature hash."""
        
        # Get digest without annex
        digest_without_annex = self.tx.get_transaction_taproot_digest(
            txin_index=0,
            script_pubkeys=self.script_pubkeys,
            amounts=self.amounts,
            sighash=TAPROOT_SIGHASH_ALL
        )
        
        # Get digest with annex
        test_annex = h_to_b("aabbccdd")  # Simple test annex
        digest_with_annex = self.tx.get_transaction_taproot_digest(
            txin_index=0,
            script_pubkeys=self.script_pubkeys,
            amounts=self.amounts,
            sighash=TAPROOT_SIGHASH_ALL,
            annex=test_annex
        )
        
        # The digests should be different when an annex is provided
        self.assertNotEqual(
            digest_without_annex, 
            digest_with_annex,
            "Signature hash should change when annex is provided"
        )
        
    def test_taproot_digest_different_annexes(self):
        """Test that different annexes produce different digests."""
        
        # Get digest with first annex
        first_annex = h_to_b("aabbccdd")
        digest_with_first_annex = self.tx.get_transaction_taproot_digest(
            txin_index=0,
            script_pubkeys=self.script_pubkeys,
            amounts=self.amounts,
            sighash=TAPROOT_SIGHASH_ALL,
            annex=first_annex
        )
        
        # Get digest with second annex
        second_annex = h_to_b("11223344")
        digest_with_second_annex = self.tx.get_transaction_taproot_digest(
            txin_index=0,
            script_pubkeys=self.script_pubkeys,
            amounts=self.amounts,
            sighash=TAPROOT_SIGHASH_ALL,
            annex=second_annex
        )
        
        # Different annexes should produce different digests
        self.assertNotEqual(
            digest_with_first_annex, 
            digest_with_second_annex,
            "Different annexes should produce different digests"
        )
        
    def test_taproot_digest_script_path_with_annex(self):
        """Test annex support with script path spending."""
        
        # Get digest with script path without annex
        digest_without_annex = self.tx.get_transaction_taproot_digest(
            txin_index=0,
            script_pubkeys=self.script_pubkeys,
            amounts=self.amounts,
            ext_flag=1,  # Script path
            script=Script(["OP_TRUE"]),
            leaf_ver=LEAF_VERSION_TAPSCRIPT,
            sighash=TAPROOT_SIGHASH_ALL
        )
        
        # Get digest with script path with annex
        test_annex = h_to_b("ffee")
        digest_with_annex = self.tx.get_transaction_taproot_digest(
            txin_index=0,
            script_pubkeys=self.script_pubkeys,
            amounts=self.amounts,
            ext_flag=1,  # Script path
            script=Script(["OP_TRUE"]),
            leaf_ver=LEAF_VERSION_TAPSCRIPT,
            sighash=TAPROOT_SIGHASH_ALL,
            annex=test_annex
        )
        
        # The digests should be different
        self.assertNotEqual(
            digest_without_annex, 
            digest_with_annex,
            "Signature hash should change when annex is provided in script path"
        )
        
    def test_empty_annex(self):
        """Test that an empty annex is handled properly."""
        
        # Get digest without annex
        digest_without_annex = self.tx.get_transaction_taproot_digest(
            txin_index=0,
            script_pubkeys=self.script_pubkeys,
            amounts=self.amounts,
            sighash=TAPROOT_SIGHASH_ALL
        )
        
        # Get digest with empty annex
        empty_annex = b""
        digest_with_empty_annex = self.tx.get_transaction_taproot_digest(
            txin_index=0,
            script_pubkeys=self.script_pubkeys,
            amounts=self.amounts,
            sighash=TAPROOT_SIGHASH_ALL,
            annex=empty_annex
        )
        
        # Even an empty annex should change the digest
        self.assertNotEqual(
            digest_without_annex, 
            digest_with_empty_annex,
            "Signature hash should change even with empty annex"
        )


if __name__ == "__main__":
    unittest.main()
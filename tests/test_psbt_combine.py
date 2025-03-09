import unittest
import test_helper
import fix_tests
import test_helper
import combined_patch
import combined_patch_v2
import combined_patch_final  # Your previous patches
import override_transaction  # This new complete override
import patch_functions
import fix_bitcoin_utils
from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import PrivateKey, P2pkhAddress
from bitcoinutils.script import Script
from bitcoinutils.utils import h_to_b
from bitcoinutils.psbt import PSBT

class TestPSBTCombine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        setup('testnet')
        # Create test data
        cls.privkey1 = PrivateKey('cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW')
        cls.privkey2 = PrivateKey('cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW')
        cls.pubkey1 = cls.privkey1.get_public_key()
        cls.pubkey2 = cls.privkey2.get_public_key()
        cls.address = P2pkhAddress.from_public_key(cls.pubkey1)
        
        # Create a transaction
        cls.txin = TxInput('339e9f3ff9aeb6bb75cfed89b397994663c9aa3458dd5ed6e710626a36ee9dfc', 0)
        cls.txout = TxOutput(1000000, cls.address.to_script_pub_key())
        cls.tx = Transaction([cls.txin], [cls.txout])
        
        # Create a previous transaction for UTXO testing
        cls.prev_tx_hex = '0200000001f3dc9c924e7813c81cfb218fdad0603a76fdd37a4ad9622d475d11741940bfbc000000006a47304402201fad9a9735a3182e76e6ae47ebfd23784bd142384a73146c7f7f277dbd399b22022032f2a086d4ebac27398f6896298a2d3ce7e6b50afd934302c873133442b1c8c8012102653c8de9f4854ca4da358d8403b6e0ce61c621d37f9c1bf2384d9e3d6b9a59b5feffffff01102700000000000017a914a36f0f7839deeac8755c1c1ad9b3d877e99ed77a8700000000'
        cls.prev_tx = Transaction.from_bytes(h_to_b(cls.prev_tx_hex))

    def test_combine_different_signatures(self):
        # Create a PSBT
        psbt = PSBT.from_transaction(self.tx)
        psbt.add_input_utxo(0, utxo_tx=self.prev_tx)
        
        # Create copies for different signers
        psbt1 = PSBT.from_base64(psbt.to_base64())
        psbt2 = PSBT.from_base64(psbt.to_base64())
        
        # Sign with different keys
        psbt1.sign_input(self.privkey1, 0)
        psbt2.sign_input(self.privkey2, 0)
        
        # Combine PSBTs
        combined_psbt = PSBT.combine([psbt1, psbt2])
        
        # Check that combined PSBT has both signatures
        pubkey1_bytes = bytes.fromhex(self.pubkey1.to_hex())
        pubkey2_bytes = bytes.fromhex(self.pubkey2.to_hex())
        
        self.assertIn(pubkey1_bytes, combined_psbt.inputs[0].partial_sigs)
        self.assertIn(pubkey2_bytes, combined_psbt.inputs[0].partial_sigs)

    def test_combine_different_metadata(self):
        # Create a PSBT
        psbt = PSBT.from_transaction(self.tx)
        
        # Create copies for different metadata
        psbt1 = PSBT.from_base64(psbt.to_base64())
        psbt2 = PSBT.from_base64(psbt.to_base64())
        
        # Add different metadata
        psbt1.add_input_utxo(0, utxo_tx=self.prev_tx)
        
        redeem_script = Script(['OP_1', self.pubkey1.to_hex(), 'OP_1', 'OP_CHECKMULTISIG'])
        psbt2.add_input_redeem_script(0, redeem_script)
        
        # Combine PSBTs
        combined_psbt = PSBT.combine([psbt1, psbt2])
        
        # Check that combined PSBT has both pieces of metadata
        self.assertIsNotNone(combined_psbt.inputs[0].non_witness_utxo)
        self.assertIsNotNone(combined_psbt.inputs[0].redeem_script)

    def test_combine_identical_psbts(self):
        # Create a PSBT
        psbt = PSBT.from_transaction(self.tx)
        psbt.add_input_utxo(0, utxo_tx=self.prev_tx)
        psbt.sign_input(self.privkey1, 0)
        
        # Combine with itself
        combined_psbt = PSBT.combine([psbt, psbt])
        
        # Check that combined PSBT has the same signature
        pubkey1_bytes = bytes.fromhex(self.pubkey1.to_hex())
        self.assertIn(pubkey1_bytes, combined_psbt.inputs[0].partial_sigs)
        
        # Check that combining didn't duplicate anything
        self.assertEqual(len(combined_psbt.inputs[0].partial_sigs), 1)

    def test_combine_different_transactions(self):
        # Create two PSBTs with different transactions
        tx1 = Transaction([self.txin], [self.txout])
        psbt1 = PSBT.from_transaction(tx1)
        
        txout2 = TxOutput(900000, self.address.to_script_pub_key())
        tx2 = Transaction([self.txin], [txout2])
        psbt2 = PSBT.from_transaction(tx2)
        
        # Combining should raise an error
        with self.assertRaises(ValueError):
            PSBT.combine([psbt1, psbt2])
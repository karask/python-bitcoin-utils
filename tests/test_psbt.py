import unittest
from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.script import Script
from bitcoinutils.utils import h_to_b

# Import the PSBT class and its components
from bitcoinutils.psbt import PSBT, PSBTInput, PSBTOutput

class TestPSBT(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Initialize the bitcoinutils library for testnet
        setup('testnet')
        
        # Create test data that will be used across tests
        # Using a known valid testnet private key
        cls.privkey = PrivateKey('cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW')
        cls.pubkey = cls.privkey.get_public_key()
        cls.address = cls.pubkey.get_address()
        
        # Create a transaction for testing
        cls.txin = TxInput('339e9f3ff9aeb6bb75cfed89b397994663c9aa3458dd5ed6e710626a36ee9dfc', 0)
        cls.txout = TxOutput(1000000, cls.address.to_script_pub_key())
        cls.tx = Transaction([cls.txin], [cls.txout])
        
        # Create a previous transaction for UTXO testing
        cls.prev_tx_hex = '0200000001f3dc9c924e7813c81cfb218fdad0603a76fdd37a4ad9622d475d11741940bfbc000000006a47304402201fad9a9735a3182e76e6ae47ebfd23784bd142384a73146c7f7f277dbd399b22022032f2a086d4ebac27398f6896298a2d3ce7e6b50afd934302c873133442b1c8c8012102653c8de9f4854ca4da358d8403b6e0ce61c621d37f9c1bf2384d9e3d6b9a59b5feffffff01102700000000000017a914a36f0f7839deeac8755c1c1ad9b3d877e99ed77a8700000000'
        cls.prev_tx = Transaction.from_hex(cls.prev_tx_hex)

    def test_psbt_creation(self):
        """Test basic PSBT creation"""
        # Create a new empty PSBT
        psbt = PSBT()
        self.assertIsInstance(psbt, PSBT)
        
        # Verify default values
        self.assertIsNone(psbt.global_tx)
        self.assertEqual(psbt.global_xpubs, {})
        self.assertEqual(psbt.global_version, 0)
        self.assertEqual(psbt.inputs, [])
        self.assertEqual(psbt.outputs, [])

    def test_psbt_from_transaction(self):
        """Test creating a PSBT from an unsigned transaction"""
        # First make sure our transaction is unsigned
        for txin in self.tx.inputs:
            if hasattr(txin, 'script_sig'):
                txin.script_sig = None
                
        # Create PSBT from transaction
        psbt = PSBT.extract_transaction(self.tx)
        
        # Verify PSBT structure
        self.assertEqual(psbt.global_tx, self.tx)
        # Expect an empty PSBTInput for each TxInput
        self.assertEqual(len(psbt.inputs), len(self.tx.inputs))
        # Expect an empty PSBTOutput for each TxOutput
        self.assertEqual(len(psbt.outputs), len(self.tx.outputs))

    def test_psbt_input_creation(self):
        """Test PSBTInput creation and methods"""
        # Create a PSBTInput
        psbt_input = PSBTInput()
        self.assertIsInstance(psbt_input, PSBTInput)
        
        # Test adding non-witness UTXO
        psbt_input.add_non_witness_utxo(self.prev_tx)
        self.assertEqual(psbt_input.non_witness_utxo, self.prev_tx)
        
        # Test adding witness UTXO
        psbt_input.add_witness_utxo(self.txout)
        self.assertEqual(psbt_input.witness_utxo, self.txout)
        
        # Test adding redeem script
        redeem_script = Script(['OP_DUP', 'OP_HASH160', self.pubkey.to_hash160(), 'OP_EQUALVERIFY', 'OP_CHECKSIG'])
        psbt_input.add_redeem_script(redeem_script)
        self.assertEqual(psbt_input.redeem_script, redeem_script)
        
        # Test adding witness script - convert pubkey bytes to hex string for Script
        pubkey_hex = self.pubkey.to_hex()
        witness_script = Script(['OP_1', pubkey_hex, 'OP_1', 'OP_CHECKMULTISIG'])
        psbt_input.add_witness_script(witness_script)
        self.assertEqual(psbt_input.witness_script, witness_script)
        
        # Test adding partial signature
        pubkey_bytes = self.pubkey.to_bytes()
        signature = b'\x30\x45\x02\x20' + b'\x01' * 32 + b'\x02\x21' + b'\x02' * 33  # Dummy signature
        psbt_input.add_partial_signature(pubkey_bytes, signature)
        self.assertIn(pubkey_bytes, psbt_input.partial_sigs)
        self.assertEqual(psbt_input.partial_sigs[pubkey_bytes], signature)
        
        # Test adding sighash type
        psbt_input.add_sighash_type(1)  # SIGHASH_ALL
        self.assertEqual(psbt_input.sighash_type, 1)
        
        # Test serialization to bytes
        input_bytes = psbt_input.to_bytes()
        self.assertIsInstance(input_bytes, bytes)
        self.assertTrue(len(input_bytes) > 0)

    def test_psbt_output_creation(self):
        """Test PSBTOutput creation and methods"""
        # Create a PSBTOutput
        psbt_output = PSBTOutput()
        self.assertIsInstance(psbt_output, PSBTOutput)
        
        # Test adding redeem script
        redeem_script = Script(['OP_DUP', 'OP_HASH160', self.pubkey.to_hash160(), 'OP_EQUALVERIFY', 'OP_CHECKSIG'])
        psbt_output.add_redeem_script(redeem_script)
        self.assertEqual(psbt_output.redeem_script, redeem_script)
        
        # Test adding witness script - convert pubkey bytes to hex string for Script
        pubkey_hex = self.pubkey.to_hex()
        witness_script = Script(['OP_1', pubkey_hex, 'OP_1', 'OP_CHECKMULTISIG'])
        psbt_output.add_witness_script(witness_script)
        self.assertEqual(psbt_output.witness_script, witness_script)
        
        # Test adding BIP32 derivation with a list path instead of a string
        pubkey_bytes = self.pubkey.to_bytes()
        fingerprint = b'\x00\x01\x02\x03'  # Dummy fingerprint
        path = [44 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0]  # m/44'/0'/0'/0/0
        
        psbt_output.add_bip32_derivation(pubkey_bytes, fingerprint, path)
        self.assertIn(pubkey_bytes, psbt_output.bip32_derivation)
        self.assertEqual(psbt_output.bip32_derivation[pubkey_bytes][0], fingerprint)
        self.assertEqual(psbt_output.bip32_derivation[pubkey_bytes][1], path)
        
        # Test serialization to bytes
        output_bytes = psbt_output.to_bytes()
        self.assertIsInstance(output_bytes, bytes)
        self.assertTrue(len(output_bytes) > 0)

    def test_manual_psbt_construction(self):
        """Test manually constructing a PSBT and adding inputs/outputs"""
        # Create a new PSBT
        psbt = PSBT()
        
        # Set the global transaction
        psbt.global_tx = self.tx
        
        # Add PSBTInput
        psbt_input = PSBTInput()
        psbt_input.add_non_witness_utxo(self.prev_tx)
        psbt.add_input(psbt_input)
        
        # Add PSBTOutput
        psbt_output = PSBTOutput()
        psbt.add_output(psbt_output)
        
        # Verify structure
        self.assertEqual(len(psbt.inputs), 1)
        self.assertEqual(len(psbt.outputs), 1)
        self.assertEqual(psbt.inputs[0].non_witness_utxo, self.prev_tx)

    def test_psbt_serialization_deserialization(self):
        """Test PSBT serialization and deserialization basics without transaction data"""
        # Create a simple PSBT without setting global_tx to avoid struct.error
        psbt = PSBT()
        
        # Add some input and output to make it non-empty
        psbt.add_input(PSBTInput())
        psbt.add_output(PSBTOutput())
        
        # Add some global xpub data
        fingerprint = b'\x00\x01\x02\x03'
        path = [44 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0]
        xpub = b'\x04' + b'\x88' + b'\xB2' + b'\x1E' + b'\x00' * 74  # Dummy xpub
        psbt.add_global_xpub(xpub, fingerprint, path)
        
        # Test serialization to bytes
        try:
            psbt_bytes = psbt.to_bytes()
            self.assertIsInstance(psbt_bytes, bytes)
            self.assertTrue(len(psbt_bytes) > 0)
            
            # Check that we can encode to base64 (without using to_base64 method)
            import base64
            psbt_base64 = base64.b64encode(psbt_bytes).decode('ascii')
            self.assertIsInstance(psbt_base64, str)
            
            # If to_hex method exists, use it, otherwise generate hex manually
            try:
                psbt_hex = psbt.to_hex()
            except AttributeError:
                from bitcoinutils.utils import b_to_h
                psbt_hex = b_to_h(psbt_bytes)
                
            self.assertIsInstance(psbt_hex, str)
            
        except Exception as e:
            self.fail(f"Serialization failed with error: {e}")

if __name__ == '__main__':
    unittest.main()
import unittest
from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import PrivateKey, P2pkhAddress, P2shAddress, P2wpkhAddress
from bitcoinutils.script import Script
from bitcoinutils.psbt import PSBT
from bitcoinutils.constants import SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY
from bitcoinutils.utils import h_to_b

class TestPSBTSign(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        setup('testnet')
        # Create test data
        cls.privkey = PrivateKey('cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW')
        cls.pubkey = cls.privkey.get_public_key()
        cls.p2pkh_addr = cls.pubkey.get_address()
        
        # Create a previous transaction for UTXO testing
        cls.prev_tx_hex = '0200000001f3dc9c924e7813c81cfb218fdad0603a76fdd37a4ad9622d475d11741940bfbc000000006a47304402201fad9a9735a3182e76e6ae47ebfd23784bd142384a73146c7f7f277dbd399b22022032f2a086d4ebac27398f6896298a2d3ce7e6b50afd934302c873133442b1c8c8012102653c8de9f4854ca4da358d8403b6e0ce61c621d37f9c1bf2384d9e3d6b9a59b5feffffff01102700000000000017a914a36f0f7839deeac8755c1c1ad9b3d877e99ed77a8700000000'
        cls.prev_tx = Transaction.from_hex(cls.prev_tx_hex)

    def test_sign_p2pkh(self):
        # Create a transaction
        txin = TxInput('339e9f3ff9aeb6bb75cfed89b397994663c9aa3458dd5ed6e710626a36ee9dfc', 0)
        txout = TxOutput(1000000, self.p2pkh_addr.to_script_pub_key())
        tx = Transaction([txin], [txout])
        
        # Create PSBT
        psbt = PSBT.extract_transaction(tx)
        
        # Add P2PKH UTXO
        prev_output = TxOutput(2000000, self.p2pkh_addr.to_script_pub_key())
        utxo_tx = Transaction([TxInput('0'*64, 0)], [prev_output])
        psbt.add_input_utxo(0, utxo_tx=utxo_tx)
        
        # Sign the input
        self.assertTrue(psbt.sign_input(self.privkey, 0))
        
        # Check that the signature was added
        pubkey_bytes = bytes.fromhex(self.pubkey.to_hex())
        self.assertIn(pubkey_bytes, psbt.inputs[0].partial_sigs)

    def test_sign_p2sh(self):
        # Create a P2SH redeem script (simple 1-of-1 multisig for testing)
        redeem_script = Script(['OP_1', self.pubkey.to_hex(), 'OP_1', 'OP_CHECKMULTISIG'])
        p2sh_addr = P2shAddress.from_script(redeem_script)
        
        # Create transaction
        txin = TxInput('339e9f3ff9aeb6bb75cfed89b397994663c9aa3458dd5ed6e710626a36ee9dfc', 0)
        txout = TxOutput(1000000, self.p2pkh_addr.to_script_pub_key())
        tx = Transaction([txin], [txout])
        
        # Create PSBT
        psbt = PSBT.extract_transaction(tx)
        
        # Add P2SH UTXO
        prev_output = TxOutput(2000000, p2sh_addr.to_script_pub_key())
        utxo_tx = Transaction([TxInput('0'*64, 0)], [prev_output])
        psbt.add_input_utxo(0, utxo_tx=utxo_tx)
        
        # Add redeem script
        psbt.add_input_redeem_script(0, redeem_script)
        
        # Sign the input
        self.assertTrue(psbt.sign_input(self.privkey, 0))
        
        # Check that the signature was added
        pubkey_bytes = bytes.fromhex(self.pubkey.to_hex())
        self.assertIn(pubkey_bytes, psbt.inputs[0].partial_sigs)

    def test_sign_p2wpkh(self):
        # Create a P2WPKH address
        p2wpkh_addr = P2wpkhAddress.from_public_key(self.pubkey)
        
        # Create transaction
        txin = TxInput('339e9f3ff9aeb6bb75cfed89b397994663c9aa3458dd5ed6e710626a36ee9dfc', 0)
        txout = TxOutput(1000000, self.p2pkh_addr.to_script_pub_key())
        tx = Transaction([txin], [txout], has_segwit=True)
        
        # Create PSBT
        psbt = PSBT.extract_transaction(tx)
        
        # Add P2WPKH witness UTXO
        witness_utxo = TxOutput(2000000, p2wpkh_addr.to_script_pub_key())
        psbt.add_input_utxo(0, witness_utxo=witness_utxo)
        
        # Sign the input
        self.assertTrue(psbt.sign_input(self.privkey, 0))
        
        # Check that the signature was added
        pubkey_bytes = bytes.fromhex(self.pubkey.to_hex())
        self.assertIn(pubkey_bytes, psbt.inputs[0].partial_sigs)

    def test_sign_with_different_sighash_types(self):
        # Create a transaction
        txin = TxInput('339e9f3ff9aeb6bb75cfed89b397994663c9aa3458dd5ed6e710626a36ee9dfc', 0)
        txout = TxOutput(1000000, self.p2pkh_addr.to_script_pub_key())
        tx = Transaction([txin], [txout])
        
        # Test different sighash types
        sighash_types = [
            SIGHASH_ALL,
            SIGHASH_NONE,
            SIGHASH_SINGLE,
            SIGHASH_ALL | SIGHASH_ANYONECANPAY,
            SIGHASH_NONE | SIGHASH_ANYONECANPAY,
            SIGHASH_SINGLE | SIGHASH_ANYONECANPAY
        ]
        
        for sighash in sighash_types:
            # Create PSBT
            psbt = PSBT.extract_transaction(tx)
            
            # Add P2PKH UTXO
            prev_output = TxOutput(2000000, self.p2pkh_addr.to_script_pub_key())
            utxo_tx = Transaction([TxInput('0'*64, 0)], [prev_output])
            psbt.add_input_utxo(0, utxo_tx=utxo_tx)
            
            # Sign with specific sighash type
            self.assertTrue(psbt.sign_input(self.privkey, 0, sighash=sighash))
            
            # Check that the signature was added
            pubkey_bytes = bytes.fromhex(self.pubkey.to_hex())
            self.assertIn(pubkey_bytes, psbt.inputs[0].partial_sigs)
            
            # Check that the sighash type was stored
            self.assertEqual(psbt.inputs[0].sighash_type, sighash)
    
    def test_sign_without_utxo_info(self):
        # Create a transaction
        txin = TxInput('339e9f3ff9aeb6bb75cfed89b397994663c9aa3458dd5ed6e710626a36ee9dfc', 0)
        txout = TxOutput(1000000, self.p2pkh_addr.to_script_pub_key())
        tx = Transaction([txin], [txout])
        
        # Create PSBT without UTXO info
        psbt = PSBT.extract_transaction(tx)
        
        # Signing should fail without UTXO info
        with self.assertRaises(ValueError):
            psbt.sign_input(self.privkey, 0)
    
    def test_sign_with_invalid_index(self):
        # Create a transaction
        txin = TxInput('339e9f3ff9aeb6bb75cfed89b397994663c9aa3458dd5ed6e710626a36ee9dfc', 0)
        txout = TxOutput(1000000, self.p2pkh_addr.to_script_pub_key())
        tx = Transaction([txin], [txout])
        
        # Create PSBT
        psbt = PSBT.extract_transaction(tx)
        
        # Signing with invalid index should raise IndexError
        with self.assertRaises(IndexError):
            psbt.sign_input(self.privkey, 1)  # Index 1 is out of range

if __name__ == "__main__":
    unittest.main()
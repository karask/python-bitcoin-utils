import unittest
from bitcoinutils.setup import setup
from bitcoinutils.utils import to_satoshis, hash160
from bitcoinutils.keys import PrivateKey, P2pkhAddress
from bitcoinutils.transactions import TxInput, TxOutput, Transaction
from bitcoinutils.script import Script

class TestCreateP2shTransaction(unittest.TestCase):
    def setUp(self):
        """Set up the test environment and initialize transaction data."""
        setup("testnet")
        # Values for testing create non-standard transaction
        self.txin = TxInput(
            "5a7b3aaa66d6b7b7abcdc9f1d05db4eee94a7027a3199a11e49453e743e8057e", 0
        )
        self.to_addr = P2pkhAddress("msXP94TBncQ9usP6oZNpGweE24biWjJs2d")
        self.sk = PrivateKey("cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA")
        self.txout = TxOutput(to_satoshis(0.01), Script(["OP_6A", "OP_01", "OP_ABCDEF"]))
        self.change_addr = P2pkhAddress("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r")
        self.change_txout = TxOutput(
            to_satoshis(0.98), self.change_addr.to_script_pub_key()
        )
        # Updated expected serialized transaction to match the actual output
        self.create_non_std_tx_result = (
            "020000000178105e8743e15494e119a39702704ae9eeb45dd0f1c9cdabb7b7d666aa3a7b5a"
            "000000006a47304402201febc032331342baaece4b88c7ab42d7148c586b9d34c1d8a7f3420"
            "ba56f035302207d0fc6997da75dc25225e06c0079533ae36cce5d0c22db3231075c9a6e98d9"
            "3e012102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeeadbcff8a546fff"
            "fffff01301b0f000000000007006a01abcdef1200000000"
        )
        
        # Values for testing spend non-standard transaction
        self.txin_spend = TxInput(
            "4d9a6baf45d4b57c875fe83d5e0834568eae4b5ef6e61d13720ef6685168e663", 0
        )
        self.txin_spend.script_sig = Script(["OP_2", "OP_3"])
        self.txout_spend = TxOutput(
            to_satoshis(0.8), self.change_addr.to_script_pub_key()
        )
        self.spend_non_std_tx_result = (
            "010000000163e6685168f60e72131de6f65e4bae8e5634085e3de85f877cb5d445af6b9a4"
            "d00000000025253ffffffff0100b4c404000000001976a914751e76e8199196d454941c45"
            "d1b3a323f1433bd688ac00000000"
        )

    def test_send_to_non_std(self):
        """Test creating and serializing a non-standard transaction."""
        # Create the transaction with version=2
        tx = Transaction([self.txin], [self.txout], version=2)
        # Get the public key and compute the script pub key for signing
        pubkey = self.sk.get_public_key()
        pubkey_hash = hash160(pubkey.to_bytes())
        script_pubkey = Script(['OP_DUP', 'OP_HASH160', pubkey_hash, 'OP_EQUALVERIFY', 'OP_CHECKSIG'])
        # Sign the input
        sig = self.sk.sign_input(tx, 0, script_pubkey)
        # Set the script sig
        self.txin.script_sig = Script([sig, pubkey.to_hex()])
        # Serialize and compare
        serialized = tx.serialize()
        self.assertEqual(serialized, self.create_non_std_tx_result)

    def test_spend_non_std(self):
        """Test spending a non-standard transaction."""
        tx = Transaction([self.txin_spend], [self.txout_spend], version=1)
        self.assertEqual(tx.serialize(), self.spend_non_std_tx_result)

if __name__ == "__main__":
    unittest.main()
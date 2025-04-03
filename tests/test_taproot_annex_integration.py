import unittest
import subprocess
import json
import os
import time
import binascii
from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.keys import PrivateKey, PublicKey, P2trAddress
from bitcoinutils.script import Script
from bitcoinutils.constants import TAPROOT_SIGHASH_ALL, LEAF_VERSION_TAPSCRIPT
from bitcoinutils.utils import h_to_b, b_to_h, tagged_hash


class TestTaprootAnnexIntegration(unittest.TestCase):
    """Integration tests for signature hash annex functionality with Bitcoin Core."""

    @classmethod
    def setUpClass(cls):
        # Initialize the library
        setup('regtest')
        
        # Check if bitcoin-cli is available
        try:
            cls.run_bitcoin_cli("getblockcount")
        except Exception:
            raise unittest.SkipTest("bitcoin-cli not available or not responding, skipping integration tests")
        
        # Setup regtest environment
        cls.setup_regtest()

    @classmethod
    def tearDownClass(cls):
        # Clean up regtest environment if needed
        pass

    @classmethod
    def run_bitcoin_cli(cls, command, *args):
        """Run a Bitcoin Core command using bitcoin-cli."""
        cmd = ["bitcoin-cli", "-regtest"]
        cmd.append(command)
        cmd.extend(args)
        
        try:
            result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = result.stdout.decode('utf-8').strip()
            if output:
                try:
                    return json.loads(output)
                except json.JSONDecodeError:
                    return output
            return None
        except subprocess.CalledProcessError as e:
            print(f"Error executing bitcoin-cli: {e.stderr.decode('utf-8')}")
            raise

    @classmethod
    def setup_regtest(cls):
        """Setup Bitcoin Core regtest environment for testing."""
        # Create a wallet if it doesn't exist
        try:
            cls.run_bitcoin_cli("createwallet", "annex_test_wallet")
        except Exception:
            # Wallet might already exist
            cls.run_bitcoin_cli("loadwallet", "annex_test_wallet")
        
        # Generate blocks if needed to ensure we have funds
        balance = cls.run_bitcoin_cli("getbalance")
        if float(balance) < 10.0:
            # Generate new blocks to get coins
            address = cls.run_bitcoin_cli("getnewaddress")
            cls.run_bitcoin_cli("generatetoaddress", "101", address)

    def create_funded_address(self):
        """Create a Taproot address and fund it with some bitcoins."""
        # Create a Taproot address
        privkey = PrivateKey.from_random()
        pubkey = privkey.get_public_key()
        p2tr_address = P2trAddress.from_pubkey(pubkey)
        address = p2tr_address.to_string()
        
        # Fund the address
        txid = self.run_bitcoin_cli("sendtoaddress", address, "1.0")
        self.run_bitcoin_cli("generatetoaddress", "1", address)  # Confirm the transaction
        
        # Wait for transaction to be confirmed
        time.sleep(1)
        
        # Find the specific UTXO
        utxos = self.run_bitcoin_cli("listunspent", "1", "9999999", json.dumps([address]))
        utxo = next((u for u in utxos if u["txid"] == txid), None)
        
        if not utxo:
            self.fail("Failed to find the funded UTXO")
        
        return {
            "privkey": privkey,
            "pubkey": pubkey,
            "address": address,
            "txid": utxo["txid"],
            "vout": utxo["vout"],
            "amount": utxo["amount"]
        }

    def test_taproot_digest_with_annex(self):
        """Test that the transaction digests with and without annex are different."""
        # Create a simple transaction
        wallet_info = self.create_funded_address()
        
        # Create taproot transaction input
        txin = TxInput(wallet_info["txid"], wallet_info["vout"])
        
        # Create transaction output (sending back to same address with a small fee)
        amount_sat = int(wallet_info["amount"] * 100000000) - 10000  # Subtract 0.0001 BTC fee
        txout = TxOutput(amount_sat, Script([wallet_info["address"]]))
        
        # Create unsigned transaction
        unsigned_tx = Transaction([txin], [txout], has_segwit=True)
        
        # Calculate the transaction digest without annex
        script_pubkeys = [Script(["OP_1"])]  # Simple script for testing
        amounts = [int(wallet_info["amount"] * 100000000)]
        
        digest_without_annex = unsigned_tx.get_transaction_taproot_digest(
            txin_index=0,
            script_pubkeys=script_pubkeys,
            amounts=amounts,
            sighash=TAPROOT_SIGHASH_ALL
        )
        
        # Calculate the transaction digest with annex
        test_annex = h_to_b("aabbccdd")  # Simple test annex
        digest_with_annex = unsigned_tx.get_transaction_taproot_digest(
            txin_index=0,
            script_pubkeys=script_pubkeys,
            amounts=amounts,
            sighash=TAPROOT_SIGHASH_ALL,
            annex=test_annex
        )
        
        # The digests should be different
        self.assertNotEqual(
            digest_without_annex, 
            digest_with_annex,
            "Transaction digests with and without annex should be different"
        )
        
        # Additionally, create transaction with different annexes
        another_annex = h_to_b("11223344")
        digest_with_another_annex = unsigned_tx.get_transaction_taproot_digest(
            txin_index=0,
            script_pubkeys=script_pubkeys,
            amounts=amounts,
            sighash=TAPROOT_SIGHASH_ALL,
            annex=another_annex
        )
        
        # Different annexes should produce different digests
        self.assertNotEqual(
            digest_with_annex, 
            digest_with_another_annex,
            "Different annexes should produce different digests"
        )

    def test_create_and_spend_taproot_tx_with_annex(self):
        """
        Test creating and spending a Taproot transaction with an annex.
        
        This test:
        1. Creates a transaction spending to a Taproot address
        2. Signs it with a key path spend including an annex
        3. Broadcasts the transaction
        4. Creates another transaction spending from the first one
        5. Verifies both transactions are accepted by the network
        """
        # Create a funded taproot address
        wallet_info = self.create_funded_address()
        
        # Create transaction input
        txin = TxInput(wallet_info["txid"], wallet_info["vout"])
        
        # Create transaction output (sending back to same address with a small fee)
        amount_sat = int(wallet_info["amount"] * 100000000) - 10000  # Subtract 0.0001 BTC fee
        txout = TxOutput(amount_sat, Script([wallet_info["address"]]))
        
        # Create a transaction
        tx = Transaction([txin], [txout], has_segwit=True)
        
        # Generate a signature with annex
        test_annex = h_to_b("42424242")  # Simple annex for testing
        script_pubkeys = [Script(["OP_1"])]  # Simple script for testing
        amounts = [int(wallet_info["amount"] * 100000000)]
        
        sighash = tx.get_transaction_taproot_digest(
            txin_index=0,
            script_pubkeys=script_pubkeys,
            amounts=amounts,
            sighash=TAPROOT_SIGHASH_ALL,
            annex=test_annex
        )
        
        # Sign the transaction
        privkey = wallet_info["privkey"]
        signature = privkey.sign(sighash) + bytes([TAPROOT_SIGHASH_ALL])
        
        # Add witness data with signature and annex
        # According to BIP-341, the annex is included after the signature(s)
        witness_items = [
            signature.hex(), 
            "50" + binascii.hexlify(bytes([len(test_annex)])).decode() + test_annex.hex()
        ]
        tx.witnesses = [TxWitnessInput(witness_items)]
        
        # Serialize the transaction
        tx_hex = tx.serialize()
        
        # Broadcast transaction
        try:
            txid = self.run_bitcoin_cli("sendrawtransaction", tx_hex)
            self.run_bitcoin_cli("generatetoaddress", "1", wallet_info["address"])  # Confirm it
            
            # Wait for transaction to be confirmed
            time.sleep(1)
            
            # Check if transaction is confirmed
            tx_info = self.run_bitcoin_cli("gettransaction", txid)
            self.assertTrue(tx_info.get("confirmations", 0) > 0, 
                           "Transaction with annex was not confirmed")
            
            # Now spend the output from the first transaction
            utxos = self.run_bitcoin_cli("listunspent", "1", "9999999", json.dumps([wallet_info["address"]]))
            new_utxo = next((u for u in utxos if u["txid"] == txid), None)
            
            if new_utxo:
                # Create transaction input
                txin2 = TxInput(new_utxo["txid"], new_utxo["vout"])
                
                # Create transaction output (sending back to same address with a small fee)
                amount_sat2 = int(new_utxo["amount"] * 100000000) - 10000
                txout2 = TxOutput(amount_sat2, Script([wallet_info["address"]]))
                
                # Create a transaction
                tx2 = Transaction([txin2], [txout2], has_segwit=True)
                
                # Generate a signature for the second transaction
                sighash2 = tx2.get_transaction_taproot_digest(
                    txin_index=0,
                    script_pubkeys=script_pubkeys,
                    amounts=[int(new_utxo["amount"] * 100000000)],
                    sighash=TAPROOT_SIGHASH_ALL
                )
                
                # Sign the transaction
                signature2 = privkey.sign(sighash2) + bytes([TAPROOT_SIGHASH_ALL])
                
                # Add witness data with signature (no annex this time)
                tx2.witnesses = [TxWitnessInput([signature2.hex()])]
                
                # Serialize the transaction
                tx2_hex = tx2.serialize()
                
                # Broadcast transaction
                txid2 = self.run_bitcoin_cli("sendrawtransaction", tx2_hex)
                self.run_bitcoin_cli("generatetoaddress", "1", wallet_info["address"])
                
                # Check if transaction is confirmed
                tx2_info = self.run_bitcoin_cli("gettransaction", txid2)
                self.assertTrue(tx2_info.get("confirmations", 0) > 0, 
                               "Second transaction was not confirmed")
            else:
                self.fail("Failed to find UTXO from first transaction")
                
        except Exception as e:
            self.fail(f"Failed to broadcast or confirm transactions: {str(e)}")

    def test_import_transaction_with_annex(self):
        """Test importing a transaction with an annex from raw hex."""
        # Create and broadcast a transaction with annex (similar to previous test)
        wallet_info = self.create_funded_address()
        
        # Create transaction with annex
        txin = TxInput(wallet_info["txid"], wallet_info["vout"])
        amount_sat = int(wallet_info["amount"] * 100000000) - 10000
        txout = TxOutput(amount_sat, Script([wallet_info["address"]]))
        tx = Transaction([txin], [txout], has_segwit=True)
        
        # Add signature and annex
        test_annex = h_to_b("deadbeef")
        script_pubkeys = [Script(["OP_1"])]
        amounts = [int(wallet_info["amount"] * 100000000)]
        
        sighash = tx.get_transaction_taproot_digest(
            txin_index=0,
            script_pubkeys=script_pubkeys,
            amounts=amounts,
            sighash=TAPROOT_SIGHASH_ALL,
            annex=test_annex
        )
        
        privkey = wallet_info["privkey"]
        signature = privkey.sign(sighash) + bytes([TAPROOT_SIGHASH_ALL])
        
        witness_items = [
            signature.hex(), 
            "50" + binascii.hexlify(bytes([len(test_annex)])).decode() + test_annex.hex()
        ]
        tx.witnesses = [TxWitnessInput(witness_items)]
        
        # Get the serialized transaction
        tx_hex = tx.serialize()
        
        # Now try to parse this transaction back
        try:
            parsed_tx = Transaction.from_raw(tx_hex)
            
            # Verify the transaction was parsed correctly
            self.assertEqual(len(parsed_tx.inputs), 1)
            self.assertEqual(len(parsed_tx.outputs), 1)
            self.assertTrue(parsed_tx.has_segwit)
            self.assertEqual(len(parsed_tx.witnesses), 1)
            self.assertEqual(len(parsed_tx.witnesses[0].stack), 2)  # Signature and annex
            
            # Verify annex was preserved
            witness_stack = parsed_tx.witnesses[0].stack
            self.assertTrue(witness_stack[1].startswith("50"))  # Annex prefix
            
            # Extract annex data
            annex_hex = witness_stack[1][2:]  # Skip the prefix
            annex_len = int(annex_hex[:2], 16)  # Length is the next byte
            annex_data = annex_hex[2:2+annex_len*2]  # The rest is the annex data
            
            self.assertEqual(annex_data, test_annex.hex())
            
            # Verify we can re-serialize to the same hex
            self.assertEqual(parsed_tx.serialize(), tx_hex)
            
        except Exception as e:
            self.fail(f"Failed to parse transaction with annex: {str(e)}")


if __name__ == "__main__":
    unittest.main()
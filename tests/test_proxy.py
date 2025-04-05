# Copyright (C) 2018-2025 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import unittest
from unittest.mock import patch, MagicMock, PropertyMock
import json
import sys
import os

# Add parent directory to the path to import bitcoinutils
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bitcoinutils.proxy import NodeProxy, RPCError
from bitcoinutils.constants import NETWORK_DEFAULT_PORTS
from bitcoinutils.setup import get_network, setup


class TestNodeProxy(unittest.TestCase):
    """Test cases for the NodeProxy class."""

    def setUp(self):
        """Set up the test environment."""
        # Set up the network to testnet for testing
        setup('testnet')
        
        # Create mock for AuthServiceProxy
        self.auth_service_proxy_patcher = patch('bitcoinutils.proxy.AuthServiceProxy')
        self.mock_auth_service_proxy = self.auth_service_proxy_patcher.start()
        
        # Mock instance of AuthServiceProxy
        self.mock_proxy_instance = MagicMock()
        self.mock_auth_service_proxy.return_value = self.mock_proxy_instance

    def tearDown(self):
        """Clean up the test environment."""
        self.auth_service_proxy_patcher.stop()

    def test_init_with_defaults(self):
        """Test initialization with default parameters."""
        proxy = NodeProxy('testuser', 'testpass')
        
        # Verify AuthServiceProxy was called with correct parameters
        self.mock_auth_service_proxy.assert_called_once_with(
            f"http://testuser:testpass@127.0.0.1:{NETWORK_DEFAULT_PORTS[get_network()]}",
            timeout=30
        )

    def test_init_with_custom_params(self):
        """Test initialization with custom parameters."""
        proxy = NodeProxy(
            'testuser', 
            'testpass', 
            host='192.168.1.1', 
            port=8888, 
            timeout=60, 
            use_https=True
        )
        
        # Verify AuthServiceProxy was called with correct parameters
        self.mock_auth_service_proxy.assert_called_once_with(
            "https://testuser:testpass@192.168.1.1:8888",
            timeout=60
        )

    def test_init_missing_credentials(self):
        """Test initialization with missing credentials."""
        with self.assertRaises(ValueError):
            proxy = NodeProxy('', 'testpass')
            
        with self.assertRaises(ValueError):
            proxy = NodeProxy('testuser', '')

    def test_call_method(self):
        """Test calling a method through the proxy."""
        # Set up the return value for the mock
        self.mock_proxy_instance.getblockcount.return_value = 123456
        
        proxy = NodeProxy('testuser', 'testpass')
        result = proxy.call('getblockcount')
        
        # Verify the method was called and the result is correct
        self.mock_proxy_instance.getblockcount.assert_called_once()
        self.assertEqual(result, 123456)

    def test_call_method_with_params(self):
        """Test calling a method with parameters."""
        # Set up the return value for the mock
        mock_block = {
            'hash': '000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d',
            'confirmations': 1000,
            'size': 1234,
            'height': 123456,
            'version': 0x20000000,
            'merkleroot': '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
            'time': 1600000000,
            'nonce': 123456789,
            'bits': '1d00ffff',
            'difficulty': 1,
            'previousblockhash': 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
            'nextblockhash': 'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321',
            'tx': ['tx1', 'tx2', 'tx3']
        }
        self.mock_proxy_instance.getblock.return_value = mock_block
        
        proxy = NodeProxy('testuser', 'testpass')
        result = proxy.call('getblock', '000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d')
        
        # Verify the method was called with the correct parameters
        self.mock_proxy_instance.getblock.assert_called_once_with(
            '000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d'
        )
        self.assertEqual(result, mock_block)

    def test_call_nonexistent_method(self):
        """Test calling a non-existent method."""
        # Set up the mock to raise an exception
        self.mock_proxy_instance.nonexistentmethod.side_effect = Exception("Method not found")
        
        proxy = NodeProxy('testuser', 'testpass')
        
        # Verify that the correct exception is raised
        with self.assertRaises(RPCError):
            proxy.call('nonexistentmethod')

    def test_direct_call(self):
        """Test calling a method using __call__."""
        # Set up the return value for the mock
        self.mock_proxy_instance.getblockcount.return_value = 123456
        
        proxy = NodeProxy('testuser', 'testpass')
        result = proxy('getblockcount')
        
        # Verify the method was called and the result is correct
        self.mock_proxy_instance.getblockcount.assert_called_once()
        self.assertEqual(result, 123456)

    def test_get_blockchain_info(self):
        """Test the get_blockchain_info method."""
        # Set up the return value for the mock
        mock_info = {
            'chain': 'test',
            'blocks': 123456,
            'headers': 123456,
            'bestblockhash': '000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d',
            'difficulty': 1,
            'mediantime': 1600000000,
            'verificationprogress': 0.9999,
            'initialblockdownload': False,
            'chainwork': '0000000000000000000000000000000000000000000000000000000000000000',
            'size_on_disk': 1234567890,
            'pruned': False
        }
        self.mock_proxy_instance.getblockchaininfo.return_value = mock_info
        
        proxy = NodeProxy('testuser', 'testpass')
        result = proxy.get_blockchain_info()
        
        # Verify the method was called and the result is correct
        self.mock_proxy_instance.getblockchaininfo.assert_called_once()
        self.assertEqual(result, mock_info)
        self.assertEqual(result['chain'], 'test')
        self.assertEqual(result['blocks'], 123456)

    def test_get_block_count(self):
        """Test the get_block_count method."""
        # Set up the return value for the mock
        self.mock_proxy_instance.getblockcount.return_value = 123456
        
        proxy = NodeProxy('testuser', 'testpass')
        result = proxy.get_block_count()
        
        # Verify the method was called and the result is correct
        self.mock_proxy_instance.getblockcount.assert_called_once()
        self.assertEqual(result, 123456)

    def test_get_block_hash(self):
        """Test the get_block_hash method."""
        # Set up the return value for the mock
        self.mock_proxy_instance.getblockhash.return_value = '000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d'
        
        proxy = NodeProxy('testuser', 'testpass')
        result = proxy.get_block_hash(123456)
        
        # Verify the method was called with the correct parameters
        self.mock_proxy_instance.getblockhash.assert_called_once_with(123456)
        self.assertEqual(result, '000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d')

    def test_get_block(self):
        """Test the get_block method."""
        # Set up the return value for the mock
        mock_block = {
            'hash': '000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d',
            'confirmations': 1000,
            'size': 1234,
            'height': 123456,
            'version': 0x20000000,
            'merkleroot': '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
            'time': 1600000000,
            'nonce': 123456789,
            'bits': '1d00ffff',
            'difficulty': 1,
            'previousblockhash': 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
            'nextblockhash': 'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321',
            'tx': ['tx1', 'tx2', 'tx3']
        }
        self.mock_proxy_instance.getblock.return_value = mock_block
        
        proxy = NodeProxy('testuser', 'testpass')
        result = proxy.get_block('000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d')
        
        # Verify the method was called with the correct parameters
        self.mock_proxy_instance.getblock.assert_called_once_with(
            '000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d', 1
        )
        self.assertEqual(result, mock_block)
        
        # Test with different verbosity
        self.mock_proxy_instance.getblock.reset_mock()
        self.mock_proxy_instance.getblock.return_value = mock_block
        
        result = proxy.get_block('000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d', 2)
        
        # Verify the method was called with the correct parameters
        self.mock_proxy_instance.getblock.assert_called_once_with(
            '000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d', 2
        )
        self.assertEqual(result, mock_block)

    def test_wallet_methods(self):
        """Test wallet-related methods."""
        # Set up return values for the mocks
        self.mock_proxy_instance.getbalance.return_value = 1.23456789
        self.mock_proxy_instance.getwalletinfo.return_value = {
            'walletname': 'test_wallet',
            'walletversion': 169900,
            'balance': 1.23456789,
            'unconfirmed_balance': 0.0,
            'immature_balance': 0.0,
            'txcount': 100,
            'keypoololdest': 1600000000,
            'keypoolsize': 1000,
            'paytxfee': 0.0,
            'hdseedid': '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
            'private_keys_enabled': True
        }
        self.mock_proxy_instance.getnewaddress.return_value = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx'
        
        proxy = NodeProxy('testuser', 'testpass')
        
        # Test get_balance
        balance = proxy.get_balance()
        self.mock_proxy_instance.getbalance.assert_called_once_with('*', 0, False)
        self.assertEqual(balance, 1.23456789)
        
        # Test get_wallet_info
        wallet_info = proxy.get_wallet_info()
        self.mock_proxy_instance.getwalletinfo.assert_called_once()
        self.assertEqual(wallet_info['balance'], 1.23456789)
        self.assertEqual(wallet_info['walletname'], 'test_wallet')
        
        # Test get_new_address
        address = proxy.get_new_address()
        self.mock_proxy_instance.getnewaddress.assert_called_once_with("")
        self.assertEqual(address, 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx')
        
        # Test get_new_address with parameters
        self.mock_proxy_instance.getnewaddress.reset_mock()
        self.mock_proxy_instance.getnewaddress.return_value = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx'
        
        address = proxy.get_new_address(label="test", address_type="bech32")
        self.mock_proxy_instance.getnewaddress.assert_called_once_with("test", "bech32")
        self.assertEqual(address, 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx')

    def test_transaction_methods(self):
        """Test transaction-related methods."""
        # Set up return values for the mocks
        self.mock_proxy_instance.createrawtransaction.return_value = "0100000001a5fb7a3bc532e38b0f5bad8d87fe8858a0b9f648"
        self.mock_proxy_instance.signrawtransactionwithwallet.return_value = {
            'hex': '0100000001a5fb7a3bc532e38b0f5bad8d87fe8858a0b9f648',
            'complete': True
        }
        self.mock_proxy_instance.sendrawtransaction.return_value = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
        self.mock_proxy_instance.getrawtransaction.return_value = '0100000001a5fb7a3bc532e38b0f5bad8d87fe8858a0b9f648'
        
        # Create a NodeProxy instance
        proxy = NodeProxy('testuser', 'testpass')
        
        # Test create_raw_transaction
        inputs = [{"txid": "a5fb7a3bc532e38b0f5bad8d87fe8858a0b9f648", "vout": 0}]
        outputs = {"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx": 0.001}
        
        raw_tx = proxy.create_raw_transaction(inputs, outputs)
        self.mock_proxy_instance.createrawtransaction.assert_called_once_with(
            inputs, outputs, 0, False
        )
        self.assertEqual(raw_tx, "0100000001a5fb7a3bc532e38b0f5bad8d87fe8858a0b9f648")
        
        # Test sign_raw_transaction_with_wallet
        signed_tx = proxy.sign_raw_transaction_with_wallet(raw_tx)
        self.mock_proxy_instance.signrawtransactionwithwallet.assert_called_once_with(raw_tx)
        self.assertEqual(signed_tx['hex'], "0100000001a5fb7a3bc532e38b0f5bad8d87fe8858a0b9f648")
        self.assertTrue(signed_tx['complete'])
        
        # Test send_raw_transaction
        tx_id = proxy.send_raw_transaction(signed_tx['hex'])
        self.mock_proxy_instance.sendrawtransaction.assert_called_once_with(signed_tx['hex'])
        self.assertEqual(tx_id, '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef')
        
        # Test get_raw_transaction
        raw_tx = proxy.get_raw_transaction(tx_id)
        self.mock_proxy_instance.getrawtransaction.assert_called_once_with(tx_id, False)
        self.assertEqual(raw_tx, '0100000001a5fb7a3bc532e38b0f5bad8d87fe8858a0b9f648')

    def test_error_handling(self):
        """Test error handling in the NodeProxy class."""
        # Set up the mock to raise an exception with an error code
        error_response = {
            'code': -8,
            'message': 'Invalid parameter'
        }
        mock_exception = Exception("Invalid parameter")
        mock_exception.error = error_response
        
        self.mock_proxy_instance.getblockhash.side_effect = mock_exception
        
        # Create a NodeProxy instance
        proxy = NodeProxy('testuser', 'testpass')
        
        # Verify that RPCError is raised with the correct error code
        with self.assertRaises(RPCError) as cm:
            proxy.get_block_hash(-1)
            
        self.assertEqual(str(cm.exception), "RPC Error (-8): Invalid parameter")
        self.assertEqual(cm.exception.code, -8)
        
        # Test with an exception without an error code
        self.mock_proxy_instance.getblockhash.side_effect = Exception("Network error")
        
        with self.assertRaises(RPCError) as cm:
            proxy.get_block_hash(123456)
            
        self.assertEqual(str(cm.exception), "Network error")
        self.assertIsNone(cm.exception.code)

    def test_compatibility_get_proxy(self):
        """Test compatibility method get_proxy."""
        proxy = NodeProxy('testuser', 'testpass')
        result = proxy.get_proxy()
        
        # Verify that the result is the AuthServiceProxy instance
        self.assertEqual(result, self.mock_proxy_instance)


if __name__ == '__main__':
    unittest.main()
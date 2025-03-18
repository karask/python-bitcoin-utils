# Testing Framework

This document provides an overview of the testing framework for the python-bitcoin-utils library.

## Testing Approach

The tests in this library are designed to work without requiring an active Bitcoin node connection or live network. Instead, they use a mock data approach to simulate Bitcoin network operations.

Key features of our testing approach:
- **Mock Data**: Pre-defined test vectors are stored in JSON files in the `mock_data` directory
- **Isolation**: Tests run independently of any live Bitcoin network
- **Reproducibility**: Fixed inputs ensure consistent test results
- **Comprehensive Coverage**: Tests cover edge cases and error handling

## Test Organization

The tests are organized by functionality:
- **Key and Address Tests**: Tests for private/public keys and address generation
- **Transaction Tests**: Tests for creating and signing various transaction types
- **Script Tests**: Tests for Bitcoin Script operations

## Mock Data

Mock data is stored in JSON files in the `tests/mock_data` directory. These files contain test vectors for various scenarios.

## Public Key Recovery Tests (PR #120)

The `test_key_recovery.py` file contains fully implemented tests for public key recovery from message and signature functionality from PR #120. These tests verify:

- Recovery of public keys from message signatures
- Error handling for invalid signature length
- Error handling for invalid recovery ID
- Error handling for missing parameters
- Error handling for empty messages

The tests use predefined test vectors with known messages, signatures, and corresponding public keys to verify the recovery process works correctly.

### Running the Public Key Recovery Tests

To run the public key recovery tests specifically:

```bash
pytest -xvs tests/test_key_recovery.py
```

### Extending Public Key Recovery Tests

To add more test cases for public key recovery:
1. Add new test vectors (message, signature, expected public key)
2. Follow the pattern in the `TestPublicKeyRecovery` class
3. Ensure proper validation of error cases

## Running Tests

To run all tests:
```bash
python -m unittest discover tests
```

To run a specific test file:
```bash
python -m unittest tests.test_file_name
```

## Adding New Tests

When adding new tests:
1. Create appropriate mock data in the `tests/mock_data` directory
2. Create test classes extending `unittest.TestCase`
3. Use the mock data in your tests instead of making live network calls
4. Update this README with information about your new tests

## Test Dependencies

The tests require the following packages:
- unittest (standard library)
- json (standard library)
- os (standard library)

## Examples

### Example 1: Testing with Mock Transaction Data

```python
import unittest
import json
import os
from bitcoinutils.transactions import Transaction

class TestTransactions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load mock data
        mock_data_path = os.path.join('tests', 'mock_data', 'transaction_data.json')
        with open(mock_data_path, 'r') as file:
            cls.mock_data = json.load(file)
    
    def test_transaction_parsing(self):
        # Use mock transaction data
        raw_tx = self.mock_data['valid_transactions'][0]['raw']
        tx = Transaction.from_raw(raw_tx)
        
        # Verify transaction properties
        self.assertEqual(tx.version, self.mock_data['valid_transactions'][0]['version'])
        self.assertEqual(len(tx.inputs), self.mock_data['valid_transactions'][0]['input_count'])
```

### Example 2: Using Mock Data for Keys and Addresses

```python
import unittest
import json
import os
from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey, PublicKey

class TestKeysAndAddresses(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Set up the network
        setup('testnet')
        
        # Load mock data
        mock_data_path = os.path.join('tests', 'mock_data', 'key_address_data.json')
        with open(mock_data_path, 'r') as file:
            cls.mock_data = json.load(file)
    
    def test_address_generation(self):
        # Use mock private key data
        priv_key_wif = self.mock_data['private_keys'][0]['wif']
        expected_address = self.mock_data['private_keys'][0]['address']
        
        # Create private key and derive address
        priv_key = PrivateKey(priv_key_wif)
        pub_key = priv_key.get_public_key()
        address = pub_key.get_address()
        
        # Verify address matches expected
        self.assertEqual(address.to_string(), expected_address)
```

### Example 3: Testing Public Key Recovery (PR #120)

```python
import unittest
from bitcoinutils.setup import setup
from bitcoinutils.keys import PublicKey

class TestPublicKeyRecovery(unittest.TestCase):
    def setUp(self):
        # Set up the network
        setup('testnet')
        
        # Test data for public key recovery
        self.valid_message = "Hello, Bitcoin!"
        self.valid_signature = b'\x1f\x0c\xfc\xd8V\xec27)\xa7\xfc\x02:\xda\xcfT\xb2*\x02\x16.\xe2s\x7f\x18[&^\xb3e\xee3"KN\xfct\x011Z[\x05\xb5\xea\n!\xe8\xce\x9em\x89/\xf2\xa0\x15\x83{\x7f\x9e\xba+\xb4\xf8&\x15'
        self.expected_public_key = '02649abc7094d2783670255073ccfd132677555ca84045c5a005611f25ef51fdbf'
    
    def test_public_key_recovery_valid(self):
        # Recover public key from message and signature
        pubkey = PublicKey(message=self.valid_message, signature=self.valid_signature)
        
        # Verify recovered public key matches expected
        self.assertEqual(pubkey.key.to_string("compressed").hex(), self.expected_public_key)
```

These examples demonstrate how to use mock data in your tests without relying on live network connections.
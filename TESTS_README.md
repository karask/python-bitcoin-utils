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

## Message Signature Tests (PR #120)

The `test_public_key_recovery.py` file contains tests for public key recovery from message and signature functionality (PR #120). Most of these tests are currently skipped as they require the implementation from PR #120.

Once PR #120 is merged, these tests will verify:
- Recovery of public keys from message signatures
- Error handling for various invalid inputs
- Functionality of the `from_message_signature` class method

The tests use mock data from `message_signature_data.json`, which contains test vectors for message signature operations.

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

These examples demonstrate how to use mock data in your tests without relying on live network connections.
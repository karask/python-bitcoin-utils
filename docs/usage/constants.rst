Constants Module
===============

The `constants` module provides constants used throughout the Python Bitcoin Utils library. These constants include network-specific values, address prefixes, signature hash types, and other Bitcoin-related constants.

Overview
--------

The constants in this module are organized into categories:

- Network-related constants
- Address type constants
- Signature hash constants
- Script constants
- Other Bitcoin-specific constants

Network Constants
---------------

These constants define network-specific values for mainnet, testnet, and regtest:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.constants import NETWORK_P2PKH_PREFIXES, NETWORK_P2SH_PREFIXES, NETWORK_SEGWIT_PREFIXES, NETWORK_WIF_PREFIXES, NETWORK_DEFAULT_PORTS
    
    # Set up the network
    setup('mainnet')
    
    # Display network constants
    print(f"P2PKH Prefix (mainnet): {NETWORK_P2PKH_PREFIXES['mainnet'].hex()}")
    print(f"P2SH Prefix (mainnet): {NETWORK_P2SH_PREFIXES['mainnet'].hex()}")
    print(f"SegWit Prefix (mainnet): {NETWORK_SEGWIT_PREFIXES['mainnet']}")
    print(f"WIF Prefix (mainnet): {NETWORK_WIF_PREFIXES['mainnet'].hex()}")
    print(f"Default Port (mainnet): {NETWORK_DEFAULT_PORTS['mainnet']}")
    
    # Change network
    setup('testnet')
    
    # Display network constants for testnet
    print(f"P2PKH Prefix (testnet): {NETWORK_P2PKH_PREFIXES['testnet'].hex()}")
    print(f"P2SH Prefix (testnet): {NETWORK_P2SH_PREFIXES['testnet'].hex()}")
    print(f"SegWit Prefix (testnet): {NETWORK_SEGWIT_PREFIXES['testnet']}")
    print(f"WIF Prefix (testnet): {NETWORK_WIF_PREFIXES['testnet'].hex()}")
    print(f"Default Port (testnet): {NETWORK_DEFAULT_PORTS['testnet']}")

Network Prefixes
--------------

The network prefixes are used for address encoding:

- `NETWORK_P2PKH_PREFIXES`: Prefixes for Pay-to-Public-Key-Hash (P2PKH) addresses
  - Mainnet: 0x00 (addresses start with '1')
  - Testnet: 0x6f (addresses start with 'm' or 'n')

- `NETWORK_P2SH_PREFIXES`: Prefixes for Pay-to-Script-Hash (P2SH) addresses
  - Mainnet: 0x05 (addresses start with '3')
  - Testnet: 0xc4 (addresses start with '2')

- `NETWORK_SEGWIT_PREFIXES`: Prefixes for SegWit addresses (Bech32)
  - Mainnet: "bc"
  - Testnet: "tb"

- `NETWORK_WIF_PREFIXES`: Prefixes for Wallet Import Format (WIF) private keys
  - Mainnet: 0x80
  - Testnet: 0xef

Address Types
-----------

The library defines constants for different address types:

.. code-block:: python

    from bitcoinutils.constants import P2PKH_ADDRESS, P2SH_ADDRESS, P2WPKH_ADDRESS_V0, P2WSH_ADDRESS_V0, P2TR_ADDRESS_V1
    
    print(f"P2PKH Address Type: {P2PKH_ADDRESS}")
    print(f"P2SH Address Type: {P2SH_ADDRESS}")
    print(f"P2WPKH Address Type (SegWit v0): {P2WPKH_ADDRESS_V0}")
    print(f"P2WSH Address Type (SegWit v0): {P2WSH_ADDRESS_V0}")
    print(f"P2TR Address Type (SegWit v1): {P2TR_ADDRESS_V1}")

Signature Hash Constants
---------------------

These constants define signature hash types used in transaction signing:

.. code-block:: python

    from bitcoinutils.constants import SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY, TAPROOT_SIGHASH_ALL
    
    # Legacy and SegWit v0 signature hash types
    print(f"SIGHASH_ALL: {SIGHASH_ALL}")
    print(f"SIGHASH_NONE: {SIGHASH_NONE}")
    print(f"SIGHASH_SINGLE: {SIGHASH_SINGLE}")
    print(f"SIGHASH_ANYONECANPAY: {SIGHASH_ANYONECANPAY}")
    
    # Combinations
    print(f"SIGHASH_ALL | SIGHASH_ANYONECANPAY: {SIGHASH_ALL | SIGHASH_ANYONECANPAY}")
    print(f"SIGHASH_NONE | SIGHASH_ANYONECANPAY: {SIGHASH_NONE | SIGHASH_ANYONECANPAY}")
    print(f"SIGHASH_SINGLE | SIGHASH_ANYONECANPAY: {SIGHASH_SINGLE | SIGHASH_ANYONECANPAY}")
    
    # Taproot signature hash type
    print(f"TAPROOT_SIGHASH_ALL: {TAPROOT_SIGHASH_ALL}")

Using Constants in Code
---------------------

Here are some examples of how constants are used in the library:

1. **Network Selection**:

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.constants import NETWORK_P2PKH_PREFIXES
    
    # Set up the network
    setup('testnet')
    
    # Get the network prefix for the current network
    network = get_network()
    prefix = NETWORK_P2PKH_PREFIXES[network]
    print(f"Current network: {network}")
    print(f"P2PKH prefix: {prefix.hex()}")

2. **Address Type Identification**:

.. code-block:: python

    from bitcoinutils.keys import P2pkhAddress, P2shAddress, P2wpkhAddress, P2wshAddress, P2trAddress
    
    # Create addresses
    p2pkh = P2pkhAddress('mnc4ZZCFRvbNxTRMhf2gEgKUfMi3XSy7L6')
    p2sh = P2shAddress('2N6Vk58WRh7gQYrRUBZAJAxXC7TKPPpKmDD')
    p2wpkh = P2wpkhAddress('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx')
    p2wsh = P2wshAddress('tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7')
    p2tr = P2trAddress('tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6')
    
    # Check address types
    print(f"P2PKH type: {p2pkh.get_type() == P2PKH_ADDRESS}")
    print(f"P2SH type: {p2sh.get_type() == P2SH_ADDRESS}")
    print(f"P2WPKH type: {p2wpkh.get_type() == P2WPKH_ADDRESS_V0}")
    print(f"P2WSH type: {p2wsh.get_type() == P2WSH_ADDRESS_V0}")
    print(f"P2TR type: {p2tr.get_type() == P2TR_ADDRESS_V1}")

3. **Signature Hash Types**:

.. code-block:: python

    from bitcoinutils.transactions import Transaction, TxInput, TxOutput
    from bitcoinutils.keys import PrivateKey
    from bitcoinutils.constants import SIGHASH_ALL, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY
    
    # Create a transaction
    txin = TxInput('previous_tx_id', 0)
    txout = TxOutput(0.001, recipient_script_pub_key)
    tx = Transaction([txin], [txout])
    
    # Sign with different sighash types
    private_key = PrivateKey('private_key_wif')
    
    # Sign with SIGHASH_ALL (default)
    sig_all = private_key.sign_input(tx, 0, script_pub_key)
    
    # Sign with SIGHASH_SINGLE
    sig_single = private_key.sign_input(tx, 0, script_pub_key, sighash=SIGHASH_SINGLE)
    
    # Sign with SIGHASH_ALL | SIGHASH_ANYONECANPAY
    sig_all_anyone = private_key.sign_input(tx, 0, script_pub_key, sighash=SIGHASH_ALL | SIGHASH_ANYONECANPAY)

Default Values
-----------

The library also defines some default values:

.. code-block:: python

    from bitcoinutils.constants import DEFAULT_TX_LOCKTIME, DEFAULT_TX_VERSION, DEFAULT_TX_IN_SEQUENCE
    
    print(f"Default Transaction Locktime: {DEFAULT_TX_LOCKTIME}")
    print(f"Default Transaction Version: {DEFAULT_TX_VERSION}")
    print(f"Default Transaction Input Sequence: {DEFAULT_TX_IN_SEQUENCE}")

Extending and Customizing
-----------------------

If you need to work with networks not defined in the constants module (e.g., a private Bitcoin network), you can extend the constants in your application:

.. code-block:: python

    from bitcoinutils.constants import NETWORK_P2PKH_PREFIXES, NETWORK_P2SH_PREFIXES, NETWORK_SEGWIT_PREFIXES, NETWORK_WIF_PREFIXES, NETWORK_DEFAULT_PORTS
    import bitcoinutils.setup
    
    # Add custom network
    NETWORK_P2PKH_PREFIXES['mynet'] = bytes.fromhex('6f')  # Same as testnet
    NETWORK_P2SH_PREFIXES['mynet'] = bytes.fromhex('c4')   # Same as testnet
    NETWORK_SEGWIT_PREFIXES['mynet'] = 'my'                # Custom prefix
    NETWORK_WIF_PREFIXES['mynet'] = bytes.fromhex('ef')    # Same as testnet
    NETWORK_DEFAULT_PORTS['mynet'] = 18333                 # Custom port
    
    # Patch the network list
    bitcoinutils.setup.NETWORKS.append('mynet')
    
    # Set up the custom network
    bitcoinutils.setup.setup('mynet')
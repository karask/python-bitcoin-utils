HD Wallet
========

The `hdwallet` module implements Hierarchical Deterministic (HD) wallets according to BIP32. HD wallets allow for the generation of a tree of keys from a single seed, which is particularly useful for wallet applications.

Overview
--------

HD wallets work by deriving a hierarchy of keys from a single master key. This master key is derived from a seed, which can be represented as a mnemonic phrase (as specified in BIP39) or as a seed directly.

Basic Usage
----------

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.hdwallet import HDWallet

    # Setup the network
    setup('testnet')

    # Create an HD wallet from a seed
    seed = "000102030405060708090a0b0c0d0e0f"
    hdwallet = HDWallet.from_seed(seed)

    # Derive a child key
    child = hdwallet.derive_path("m/44'/0'/0'/0/0")

    # Get the private and public keys
    private_key = child.get_private_key()
    public_key = child.get_public_key()

    print(f"BIP32 extended private key: {child.to_extended_private_key()}")
    print(f"BIP32 extended public key: {child.to_extended_public_key()}")
    print(f"Private key (WIF): {private_key.to_wif()}")
    print(f"Public key (hex): {public_key.to_hex()}")
    print(f"Address: {public_key.get_address().to_string()}")

Creating an HD Wallet
--------------------

You can create an HD wallet from a seed, a mnemonic phrase, or an extended key:

.. code-block:: python

    # From a seed (hex string)
    seed = "000102030405060708090a0b0c0d0e0f"
    hdwallet_from_seed = HDWallet.from_seed(seed)

    # From an extended private key
    xpriv = "tprv8ZgxMBicQKsPeWHBt7a68nPnvgTnuDhUgDWC8wZCgA8GahrQ3f3uWpq7wE7Uc1dLBnCe1hhCZ886K6ND37memNCdCUNrfumuKHDYDAEqoia"
    hdwallet_from_xpriv = HDWallet.from_extended_key(xpriv)

    # From an extended public key (watch-only wallet)
    xpub = "tpubD6NzVbkrYhZ4XpMCLWrG6bG7E9FeX6qehxQ6RaMBhB49XyCMQUi9NwD9HBrichm9jnN9hEhAsR7Ks3H7DZYJu2BcTKKCPQH7VsaBAusVSSS"
    hdwallet_from_xpub = HDWallet.from_extended_key(xpub)

Deriving Child Keys
-----------------

There are two ways to derive child keys:

1. Using the `derive_child` method to derive a single child key
2. Using the `derive_path` method to derive a key using a BIP32 path

.. code-block:: python

    # Using derive_child
    # Derive a child key at index 0 (non-hardened)
    child_0 = hdwallet.derive_child(0)

    # Derive a hardened child key at index 0
    child_0_hardened = hdwallet.derive_child(0, hardened=True)

    # Using derive_path
    # Derive using a BIP32 path
    # m / purpose' / coin_type' / account' / change / address_index
    # Note: In paths, ' or h denotes hardened derivation
    bip44_path = "m/44'/0'/0'/0/0"  # BIP44 path for the first address
    child = hdwallet.derive_path(bip44_path)

Extended Keys
-----------

Extended keys are serialized representations of HD wallet keys that contain both the key and the chain code. They are used to export and import HD wallets.

.. code-block:: python

    # Get the extended private key
    xpriv = hdwallet.to_extended_private_key()
    print(f"Extended private key: {xpriv}")

    # Get the extended public key
    xpub = hdwallet.to_extended_public_key()
    print(f"Extended public key: {xpub}")

    # Import from an extended key
    imported_wallet = HDWallet.from_extended_key(xpriv)

BIP44 Standard Paths
------------------

BIP44 defines a standard path structure for HD wallets:

`m / purpose' / coin_type' / account' / change / address_index`

- `purpose` is always 44' for BIP44
- `coin_type` is the type of cryptocurrency (0' for Bitcoin, 1' for Bitcoin testnet)
- `account` is the account number, starting from 0'
- `change` is 0 for external addresses (receiving) and 1 for internal addresses (change)
- `address_index` is the address number, starting from 0

.. code-block:: python

    # Derive the first receiving address for the first account
    receiving_address_0 = hdwallet.derive_path("m/44'/0'/0'/0/0")

    # Derive the first change address for the first account
    change_address_0 = hdwallet.derive_path("m/44'/0'/0'/1/0")

Working with Keys and Addresses
-----------------------------

After deriving a child key, you can get the associated private key, public key, and addresses:

.. code-block:: python

    # Derive a child key
    child = hdwallet.derive_path("m/44'/0'/0'/0/0")

    # Get the private key
    private_key = child.get_private_key()
    print(f"Private key (WIF): {private_key.to_wif()}")

    # Get the public key
    public_key = child.get_public_key()
    print(f"Public key (hex): {public_key.to_hex()}")

    # Get different address types
    p2pkh_address = public_key.get_address()
    p2wpkh_address = public_key.get_segwit_address()
    p2tr_address = public_key.get_taproot_address()

    print(f"P2PKH address: {p2pkh_address.to_string()}")
    print(f"P2WPKH address: {p2wpkh_address.to_string()}")
    print(f"P2TR address: {p2tr_address.to_string()}")

Creating a Watch-Only Wallet
--------------------------

You can create a watch-only wallet from an extended public key. This is useful for monitoring addresses without having access to the private keys:

.. code-block:: python

    # Create a wallet
    seed = "000102030405060708090a0b0c0d0e0f"
    hdwallet = HDWallet.from_seed(seed)

    # Get the extended public key for the account
    account = hdwallet.derive_path("m/44'/0'/0'")
    xpub = account.to_extended_public_key()

    # Create a watch-only wallet from the xpuba
    watch_only = HDWallet.from_extended_key(xpub)

    # Derive receiving addresses
    address_0 = watch_only.derive_path("0/0").get_public_key().get_address()
    address_1 = watch_only.derive_path("0/1").get_public_key().get_address()

    print(f"Address 0: {address_0.to_string()}")
    print(f"Address 1: {address_1.to_string()}")

Security Considerations
---------------------

When working with HD wallets, keep the following security considerations in mind:

1. **Master Key Security**: The master key (seed or mnemonic) can derive all keys in the wallet. Keep it secure.
2. **Extended Private Keys**: Extended private keys contain the chain code and can derive all child private keys. Treat them as sensitive as the master key.
3. **Extended Public Keys**: While extended public keys can only derive public keys, they can leak privacy information if combined with any child private key.
4. **Hardened Derivation**: Use hardened derivation (') for the first levels of your HD wallet to prevent potential security issues.
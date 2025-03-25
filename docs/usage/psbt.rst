PSBT - Partially Signed Bitcoin Transactions
============================================

The ``bitcoinutils.psbt`` module provides classes and methods to work with Partially Signed Bitcoin Transactions (PSBTs) as specified in BIP-174. PSBTs enable collaborative transaction construction and signing, which is particularly useful for multisignature wallets and hardware wallet integrations.

Overview
--------

A PSBT represents a Bitcoin transaction that may be incomplete or partially signed. It contains the unsigned transaction data, as well as additional metadata needed for signing. The PSBT lifecycle typically follows these stages:

1. **Creation**: An unsigned transaction is converted to a PSBT.
2. **Update**: UTXO information, redeem scripts, and other metadata are added.
3. **Signing**: One or more parties add their signatures.
4. **Combining**: PSBTs signed by different parties are merged.
5. **Finalization**: Partial signatures are converted to scriptSigs or witness data.
6. **Extraction**: The final, signed transaction is extracted for broadcasting.

Main Classes
-----------

PSBT
~~~~

The main container class for PSBT data.

.. code-block:: python

    from bitcoinutils.psbt import PSBT

Methods:

- ``from_transaction(tx)`` - Create a new PSBT from an unsigned transaction.
- ``add_input_utxo(input_index, utxo_tx=None, witness_utxo=None)`` - Add UTXO information to an input.
- ``add_input_redeem_script(input_index, redeem_script)`` - Add a redeem script to an input.
- ``sign_input(private_key, input_index, redeem_script=None, witness_script=None, sighash=SIGHASH_ALL)`` - Sign an input with a private key.
- ``combine(psbts)`` - Combine multiple PSBTs (static method).
- ``finalize()`` - Finalize all inputs by converting partial signatures to scriptSigs or witness data.
- ``finalize_input(input_index)`` - Finalize a specific input.
- ``extract_transaction()`` - Extract the final transaction for broadcasting.
- ``to_base64()`` - Serialize the PSBT to base64 encoding.
- ``from_base64(b64_str)`` - Deserialize a PSBT from base64 encoding (static method).

PSBTInput
~~~~~~~~~

Represents an input in a PSBT.

Methods:

- ``add_non_witness_utxo(tx)`` - Add a non-witness UTXO transaction.
- ``add_witness_utxo(txout)`` - Add a witness UTXO.
- ``add_partial_signature(pubkey, signature)`` - Add a partial signature.
- ``add_sighash_type(sighash_type)`` - Add a sighash type.
- ``add_redeem_script(script)`` - Add a redeem script.
- ``add_witness_script(script)`` - Add a witness script.
- ``add_bip32_derivation(pubkey, fingerprint, path)`` - Add a BIP32 derivation path.

PSBTOutput
~~~~~~~~~~

Represents an output in a PSBT.

Methods:

- ``add_redeem_script(script)`` - Add a redeem script.
- ``add_witness_script(script)`` - Add a witness script.
- ``add_bip32_derivation(pubkey, fingerprint, path)`` - Add a BIP32 derivation path.

Examples
--------

Creating a PSBT
~~~~~~~~~~~~~~

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.transactions import Transaction, TxInput, TxOutput
    from bitcoinutils.keys import PrivateKey, P2pkhAddress
    from bitcoinutils.psbt import PSBT
    
    # Setup the network
    setup('testnet')
    
    # Create keys and address
    private_key = PrivateKey('cVwfreZB3r8vUkSnaoeZJ4Ux9W8YMqYM5XRV4zJo6ThcYs1MYiXj')
    public_key = private_key.get_public_key()
    address = P2pkhAddress.from_public_key(public_key)
    
    # Create an unsigned transaction
    txin = TxInput('339e9f3ff9aeb6bb75cfed89b397994663c9aa3458dd5ed6e710626a36ee9dfc', 0)
    txout = TxOutput(1000000, address.to_script_pub_key())
    tx = Transaction([txin], [txout])
    
    # Create a PSBT from the transaction
    psbt = PSBT.from_transaction(tx)
    
    # Add UTXO information
    prev_tx_hex = '0200000001f3dc9c924e7813c81cfb218fdad0603a76fdd37a4ad9622d475d11741940bfbc000000006a47304402201fad9a9735a3182e76e6ae47ebfd23784bd142384a73146c7f7f277dbd399b22022032f2a086d4ebac27398f6896298a2d3ce7e6b50afd934302c873133442b1c8c8012102653c8de9f4854ca4da358d8403b6e0ce61c621d37f9c1bf2384d9e3d6b9a59b5feffffff01102700000000000017a914a36f0f7839deeac8755c1c1ad9b3d877e99ed77a8700000000'
    prev_tx = Transaction.from_raw(prev_tx_hex)
    psbt.add_input_utxo(0, utxo_tx=prev_tx)
    
    # Serialize the PSBT for sharing
    psbt_base64 = psbt.to_base64()
    print(psbt_base64)

Signing a PSBT
~~~~~~~~~~~~~

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.keys import PrivateKey
    from bitcoinutils.psbt import PSBT
    
    # Setup the network
    setup('testnet')
    
    # Parse the PSBT from base64
    psbt_base64 = "cHNidP8BAHUCAAAAAcgijGQXgR7MRl5Fx6g5dPgaVJfwhY4SK4M5I6pTLy9HAAAAAAD/////AoCWmAEAAAAAGXapFEPbU3M0+15UVo8nUXvQPVgvMQqziKwAAAAAAAAAGXapFC3J0f1e4DC1YgLFBzThoaj8jWWjiKwAAAAAAAEBIAhYmAEAAAAAFgAUfaLsJ5hKK8BLOXfgXHb0EbQnS3IAAA=="
    psbt = PSBT.from_base64(psbt_base64)
    
    # Create the signing key
    private_key = PrivateKey('cVwfreZB3r8vUkSnaoeZJ4Ux9W8YMqYM5XRV4zJo6ThcYs1MYiXj')
    
    # Sign the PSBT
    psbt.sign_input(private_key, 0)
    
    # Serialize the signed PSBT
    signed_psbt_base64 = psbt.to_base64()
    print(signed_psbt_base64)

Combining PSBTs
~~~~~~~~~~~~~

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.psbt import PSBT
    
    # Setup the network
    setup('testnet')
    
    # Parse PSBTs from different signers
    psbt1_base64 = "cHNidP8BAHUCAAAAAcgijGQXgR7MRl5Fx6g5dPgaVJfwhY4SK4M5I6pTLy9HAAAAAAD/////AoCWmAEAAAAAGXapFEPbU3M0+15UVo8nUXvQPVgvMQqziKwAAAAAAAAAGXapFC3J0f1e4DC1YgLFBzThoaj8jWWjiKwAAAAAAAEBIAhYmAEAAAAAFgAUfaLsJ5hKK8BLOXfgXHb0EbQnS3IiBgMC9D2zgHto4gyl4qbtdGuihjh7GzWk2n3LQ4iLzOA5QBjiJ015AAAA"
    psbt2_base64 = "cHNidP8BAHUCAAAAAcgijGQXgR7MRl5Fx6g5dPgaVJfwhY4SK4M5I6pTLy9HAAAAAAD/////AoCWmAEAAAAAGXapFEPbU3M0+15UVo8nUXvQPVgvMQqziKwAAAAAAAAAGXapFC3J0f1e4DC1YgLFBzThoaj8jWWjiKwAAAAAAAEBIAhYmAEAAAAAFgAUfaLsJ5hKK8BLOXfgXHb0EbQnS3IiBgLELw4bRrPuQpkHvEwxohfO3kLLKpfOqgzFLXNzOLXkfRitMgFjAAAA"
    
    psbt1 = PSBT.from_base64(psbt1_base64)
    psbt2 = PSBT.from_base64(psbt2_base64)
    
    # Combine the PSBTs
    combined_psbt = PSBT.combine([psbt1, psbt2])
    
    # Serialize the combined PSBT
    combined_psbt_base64 = combined_psbt.to_base64()
    print(combined_psbt_base64)

Finalizing and Extracting a Transaction
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    from bitcoinutils.setup import setup
    from bitcoinutils.psbt import PSBT
    
    # Setup the network
    setup('testnet')
    
    # Parse the PSBT from base64
    psbt_base64 = "cHNidP8BAHUCAAAAAcgijGQXgR7MRl5Fx6g5dPgaVJfwhY4SK4M5I6pTLy9HAAAAAAD/////AoCWmAEAAAAAGXapFEPbU3M0+15UVo8nUXvQPVgvMQqziKwAAAAAAAAAGXapFC3J0f1e4DC1YgLFBzThoaj8jWWjiKwAAAAAAAEBIAhYmAEAAAAAFgAUfaLsJ5hKK8BLOXfgXHb0EbQnS3IiAgMC9D2zgHto4gyl4qbtdGuihjh7GzWk2n3LQ4iLzOA5QEcwRAIgcLsQZYL5GAmpk9GHYV0yQwAfRwL9kYoZ0dKB8tWBxCkCIBiQlz9HUeZ6gsXLgCHLVJk94+GaynYEQQTrZUHj63HHASECC+Ch0g8yJaMFvtJdT13DiKEqRxGwIzdUyF/YgfCiVpSsAAAAIgICxC8OG0az7kKZB7xMMaIXzt5CyyqXzqoMxS1zczS15H0YRzBEAiAufbU+MI/sVWzwB/r5+y4H9Vfa/PbWrXQfJYgDgW3cWQIgP9MsPMeAeN8Qw+l8nmF12Nj5XBcMmMSNURHwWB4rg2ABAQMEAQAAAAEFW1IhA5XEW4M0wOepEHBa+/xw+lnbEwL//SZtWADcW0Igyo0wUq92U64AAA=="
    psbt = PSBT.from_base64(psbt_base64)
    
    # Finalize the PSBT
    if psbt.finalize():
        print("PSBT successfully finalized")
        
        # Extract the final transaction
        final_tx = psbt.extract_transaction()
        tx_hex = final_tx.serialize()
        print(f"Final Transaction Hex: {tx_hex}")
        print(f"Transaction ID: {final_tx.get_txid()}")
    else:
        print("Failed to finalize PSBT")

Multisignature Wallet Example
~~~~~~~~~~~~~~~~~~~~~~~~~~~

For a complete multisignature wallet example using PSBTs, refer to the ``psbt_multisig_wallet.py`` example in the GitHub repository.

Best Practices
-------------

1. **Check Signatures**: Always verify that the expected number of signatures are present before finalizing a PSBT.
2. **Validate Inputs**: Ensure that all inputs have appropriate UTXO information before attempting to sign.
3. **Secure Serialization**: Base64-encoded PSBTs are safe to share, but ensure they're transmitted securely.
4. **Script Verification**: For complex script types, verify the redeem and witness scripts match expectations.
5. **Testing**: Always test your PSBT workflows on testnet before using them on mainnet.

BIP-174 Reference
---------------

For more details on the PSBT specification, refer to the BIP-174 document:
https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
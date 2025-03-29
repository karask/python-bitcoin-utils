Transactions module
-------------------

.. automodule:: transactions
   :members:

Automatic Witness Handling
-------------------------

When creating transactions with both SegWit and non-SegWit inputs, the library now automatically handles witness data for non-witness inputs by adding an empty witness (0x00) during serialization. This eliminates the need to manually add an empty TxWitnessInput for non-SegWit inputs.

Example::

    # Create a transaction with both SegWit and non-SegWit inputs
    tx = Transaction(version=2)
    tx.add_input(txin_legacy)  # non-witness input
    tx.add_input(txin_segwit)  # witness input
    tx.add_output(txout)
    tx.has_segwit = True

    # Sign inputs
    # ...

    # Add witness data only for the SegWit input
    # The non-SegWit input will automatically get an empty witness
    tx.add_witness(1, [signature, pubkey])

    # Serialize and broadcast
    serialized_tx = tx.serialize()

Annex Support in Taproot Signatures
----------------------------------

The library now supports including an annex in Taproot signature calculations. An annex is additional data that can be included in a Taproot signature but does not affect the scriptPubKey.

Example::

    # Create an annex (must start with 0x50)
    annex = bytes([0x50]) + b"Custom annex data"

    # Sign with annex
    signature = priv_key.sign_taproot_input(
        tx,
        input_index,
        script_pubkeys,
        amounts,
        script_path=False,
        annex=annex
    )

    # Add the witness data including the annex
    tx.add_witness(input_index, [signature, annex.hex()])
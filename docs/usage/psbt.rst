PSBT
====

The :mod:`bitcoinutils.psbt` module implements BIP-174 PSBT v0 workflows.

Roles
-----

The ``PSBT`` class can act as:

* Creator: wrap an unsigned ``Transaction``.
* Updater: attach UTXO and script metadata with ``update_input``.
* Signer: call ``sign_input`` with a ``PrivateKey``.
* Combiner: merge compatible PSBTs with ``combine``.
* Finalizer: call ``finalize`` or ``finalize_input``.
* Extractor: call ``extract_transaction``.

Minimal Flow
------------

.. code-block:: python

   psbt = PSBT(tx)
   psbt.update_input(0, non_witness_utxo=previous_tx, redeem_script=redeem_script)
   psbt.sign_input(0, private_key)
   psbt.finalize()
   final_tx = psbt.extract_transaction()

2-of-3 Multisig Walkthrough
---------------------------

The examples include a complete 2-of-3 P2SH multisig PSBT workflow split across
creator and signer scripts.

.. literalinclude:: ../../examples/psbt/PSBT_2of3_MULTISIG.md
   :language: markdown
   :linenos:

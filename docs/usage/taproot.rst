Taproot
=======

Taproot support includes P2TR addresses, key-path signing, script-path signing,
Taproot tweaks, and control blocks.

Addresses and Tweaks
--------------------

``PublicKey.get_taproot_address()`` returns a ``P2trAddress``. If scripts are
passed, the internal key is tweaked with the script tree commitment.

.. literalinclude:: ../../examples/keys_taproot_addresses.py
   :language: python
   :linenos:

Key-Path Spending
-----------------

For a key-path spend, call ``PrivateKey.sign_taproot_input`` with all input
scriptPubKeys and amounts.

.. literalinclude:: ../../examples/spend_p2tr_default_path.py
   :language: python
   :linenos:

Script-Path Spending
--------------------

Script-path spends add the executed tapleaf script and a control block to the
witness stack.

.. literalinclude:: ../../examples/spend_p2tr_single_script_by_script_path.py
   :language: python
   :linenos:

Multiple Script Paths
---------------------

The examples directory contains two-, three-, and four-leaf Taproot trees.

.. literalinclude:: ../../examples/send_to_p2tr_with_three_scripts.py
   :language: python
   :linenos:

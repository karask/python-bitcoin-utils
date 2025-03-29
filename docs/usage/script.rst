Script module
-------------

.. automodule:: script
   :members:

Tapscript Support
---------------

The library now differentiates between regular scripts and Tapscripts (used in Taproot). This is important because Tapscript allows opcodes like OP_CHECKSIGADD that are not valid in other script types.

Creating a Tapscript::

    # Import the required constants
    from bitcoinutils.script import Script, SCRIPT_TYPE_TAPSCRIPT, TapscriptFactory

    # Create a script and specify it's a Tapscript
    tapscript = Script(["<pubkey>", "OP_CHECKSIG"], script_type=SCRIPT_TYPE_TAPSCRIPT)

Using TapscriptFactory for common patterns::

    # Create a 2-of-3 multisig using OP_CHECKSIGADD (Taproot only)
    multisig_script = TapscriptFactory.create_checksigadd_script(
        [pubkey1, pubkey2, pubkey3],
        2  # threshold (require 2 signatures)
    )
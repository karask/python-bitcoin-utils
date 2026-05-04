Keys and Addresses module
-------------------------

Security note
~~~~~~~~~~~~~

The key APIs are pure Python and intended for education, tests, testnet, and
offline experimentation. Private-key operations, including ECDSA signing and
Taproot/Schnorr signing, are not side-channel hardened. They should not be used
to protect real funds in timing-observable environments.

This mirrors Bitcoin Core's Python test framework: readable Python secp256k1
code is useful for tests and teaching, while production Bitcoin software uses
hardened native implementations or external signers for real keys.

Warnings for private-key operations are enabled by default on mainnet. They can
be disabled with ``bitcoinutils.setup.set_security_warnings(False)``. Testnet,
testnet4, signet and regtest do not emit the warning by default, so educational
examples stay quiet.

.. automodule:: keys
   :members:

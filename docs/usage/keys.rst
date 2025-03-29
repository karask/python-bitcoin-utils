Keys and Addresses module
-------------------------

.. automodule:: keys
   :members:

Security Improvements
--------------------

As of version X.Y.Z, the library has switched from using python-ecdsa to coincurve for all ECDSA operations. The coincurve library is a Python binding for libsecp256k1, the same library used by Bitcoin Core, providing:

* Better performance
* Protection against timing attacks
* Deterministic signature generation (RFC6979)
* Low-S normalization for Bitcoin compatibility

This change addresses the Minerva timing attack vulnerability (GHSA-wj6h-64fc-37mp) present in python-ecdsa.
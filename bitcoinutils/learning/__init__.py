"""Optional educational helpers built on top of :mod:`bitcoinutils`.

Core library modules do not import this package.  It can therefore be omitted
or removed without changing address, key, script, or transaction behaviour.
"""

from bitcoinutils.learning.p2pkh import trace_p2pkh_input

__all__ = ["trace_p2pkh_input"]

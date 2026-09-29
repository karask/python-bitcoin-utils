"""Optional educational helpers built on top of :mod:`bitcoinutils`.

Core library modules do not import this package.  It can therefore be omitted
or removed without changing address, key, script, or transaction behaviour.
"""

from bitcoinutils.learning.block import (
    create_coinbase_transaction,
    get_block_subsidy,
    trace_merkle_root,
)
from bitcoinutils.learning.p2pkh import trace_p2pkh_input
from bitcoinutils.learning.p2wpkh import trace_p2wpkh_input
from bitcoinutils.learning.segwit_block import create_segwit_coinbase_transaction
from bitcoinutils.learning.sighash import trace_segwit_v0_sighash

__all__ = [
    "create_coinbase_transaction",
    "get_block_subsidy",
    "trace_merkle_root",
    "trace_p2pkh_input",
    "trace_p2wpkh_input",
    "create_segwit_coinbase_transaction",
    "trace_segwit_v0_sighash",
]

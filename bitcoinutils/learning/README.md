# Educational helpers

`bitcoinutils.learning` contains optional, trace-oriented helpers for teaching
Bitcoin concepts. Core `bitcoinutils` modules do not import this package, so it
can be removed without changing core library behaviour.

The initial API traces one standard legacy P2PKH input:

```python
from bitcoinutils.learning import trace_p2pkh_input

result = trace_p2pkh_input(transaction, 0, previous_script_pubkey)
for step in result["steps"]:
    print(step["instruction"], step["stack_before"], step["stack_after"])
```

This is not a general Bitcoin Script interpreter or a complete transaction,
consensus, or policy validator. It supports only a two-push P2PKH `scriptSig`,
the standard P2PKH locking script, and legacy `SIGHASH_ALL`. The caller must
supply the previous output script; existence and unspent status are not checked.

## Legacy candidate-block construction

The block helpers expose real transaction bytes and intermediate hashes for
education while keeping core block parsing and serialization separate:

~~~python
from bitcoinutils.learning import (
    create_coinbase_transaction, get_block_subsidy, trace_merkle_root,
)
from bitcoinutils.script import Script
from bitcoinutils.transactions import TxOutput

fees = 0  # Replace with the fees from the selected transactions.
selected_legacy_transactions = []
payout_script = Script(["OP_1"])  # Minimal teaching example.
subsidy = get_block_subsidy(840_000, network="mainnet")
coinbase = create_coinbase_transaction(
    840_000, [TxOutput(subsidy + fees, payout_script)],
    fees=fees, network="mainnet", extra_nonce=b"\x01",
)
trace = trace_merkle_root([coinbase, *selected_legacy_transactions])
merkle_root_bytes = bytes.fromhex(trace["root"])  # For BlockHeader.merkle_root.
~~~

`get_block_subsidy` returns satoshis for mainnet, testnet, testnet4, signet,
or regtest. Regtest halves every 150 blocks; the others every 210,000.
`create_coinbase_transaction` returns a legacy `Transaction` whose first
`scriptSig` item is the minimally encoded BIP34 height. Its input uses the
null outpoint and final sequence, and its outputs cannot exceed subsidy plus
the supplied fees. Optional extranonce and message are separate data pushes.
The caller must supply a payout script and fees derived from the included
transactions. The helper does not validate that chain state or those fees.

`trace_merkle_root` takes an ordered, nonempty list of `Transaction` objects.
It returns displayed TXIDs, each level in display and internal byte order,
every pair's preimage and double-SHA256 result, the final root in both orders,
odd-leaf duplication flags, and a `mutated` flag for equal existing siblings.
`root` is the display-order value accepted by `BlockHeader`, while
`root_internal` is the exact 32-byte field in the serialized header.

These helpers construct only legacy candidates. They do not build a SegWit
witness commitment, validate a whole block, select mempool entries, or
serialize the complete block. Coinbase scriptSig length is kept within the
consensus 2–100 byte range.

References: [BIP34](https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki)
and [Bitcoin Core's Merkle implementation](https://github.com/bitcoin/bitcoin/blob/master/src/consensus/merkle.cpp).

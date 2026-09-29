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

## Native P2WPKH execution

```python
from bitcoinutils.learning import trace_p2wpkh_input

# transaction is signed and has one witness slot per input.
# previous_script_pubkey is the spent output's Script (0014<20-byte hash>).
result = trace_p2wpkh_input(transaction, 0, previous_script_pubkey, amount=100_000)
for step in result["steps"]:
    print(step["phase"], step["instruction"], step["stack_after"])
```

The previous output amount is required in **satoshis**. Changing it changes
the BIP143 signing digest, so the original signature will fail. The selected
input must have an empty scriptSig and a witness containing exactly a DER
signature with a trailing `01` sighash byte and a compressed SEC public key.
The initial scope is native P2WPKH with `SIGHASH_ALL`; P2SH wrapping, P2WSH,
Taproot, other sighash modes, and uncompressed keys are explicitly unsupported.
The compressed-key restriction follows default policy; it is not presented as
a consensus rule. This helper does not enforce low-S or NULLFAIL policy.

Results use the same `success`, `final_stack`, `steps`, and `error` fields as
the P2PKH tracer. Additional fields expose the `witness_program`, implied
`script_code` (without a length prefix), and supplied `amount`. `sighash` is
null until read; `sighash_byte` records the actual signature type when present.
All stacks are hex arrays, bottom first; false is `""`, true is `"01"`.
The successful trace contains seven steps:

1. Two `witness` steps (`kind: witness_load`) initialize the stack. These
   load data; they are not Script opcodes or scriptSig pushes.
2. Five `scriptCode` steps execute DUP, HASH160, the public-key-hash push,
   EQUALVERIFY, and CHECKSIG using the implied P2PKH script. The witness program
   selects this script; `OP_0 <hash>` is not a replacement unlocking script.

CHECKSIG exposes its BIP143 `digest` and `signature_valid` result. Failures
return a structured error and the trace so far, with the failing step annotated
when execution has begun. An incorrect/empty signature produces false; malformed
nonempty DER halts execution. A hash mismatch fails at EQUALVERIFY and leaves
the false comparison result on the stack. The helper does not mutate its inputs
or verify UTXO existence, unspent status, claimed amounts, or whole-transaction
validity.

Witness slots must stay aligned with transaction inputs. Include an empty
`TxWitnessInput([])` for each legacy input in a mixed transaction. The current
core `Transaction.from_raw()` drops empty witness slots; the tracer rejects
the resulting shorter list with `WITNESS_COUNT_MISMATCH` rather than assigning
a witness to the wrong input. Construct mixed transactions with explicit slots
(or `set_witness` on a freshly constructed transaction). Transactions with
P2WPKH witnesses for every input can be parsed and traced directly.

Tests live here to keep the addition contained in the optional subpackage:

```sh
python -m unittest discover -s bitcoinutils/learning/tests -p 'test_*.py'
```

References: [BIP141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
and [BIP143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki).

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

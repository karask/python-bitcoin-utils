# Signature Hash Annex Support

## Overview

This feature implements support for the signature hash annex as defined in [BIP-341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) (Taproot). The annex is an additional data structure that can be included in the transaction signature hash calculation, allowing for future extensions to the signature validation system.

## Implementation Details

The annex is an optional parameter in the `get_transaction_taproot_digest` method. When provided, it changes how the transaction's signature hash is calculated according to the BIP-341 specification:

1. The `spend_type` byte includes bit 0 set to 1 to indicate the presence of an annex
2. The annex is prefixed with 0x50 and its length as a compact size
3. The SHA256 hash of this prefixed annex is included in the signature hash calculation

## Usage

```python
from bitcoinutils.transactions import Transaction
from bitcoinutils.utils import h_to_b

# Your existing code to create and set up a transaction
# ...

# Calculate signature hash with annex
annex_data = h_to_b("aabbccdd")  # Your annex data as bytes
signature_hash = tx.get_transaction_taproot_digest(
    txin_index=0,
    script_pubkeys=script_pubkeys,
    amounts=amounts,
    sighash=TAPROOT_SIGHASH_ALL,
    annex=annex_data
)
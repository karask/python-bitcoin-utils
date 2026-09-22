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

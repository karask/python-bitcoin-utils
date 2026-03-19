# Copyright (C) 2018-2025 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.


"""PSBT 2-of-3 Multisig — Step 2: Signer 1.

BIP-174 role: Signer

This script loads the unsigned PSBT created by ``psbt_2of3_create.py``,
signs input 0 with Signer 1's private key, and writes the partially-signed
PSBT to ``signer1.psbt``.

The PSBT is NOT finalized here — we still need Signer 2's signature.

See PSBT_2of3_MULTISIG.md for the full workflow description.
"""

import json

from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey
from bitcoinutils.psbt import PSBT


INPUT_FILE = "unsigned.psbt"
KEYS_FILE = "keys.json"
OUTPUT_FILE = "signer1.psbt"


def main():
    setup("regtest")

    # ------------------------------------------------------------------
    # 1. Load the unsigned PSBT
    # ------------------------------------------------------------------
    with open(INPUT_FILE) as f:
        psbt = PSBT.from_base64(f.read().strip())

    print(f"Loaded PSBT from {INPUT_FILE}")
    print(f"  Inputs:  {len(psbt.tx.inputs)}")
    print(f"  Outputs: {len(psbt.tx.outputs)}")

    # ------------------------------------------------------------------
    # 2. Load Signer 1's private key
    # ------------------------------------------------------------------
    # In production this key would come from a hardware wallet or secure
    # keystore — never from a shared file.  Here we read keys.json for
    # convenience in this demo.
    with open(KEYS_FILE) as f:
        keys = json.load(f)

    sk1 = PrivateKey(keys["sk1_wif"])
    pk1_hex = sk1.get_public_key().to_hex()

    # ------------------------------------------------------------------
    # 3. Sign with Signer 1's key
    # ------------------------------------------------------------------
    signed = psbt.sign_input(0, sk1)
    print(f"\nSigner 1 ({pk1_hex[:16]}...):")
    print(f"  Signed: {signed}")
    print(f"  Partial signatures on input 0: {len(psbt.inputs[0].partial_sigs)}")

    # ------------------------------------------------------------------
    # 4. Export the partially-signed PSBT
    # ------------------------------------------------------------------
    # DO NOT finalize — we need Signer 2's signature before the
    # transaction is complete.

    b64 = psbt.to_base64()
    with open(OUTPUT_FILE, "w") as f:
        f.write(b64)

    print(f"\nPartially-signed PSBT written to {OUTPUT_FILE}")
    print(f"Base64 ({len(b64)} chars): {b64[:72]}...")
    print("\nNext step: run psbt_2of3_sign2.py (Signer 2 + Combiner + Finalizer)")


if __name__ == "__main__":
    main()

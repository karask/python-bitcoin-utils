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


"""PSBT 2-of-3 Multisig — Step 3: Signer 2 + Combiner + Finalizer + Extractor.

BIP-174 roles: Signer, Combiner, Finalizer, Transaction Extractor

This script:

  1. Loads the unsigned PSBT and signs it with Signer 2's private key.
  2. Loads Signer 1's partially-signed PSBT.
  3. Combines both into a single PSBT with two partial signatures.
  4. Finalizes the PSBT — constructs the scriptSig from the 2-of-3
     partial signatures.
  5. Extracts the fully signed transaction.
  6. Validates the transaction via testmempoolaccept on the regtest node.

Requires a running Bitcoin Core node on regtest.

See PSBT_2of3_MULTISIG.md for the full workflow description.
"""

import json

from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey
from bitcoinutils.proxy import NodeProxy
from bitcoinutils.psbt import PSBT


RPC_USER = "kostas"
RPC_PASSWORD = "toolonganddifficult"

UNSIGNED_FILE = "unsigned.psbt"
SIGNER1_FILE = "signer1.psbt"
KEYS_FILE = "keys.json"
OUTPUT_FILE = "final_tx.hex"


def main():
    setup("regtest")

    proxy = NodeProxy(RPC_USER, RPC_PASSWORD).get_proxy()

    # ------------------------------------------------------------------
    # 1. Load keys and Signer 2's private key
    # ------------------------------------------------------------------
    with open(KEYS_FILE) as f:
        keys = json.load(f)

    sk2 = PrivateKey(keys["sk2_wif"])
    pk2_hex = sk2.get_public_key().to_hex()

    # ------------------------------------------------------------------
    # 2. Signer role — sign a fresh copy of the unsigned PSBT
    # ------------------------------------------------------------------
    with open(UNSIGNED_FILE) as f:
        psbt_signer2 = PSBT.from_base64(f.read().strip())

    signed = psbt_signer2.sign_input(0, sk2)
    print(f"Signer 2 ({pk2_hex[:16]}...):")
    print(f"  Signed: {signed}")
    print(f"  Partial signatures on input 0: {len(psbt_signer2.inputs[0].partial_sigs)}")

    # ------------------------------------------------------------------
    # 3. Load Signer 1's partially-signed PSBT
    # ------------------------------------------------------------------
    with open(SIGNER1_FILE) as f:
        psbt_signer1 = PSBT.from_base64(f.read().strip())

    print(f"\nSigner 1's PSBT loaded from {SIGNER1_FILE}")
    print(f"  Partial signatures on input 0: {len(psbt_signer1.inputs[0].partial_sigs)}")

    # ------------------------------------------------------------------
    # 4. Combiner role — merge both signed PSBTs
    # ------------------------------------------------------------------
    combined = psbt_signer1.combine(psbt_signer2)
    print(f"\nCombined PSBT:")
    print(f"  Partial signatures on input 0: {len(combined.inputs[0].partial_sigs)}")

    # ------------------------------------------------------------------
    # 5. Finalizer role — construct the final scriptSig
    # ------------------------------------------------------------------
    # The finalizer detects the 2-of-3 multisig redeemScript, orders the
    # two signatures to match the pubkey order in the script, and builds:
    #   OP_0 <sig_1> <sig_2> <serialized_redeemScript>
    combined.finalize()
    print(f"\nFinalized:")
    print(f"  final_scriptsig present: {combined.inputs[0].final_scriptsig is not None}")
    print(f"  partial_sigs cleared:    {len(combined.inputs[0].partial_sigs) == 0}")
    print(f"  redeem_script cleared:   {combined.inputs[0].redeem_script is None}")

    # ------------------------------------------------------------------
    # 6. Extractor role — pull out the fully signed transaction
    # ------------------------------------------------------------------
    final_tx = combined.extract_transaction()
    tx_hex = final_tx.serialize()

    with open(OUTPUT_FILE, "w") as f:
        f.write(tx_hex)

    print(f"\nFinal signed transaction written to {OUTPUT_FILE}")
    print(f"TxId: {final_tx.get_txid()}")
    print(f"Size: {len(tx_hex) // 2} bytes")

    # ------------------------------------------------------------------
    # 7. Validate via testmempoolaccept
    # ------------------------------------------------------------------
    print("\nValidating transaction with testmempoolaccept...")
    result = proxy.testmempoolaccept([tx_hex])[0]

    if result["allowed"]:
        print("PASSED — transaction is valid and would be accepted by the mempool.")
        print(f"  vsize: {result['vsize']} vbytes")
        if "fees" in result:
            print(f"  fee:   {result['fees']['base']} BTC")
    else:
        print(f"FAILED — transaction rejected: {result['reject-reason']}")


if __name__ == "__main__":
    main()

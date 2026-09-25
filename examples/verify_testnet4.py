#!/usr/bin/env python3
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


"""Live Testnet4 PSBT verification script.

This script performs a complete end-to-end PSBT lifecycle against the
Bitcoin Testnet4 network. It is intended for **manual** verification
only — it is NOT part of the automated test suite and should NOT be
run in CI.

Workflow:
    1. Check balance of the test address
    2. Select a UTXO
    3. Create PSBT
    4. Sign
    5. Finalize
    6. Extract signed transaction
    7. Broadcast via API
    8. Print transaction URL for manual verification

Prerequisites:
    - The test address must be funded with testnet4 coins
    - Internet access to query the API and broadcast
    - The ``urllib`` module (standard library, no extra deps)

Usage:
    python examples/verify_testnet4.py [--api-endpoint URL]

    Default API endpoint: https://mempool.space/testnet4/api
"""

import sys
import json
import urllib.request
import urllib.error
import argparse
import time

from bitcoinutils.setup import setup
from bitcoinutils.utils import to_satoshis
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import PrivateKey
from bitcoinutils.psbt import PSBT


# Default test key (testnet WIF) — DO NOT use on mainnet
TEST_WIF = "cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo"

# Fee in satoshis (conservatively high for testnet4)
FEE_SATS = 1000

# Default API endpoint
DEFAULT_API = "https://mempool.space/testnet4/api"


def api_get(endpoint: str, path: str) -> dict:
    """GET JSON from the API."""
    url = f"{endpoint}{path}"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"  HTTP error {e.code} for {url}")
        raise
    except urllib.error.URLError as e:
        print(f"  URL error for {url}: {e.reason}")
        raise


def api_post(endpoint: str, path: str, data: str) -> str:
    """POST raw text data to the API, return response text."""
    url = f"{endpoint}{path}"
    req = urllib.request.Request(
        url,
        data=data.encode("utf-8"),
        headers={"Content-Type": "text/plain"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode().strip()


def fetch_utxos(endpoint: str, address: str) -> list:
    """Fetch confirmed UTXOs for an address."""
    return api_get(endpoint, f"/address/{address}/utxo")


def broadcast_tx(endpoint: str, raw_hex: str) -> str:
    """Broadcast a raw transaction and return the txid."""
    return api_post(endpoint, "/tx", raw_hex)


def main():
    parser = argparse.ArgumentParser(
        description="Live Testnet4 PSBT verification"
    )
    parser.add_argument(
        "--api-endpoint",
        default=DEFAULT_API,
        help=f"API endpoint (default: {DEFAULT_API})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do everything except broadcast",
    )
    args = parser.parse_args()

    setup("testnet4")

    sk = PrivateKey.from_wif(TEST_WIF)
    pub = sk.get_public_key()
    addr = pub.get_segwit_address()
    address_str = addr.to_string()

    print("=" * 70)
    print("Live Testnet4 PSBT Verification")
    print("=" * 70)
    print(f"\nAddress (P2WPKH): {address_str}")
    print(f"API endpoint:     {args.api_endpoint}")

    # Step 1: Fetch UTXOs
    print(f"\n--- Step 1: Fetch UTXOs ---")
    try:
        utxos = fetch_utxos(args.api_endpoint, address_str)
    except Exception as e:
        print(f"ERROR: Could not fetch UTXOs: {e}")
        print(f"\nFund the address first:")
        print(f"  https://faucet.testnet4.dev")
        print(f"  https://mempool.space/testnet4/faucet")
        sys.exit(1)

    confirmed = [u for u in utxos if u.get("status", {}).get("confirmed", False)]
    if not confirmed:
        print(f"No confirmed UTXOs found. Fund the address and wait for confirmation.")
        print(f"  Address: {address_str}")
        sys.exit(1)

    # Pick the largest UTXO
    utxo = max(confirmed, key=lambda u: u["value"])
    utxo_txid = utxo["txid"]
    utxo_vout = utxo["vout"]
    utxo_amount = utxo["value"]

    print(f"  Found {len(confirmed)} confirmed UTXO(s)")
    print(f"  Using: {utxo_txid}:{utxo_vout} ({utxo_amount} sats)")

    if utxo_amount <= FEE_SATS:
        print(f"  ERROR: UTXO amount ({utxo_amount}) is too small for fee ({FEE_SATS})")
        sys.exit(1)

    send_amount = utxo_amount - FEE_SATS

    # Step 2: Create PSBT
    print(f"\n--- Step 2: Creator + Updater ---")
    txin = TxInput(utxo_txid, utxo_vout)
    txout = TxOutput(send_amount, addr.to_script_pub_key())  # send back to self
    tx = Transaction([txin], [txout], has_segwit=True)

    psbt = PSBT(tx)
    witness_utxo = TxOutput(utxo_amount, addr.to_script_pub_key())
    psbt.update_input(0, witness_utxo=witness_utxo)

    unsigned_b64 = psbt.to_base64()
    print(f"  Sending {send_amount} sats back to self (fee: {FEE_SATS} sats)")
    print(f"  Unsigned PSBT: {unsigned_b64[:60]}...")

    # Step 3: Sign
    print(f"\n--- Step 3: Signer ---")
    result = psbt.sign_input(0, sk)
    print(f"  Signed: {result}")
    signed_b64 = psbt.to_base64()
    print(f"  Signed PSBT: {signed_b64[:60]}...")

    # Step 4: Finalize
    print(f"\n--- Step 4: Finalizer ---")
    psbt.finalize_input(0)
    print(f"  Finalized: witness items = {len(psbt.inputs[0].final_scriptwitness)}")

    # Step 5: Extract
    print(f"\n--- Step 5: Extractor ---")
    final_tx = psbt.extract_transaction()
    raw_hex = final_tx.serialize()
    txid = final_tx.get_txid()
    print(f"  Transaction ID: {txid}")
    print(f"  Raw hex: {raw_hex[:60]}...")
    print(f"  Size: {final_tx.get_size()} bytes, vSize: {final_tx.get_vsize()} vbytes")

    # Step 6: Broadcast
    print(f"\n--- Step 6: Broadcast ---")
    if args.dry_run:
        print(f"  DRY RUN — not broadcasting")
        print(f"\n  To broadcast manually:")
        print(f"  curl -X POST {args.api_endpoint}/tx -d '{raw_hex}'")
    else:
        try:
            result_txid = broadcast_tx(args.api_endpoint, raw_hex)
            print(f"  Broadcast successful!")
            print(f"  Returned txid: {result_txid}")
        except urllib.error.HTTPError as e:
            body = e.read().decode() if hasattr(e, 'read') else str(e)
            print(f"  Broadcast failed: HTTP {e.code}")
            print(f"  Response: {body}")
            print(f"\n  To broadcast manually:")
            print(f"  curl -X POST {args.api_endpoint}/tx -d '{raw_hex}'")
            sys.exit(1)

    # Step 7: Verify
    print(f"\n{'=' * 70}")
    print(f"Verification")
    print(f"{'=' * 70}")
    print(f"\nView transaction at:")
    print(f"  https://mempool.space/testnet4/tx/{txid}")
    print(f"\nPSBT lifecycle: ✅ Creator → Updater → Signer → Finalizer → Extractor")

    if not args.dry_run:
        print(f"\nWaiting 5 seconds before checking mempool status...")
        time.sleep(5)
        try:
            tx_status = api_get(args.api_endpoint, f"/tx/{txid}")
            print(f"  Transaction found in mempool/chain: ✅")
            confirmed = tx_status.get("status", {}).get("confirmed", False)
            print(f"  Confirmed: {'✅' if confirmed else '⏳ pending'}")
        except Exception:
            print(f"  Transaction not yet visible (may take a moment)")


if __name__ == "__main__":
    main()

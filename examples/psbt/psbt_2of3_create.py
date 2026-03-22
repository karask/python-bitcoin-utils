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


"""PSBT 2-of-3 Multisig — Step 1: Creator + Updater.

BIP-174 roles: Creator, Updater

This script:

  1. Generates three private keys and derives their public keys.
  2. Constructs the 2-of-3 redeemScript and the P2SH address.
  3. Funds the multisig address via the regtest node.
  4. Mines a block to confirm the funding transaction.
  5. Builds the spending transaction (unsigned).
  6. Wraps it in a PSBT and attaches the non-witness UTXO and redeemScript.
  7. Writes the PSBT to ``unsigned.psbt`` and the three WIF keys to
     ``keys.json`` (so the signing scripts can pick them up).

Requires a running Bitcoin Core node on regtest with a loaded wallet.

See PSBT_2of3_MULTISIG.md for the full workflow description.
"""

import json

from bitcoinutils.setup import setup
from bitcoinutils.utils import to_satoshis
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import PrivateKey, P2shAddress
from bitcoinutils.script import Script
from bitcoinutils.proxy import NodeProxy
from bitcoinutils.psbt import PSBT


RPC_USER = "kostas"
RPC_PASSWORD = "toolonganddifficult"

PSBT_FILE = "unsigned.psbt"
KEYS_FILE = "keys.json"

FUND_AMOUNT = 1.0  # BTC to send to the multisig
SPEND_AMOUNT = 0.999  # BTC to send out (the rest is fee)


def main():
    setup("regtest")

    proxy = NodeProxy(RPC_USER, RPC_PASSWORD)
    print(f"Connected to regtest node — block height: {proxy.getblockcount()}")

    # ------------------------------------------------------------------
    # 1. Generate three private keys
    # ------------------------------------------------------------------
    sk1 = PrivateKey()
    sk2 = PrivateKey()
    sk3 = PrivateKey()

    pk1 = sk1.get_public_key()
    pk2 = sk2.get_public_key()
    pk3 = sk3.get_public_key()

    print("\nGenerated keys:")
    print(f"  Key 1 (Signer 1): {sk1.to_wif(compressed=True)}")
    print(f"    Pubkey: {pk1.to_hex()}")
    print(f"  Key 2 (Signer 2): {sk2.to_wif(compressed=True)}")
    print(f"    Pubkey: {pk2.to_hex()}")
    print(f"  Key 3 (unused):   {sk3.to_wif(compressed=True)}")
    print(f"    Pubkey: {pk3.to_hex()}")

    # ------------------------------------------------------------------
    # 2. Build the 2-of-3 redeemScript and P2SH address
    # ------------------------------------------------------------------
    redeem_script = Script(
        [
            "OP_2",
            pk1.to_hex(),
            pk2.to_hex(),
            pk3.to_hex(),
            "OP_3",
            "OP_CHECKMULTISIG",
        ]
    )

    p2sh_addr = P2shAddress(script=redeem_script)
    p2sh_address_str = p2sh_addr.to_string()

    print(f"\nRedeemScript: {redeem_script.to_hex()}")
    print(f"P2SH address: {p2sh_address_str}")

    # ------------------------------------------------------------------
    # 3. Fund the multisig address from the node's wallet
    # ------------------------------------------------------------------
    # On regtest with few blocks, fee estimation has no data. Set a
    # wallet-level fallback fee rate so sendtoaddress succeeds.
    proxy.settxfee(0.0001)

    print(f"\nSending {FUND_AMOUNT} BTC to multisig address...")
    funding_txid = proxy.sendtoaddress(p2sh_address_str, FUND_AMOUNT)
    print(f"Funding txid: {funding_txid}")

    # Mine a block so the funding tx confirms
    proxy.generatetoaddress(1, proxy.getnewaddress())
    print(f"Mined 1 block — new height: {proxy.getblockcount()}")

    # ------------------------------------------------------------------
    # 4. Get the full funding transaction and find the output index
    # ------------------------------------------------------------------
    # getrawtransaction needs a block hash when txindex is not enabled.
    # gettransaction (wallet RPC) gives us the block hash of the confirmed tx.
    block_hash = proxy.gettransaction(funding_txid)["blockhash"]
    funding_tx_hex = proxy.getrawtransaction(funding_txid, False, block_hash)
    funding_tx = Transaction.from_raw(funding_tx_hex)

    # Find which vout pays the multisig
    p2sh_script_pubkey = redeem_script.to_p2sh_script_pub_key()
    vout = None
    for i, txout in enumerate(funding_tx.outputs):
        if txout.script_pubkey.to_hex() == p2sh_script_pubkey.to_hex():
            vout = i
            break

    if vout is None:
        raise RuntimeError("Could not find multisig output in funding tx")

    fund_amount_sat = funding_tx.outputs[vout].amount
    print(f"Multisig output: vout={vout}, amount={fund_amount_sat} satoshis")

    # ------------------------------------------------------------------
    # 5. Build the spending transaction (Creator role)
    # ------------------------------------------------------------------
    # Send to a new address from the node's wallet so we can verify
    # receipt after broadcast.
    dest_address_str = proxy.getnewaddress()
    print(f"\nDestination address: {dest_address_str}")

    spend_sat = to_satoshis(SPEND_AMOUNT)
    txin = TxInput(funding_txid, vout)
    txout = TxOutput(
        spend_sat,
        Script(
            [
                "OP_DUP",
                "OP_HASH160",
                proxy.getaddressinfo(dest_address_str)["scriptPubKey"][6:-4],
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ]
        ),
    )

    # Build output from raw scriptPubKey to handle any address type
    dest_spk_hex = proxy.getaddressinfo(dest_address_str)["scriptPubKey"]
    txout = TxOutput(spend_sat, Script.from_raw(dest_spk_hex))

    tx = Transaction([txin], [txout])

    # ------------------------------------------------------------------
    # 6. Wrap in PSBT and update (Creator + Updater roles)
    # ------------------------------------------------------------------
    psbt = PSBT(tx)
    psbt.update_input(
        0,
        non_witness_utxo=funding_tx,
        redeem_script=redeem_script,
    )

    # ------------------------------------------------------------------
    # 7. Export PSBT and keys
    # ------------------------------------------------------------------
    b64 = psbt.to_base64()
    with open(PSBT_FILE, "w") as f:
        f.write(b64)

    keys_data = {
        "sk1_wif": sk1.to_wif(compressed=True),
        "sk2_wif": sk2.to_wif(compressed=True),
        "sk3_wif": sk3.to_wif(compressed=True),
        "funding_txid": funding_txid,
        "vout": vout,
        "p2sh_address": p2sh_address_str,
        "dest_address": dest_address_str,
    }
    with open(KEYS_FILE, "w") as f:
        json.dump(keys_data, f, indent=2)

    print(f"\nPSBT written to {PSBT_FILE}")
    print(f"Keys written to {KEYS_FILE}")
    print(f"Base64 ({len(b64)} chars): {b64[:72]}...")
    print(f"\nFee: {(fund_amount_sat - spend_sat) / 1e8:.8f} BTC")
    print("\nNext step: run psbt_2of3_sign1.py (Signer 1)")


if __name__ == "__main__":
    main()

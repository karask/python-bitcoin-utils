# Copyright (C) 2018-2022 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

from bitcoinutils.setup import setup
from bitcoinutils.utils import to_satoshis, ControlBlock, tapleaf_tagged_hash
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.keys import PrivateKey
from bitcoinutils.hdwallet import HDWallet


def main():
    # always remember to setup the network
    setup("testnet")

    #######################
    # Construct the input #
    #######################

    # get an HDWallet wrapper object by extended private key and path
    xprivkey = (
        "tprv8ZgxMBicQKsPdQR9RuHpGGxSnNq8Jr3X4WnT6Nf2eq7FajuXyBep5KWYpYEixxx5XdTm1N"
        "tpe84f3cVcF7mZZ7mPkntaFXLGJD2tS7YJkWU"
    )
    path = "m/86'/1'/0'/0/7"
    hdw = HDWallet(xprivkey, path)
    internal_priv = hdw.get_private_key()
    print("From Private key:", internal_priv.to_wif())
    internal_pub = internal_priv.get_public_key()
    print("From Public key:", internal_pub.to_hex())

    # taproot script is a simple P2PK with the following keys
    privkey_tr_script_A = PrivateKey(
        "cSW2kQbqC9zkqagw8oTYKFTozKuZ214zd6CMTDs4V32cMfH3dgKa"
    )
    pubkey_tr_script_A = privkey_tr_script_A.get_public_key()
    tr_script_p2pk_A = Script([pubkey_tr_script_A.to_x_only_hex(), "OP_CHECKSIG"])

    # taproot script B is a simple P2PK with the following keys
    privkey_tr_script_B = PrivateKey(
        "cSv48xapaqy7fPs8VvoSnxNBNA2jpjcuURRqUENu3WVq6Eh4U3JU"
    )
    pubkey_tr_script_B = privkey_tr_script_B.get_public_key()
    tr_script_p2pk_B = Script([pubkey_tr_script_B.to_x_only_hex(), "OP_CHECKSIG"])

    # taproot script C is a simple P2PK with the following keys
    privkey_tr_script_C = PrivateKey(
        "cRkZPNnn3jdr64o3PDxNHG68eowDfuCdcyL6nVL4n3czvunuvryC"
    )
    pubkey_tr_script_C = privkey_tr_script_C.get_public_key()
    tr_script_p2pk_C = Script([pubkey_tr_script_C.to_x_only_hex(), "OP_CHECKSIG"])

    # tapleafs in order
    #                  TB_ABC
    #                  /    \
    #                 /      \
    #              TB_AB      \
    #               / \        \
    #              /   \        \
    #            TL_A TL_B     TL_C
    all_leafs = [[tr_script_p2pk_A, tr_script_p2pk_B], tr_script_p2pk_C]

    # taproot script path address
    from_address = internal_pub.get_taproot_address(all_leafs)
    print("From Taproot script address", from_address.to_string())

    # UTXO of from_address
    txid = "9b8a01d0f333b2440d4d305d26641e14e0e1932ebc3c4f04387c0820fada87d3"
    vout = 0

    # create transaction input from tx id of UTXO
    tx_in = TxInput(txid, vout)

    # all amounts are needed to sign a taproot input
    # (depending on sighash)
    amount = to_satoshis(0.000035)
    amounts = [amount]

    # all scriptPubKeys (in hex) are needed to sign a taproot input
    # (depending on sighash but always of the spend input)
    scriptPubkey = from_address.to_script_pub_key()
    utxos_scriptPubkeys = [scriptPubkey]

    ########################
    # Construct the output #
    ########################

    hdw.from_path("m/86'/1'/0'/0/5")
    to_priv = hdw.get_private_key()
    print("To Private key:", to_priv.to_wif())

    to_pub = to_priv.get_public_key()
    print("To Public key:", to_pub.to_hex())

    # taproot key path address
    to_address = to_pub.get_taproot_address()
    print("To Taproot address:", to_address.to_string())

    # create transaction output
    tx_out = TxOutput(to_satoshis(0.00003), to_address.to_script_pub_key())

    # create transaction without change output - if at least a single input is
    # segwit we need to set has_segwit=True
    tx = Transaction([tx_in], [tx_out], has_segwit=True)

    print("\nRaw transaction:\n" + tx.serialize())

    print("\ntxid: " + tx.get_txid())
    print("\ntxwid: " + tx.get_wtxid())

    # sign taproot input
    # to create the digest message to sign in taproot we need to
    # pass all the utxos' scriptPubKeys, their amounts and taproot script
    # we sign with the private key corresponding to the script - no key
    # tweaking required
    sig = privkey_tr_script_B.sign_taproot_input(
        tx,
        0,
        utxos_scriptPubkeys,
        amounts,
        script_path=True,
        tapleaf_script=tr_script_p2pk_B,
        tweak=False,
    )

    # tagged hashes of leafs
    leaf_a = tapleaf_tagged_hash(tr_script_p2pk_A)
    leaf_c = tapleaf_tagged_hash(tr_script_p2pk_C)

    # we need to provide the merkle path (in bytes)
    control_block = ControlBlock(internal_pub, scripts=leaf_a + leaf_c, is_odd=to_address.is_odd())

    tx.witnesses.append(
        TxWitnessInput([sig, tr_script_p2pk_B.to_hex(), control_block.to_hex()])
    )

    # print raw signed transaction ready to be broadcasted
    print("\nRaw signed transaction:\n" + tx.serialize())

    print("\nTxId:", tx.get_txid())
    print("\nTxwId:", tx.get_wtxid())

    print("\nSize:", tx.get_size())
    print("\nvSize:", tx.get_vsize())


if __name__ == "__main__":
    main()

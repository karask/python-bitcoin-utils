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
from bitcoinutils.utils import to_satoshis
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.keys import PrivateKey
from bitcoinutils.hdwallet import HDWallet


def main():
    # always remember to setup the network
    setup("testnet")

    # Keys are hard-coded in the example for simplicity but it is very bad
    # practice. Normally you would acquire them from env variables, db, etc.

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

    # taproot script is a simple P2PK with the following key
    privkey_tr_script = PrivateKey(
        "cQwzrJyTNWbEwhPEmQ3Qoo4jSfHdHEtdbL4kNBgHUKhirgzcQw7G"
    )
    pubkey_tr_script = privkey_tr_script.get_public_key()
    tr_script_p2pk = Script([pubkey_tr_script.to_x_only_hex(), "OP_CHECKSIG"])

    # taproot script path address
    from_address = internal_pub.get_taproot_address([[tr_script_p2pk]])
    print("From Taproot script address", from_address.to_string())

    # UTXO of from_address from pubkey 02
    txid = "348f577ae2509b3b73ebd810c3cdcb18045ef62b43378aed283b3259afe493b1"
    vout = 0

    # create transaction input from tx id of UTXO
    tx_in = TxInput(txid, vout)

    # all amounts are needed to sign a taproot input
    # (depending on sighash)
    amount = to_satoshis(0.00009)
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
    tx_out = TxOutput(to_satoshis(0.000085), to_address.to_script_pub_key())

    # create transaction without change output - if at least a single input is
    # segwit we need to set has_segwit=True
    tx = Transaction([tx_in], [tx_out], has_segwit=True)

    print("\nRaw transaction:\n" + tx.serialize())

    print("\ntxid: " + tx.get_txid())
    print("\ntxwid: " + tx.get_wtxid())

    # sign taproot input
    # to create the digest message to sign in taproot we need to
    # pass all the utxos' scriptPubKeys, their amounts and taproot script
    # all tapleaf scripts are required to tweak the private key
    sig = internal_priv.sign_taproot_input(
        tx,
        0,
        utxos_scriptPubkeys,
        amounts,
        script_path=False,
        tapleaf_scripts=[tr_script_p2pk],
    )

    tx.witnesses.append(TxWitnessInput([sig]))

    # print raw signed transaction ready to be broadcasted
    print("\nRaw signed transaction:\n" + tx.serialize())

    print("\nTxId:", tx.get_txid())
    print("\nTxwId:", tx.get_wtxid())

    print("\nSize:", tx.get_size())
    print("\nvSize:", tx.get_vsize())


if __name__ == "__main__":
    main()

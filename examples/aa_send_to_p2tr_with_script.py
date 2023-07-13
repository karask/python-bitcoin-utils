# Copyright (C) 2018-2023 The python-bitcoin-utils developers
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
    setup('testnet')

    # Keys are hard-coded in the example for simplicity but it is very bad
    # practice. Normally you would acquire them from env variables, db, etc.

    #######################
    # Construct the input #
    #######################

    # get an HDWallet wrapper object by extended private key and path
    xprivkey = "tprv8ZgxMBicQKsPdQR9RuHpGGxSnNq8Jr3X4WnT6Nf2eq7FajuXyBep5KWYpYEixxx5XdTm1Ntpe84f3cVcF7mZZ7mPkntaFXLGJD2tS7YJkWU"
    path = "m/86'/1'/0'/0/6"
    hdw = HDWallet(xprivkey, path)
    internal_priv1 = hdw.get_private_key()
    print('From Private key:', priv1.to_wif())

    internal_pub1 = internal_priv1.get_public_key()
    print('From Public key:', internal_pub1.to_hex())

    fromAddress1 = internal_pub1.get_taproot_address()
    print('From Taproot address:', fromAddress1.to_string())

    # UTXO of fromAddress
    txid1 = '67e8c015625279f2d4268a7b15e8a6feef39a86ed4f5c14acbd260f612b8c44a'
    vout1 = 1

    # create transaction input from tx id of UTXO
    txin1 = TxInput(txid1, vout1)

    # all amounts are needed to sign a taproot input
    # (depending on sighash)
    amount1 = to_satoshis(0.00009658)
    amounts = [ amount1 ]

    # all scriptPubKeys (in hex) are needed to sign a taproot input 
    # (depending on sighash but always of the spend input)
    scriptPubkey1 = fromAddress1.to_script_pub_key()
    utxos_scriptPubkeys = [ scriptPubkey1 ]

    ########################
    # Construct the output #
    ########################

    hdw.from_path("m/86'/1'/0'/0/7")
    priv2 = hdw.get_private_key()
    print('To Private key', priv2.to_wif())
    pub2 = priv2.get_public_key()
    print('To Public key', pub2.to_hex())

    # taproot script is a simple P2PK with the following keys

    # pubkey starts with 02
    privkey_tr_script = PrivateKey('cQwzrJyTNWbEwhPEmQ3Qoo4jSfHdHEtdbL4kNBgHUKhirgzcQw7G')
    pubkey_tr_script = privkey_tr_script.get_public_key()
    tr_script_p2pk = Script([pubkey_tr_script.to_x_only_hex(), 'OP_CHECKSIG'])

    # taproot script path address
    toAddress2 = pub2.get_taproot_address([ [tr_script_p2pk] ])
    print('To Taproot script address', toAddress2.to_string())

    # create transaction output
    txOut = TxOutput(to_satoshis(0.00009), toAddress2.to_script_pub_key())

    # create transaction without change output - if at least a single input is
    # segwit we need to set has_segwit=True
    tx = Transaction([txin1], [txOut], has_segwit=True)

    print("\nRaw transaction:\n" + tx.serialize())

    print('\ntxid: ' + tx.get_txid())
    print('\ntxwid: ' + tx.get_wtxid())

    # sign taproot input
    # to create the digest message to sign in taproot we need to
    # pass all the utxos' scriptPubKeys and their amounts
    sig1 = priv1.sign_taproot_input(tx, 0, utxos_scriptPubkeys, amounts)

    tx.witnesses.append( TxWitnessInput([ sig1 ]) )

    # print raw signed transaction ready to be broadcasted
    print("\nRaw signed transaction:\n" + tx.serialize())

    print("\nTxId:", tx.get_txid())
    print("\nTxwId:", tx.get_wtxid())

    print("\nSize:", tx.get_size())
    print("\nvSize:", tx.get_vsize())


if __name__ == "__main__":
    main()

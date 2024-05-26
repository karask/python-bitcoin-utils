# Copyright (C) 2018-2024 The python-bitcoin-utils developers
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
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import P2wpkhAddress, P2pkhAddress, PrivateKey
from bitcoinutils.script import Script


def main():
    # always remember to setup the network
    setup("testnet")

    # send 2 P2PKH inputs to 1 P2WPKH output

    # create transaction inputs from tx ids of UTXOs (contained 0.002 tBTC)
    txin = TxInput(
        "eddfaa3d5a1c9a2a2961638aa4e28871b09ed9620f9077482248f368d46d8205", 1
    )
    txin2 = TxInput(
        "cf4b2987c06b9dd2ba6770af31a4942a4ea3e7194c0d64e8699e9fda03f50551", 1
    )

    # create transaction output using P2WPKH scriptPubKey (locking script)
    addr = P2wpkhAddress("tb1qlffsz7cgzmyzhklleu97afru7vwjytux4z4zsl")
    txout = TxOutput(to_satoshis(0.0019), addr.to_script_pub_key())
    # txout = TxOutput(to_satoshis(0.0019), Script([0, addr.to_hash()]) )

    # create transaction from inputs/outputs -- default locktime is used
    # note that this is not a segwit transaction since we don't spend segwit
    tx = Transaction([txin, txin2], [txout])  # , has_segwit=True)

    # print raw transaction
    print("\nRaw unsigned transaction:\n" + tx.serialize())

    # use the private keys corresponding to the address that contains the
    # UTXOs we are trying to spend to sign the input
    sk = PrivateKey("cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo")
    sk2 = PrivateKey("cVf3kGh6552jU2rLaKwXTKq5APHPoZqCP4GQzQirWGHFoHQ9rEVt")

    # note that we pass the scriptPubkey as one of the inputs of sign_input
    # because it is used to replace the scriptSig of the UTXO we are trying to
    # spend when creating the transaction digest
    from_addr = P2pkhAddress("n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR")
    sig = sk.sign_input(
        tx,
        0,
        Script(
            [
                "OP_DUP",
                "OP_HASH160",
                from_addr.to_hash160(),
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ]
        ),
    )
    from_addr2 = P2pkhAddress("mmYNBho9BWQB2dSniP1NJvnPoj5EVWw89w")
    sig2 = sk2.sign_input(tx, 1, from_addr2.to_script_pub_key())

    # get public key as hex
    pk = sk.get_public_key().to_hex()
    pk2 = sk2.get_public_key().to_hex()

    # set the scriptSig (unlocking script)
    txin.script_sig = Script([sig, pk])
    txin2.script_sig = Script([sig2, pk2])
    signed_tx = tx.serialize()

    # print raw signed transaction ready to be broadcasted
    print("\nRaw signed transaction:\n" + signed_tx)


if __name__ == "__main__":
    main()
